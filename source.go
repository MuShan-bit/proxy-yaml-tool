package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/tidwall/jsonc"
	"gopkg.in/yaml.v3"
)

type SourceResult struct {
	Nodes    []Proxy  `json:"nodes"`
	Warnings []string `json:"warnings"`
}

func DecodeSource(content []byte, path, server, sni string, insecure bool) SourceResult {
	r := SourceResult{Nodes: []Proxy{}, Warnings: []string{}}
	var data map[string]any
	if strings.HasSuffix(strings.ToLower(path), ".json") || strings.HasPrefix(strings.TrimSpace(string(content)), "{") {
		if json.Unmarshal(jsonc.ToJSON(content), &data) != nil {
			r.Warnings = append(r.Warnings, path+"：JSON/JSONC 无法解析")
			return r
		}
	} else if yaml.Unmarshal(content, &data) != nil {
		r.Warnings = append(r.Warnings, path+"：YAML 无法解析")
		return r
	}
	if data == nil {
		r.Warnings = append(r.Warnings, path+"：配置为空")
		return r
	}
	add := func(nodes []Proxy, err error) {
		if err != nil {
			r.Warnings = append(r.Warnings, path+"："+err.Error())
			return
		}
		for _, p := range nodes {
			if sni != "" {
				key := "sni"
				if p["type"] == "vless" || p["type"] == "vmess" {
					key = "servername"
				}
				p[key] = sni
			}
			if insecure {
				p["skip-cert-verify"] = true
			}
			if text(p["type"]) != "ss" && text(p["sni"]) == "" && text(p["servername"]) == "" && (boolean(p["tls"]) || p["type"] == "tuic" || p["type"] == "hysteria2") {
				r.Warnings = append(r.Warnings, path+"：未声明 SNI，请核对证书域名；可在高级连接选项补充")
			}
			p["_source"] = path
			r.Nodes = append(r.Nodes, p)
		}
	}
	if inbounds := items(data["inbounds"]); len(inbounds) > 0 {
		for _, value := range inbounds {
			inbound := object(value)
			if inbound == nil {
				continue
			}
			if listen := text(inbound["listen"]); listen == "127.0.0.1" || listen == "::1" {
				r.Warnings = append(r.Warnings, path+"：入站监听回环地址，若前置 Nginx / CDN，请在节点列表核对实际公开端口和 SNI")
			}
			if inbound["protocol"] != nil {
				add(xrayInbound(inbound, server))
			} else {
				add(singBoxInbound(inbound, server))
			}
		}
	} else if data["protocol"] != nil {
		add(xrayInbound(data, server))
	} else if strings.Contains(strings.ToLower(path), "hysteria") || data["auth"] != nil {
		add(hysteriaSource(data, server))
	} else if strings.Contains(strings.ToLower(path), "anytls") {
		add(anytlsSource(data, server))
	} else if strings.Contains(strings.ToLower(path), "tuic") || object(data["users"]) != nil {
		add(tuicSource(data, server))
	} else if data["method"] != nil && data["password"] != nil {
		port, err := portNumber(first(text(data["server_port"]), text(data["listen_port"])))
		if err != nil {
			add(nil, err)
		} else {
			p := baseProxy("ss", server, port, "")
			p["cipher"], p["password"] = data["method"], data["password"]
			add([]Proxy{p}, nil)
		}
	} else {
		r.Warnings = append(r.Warnings, path+"：未识别到支持的服务端入站配置")
	}
	return r
}

func listeningPort(v any) (int, error) {
	s := text(v)
	if _, port, err := net.SplitHostPort(s); err == nil {
		return portNumber(port)
	}
	return portNumber(s)
}

func xrayInbound(in map[string]any, server string) ([]Proxy, error) {
	kind := text(in["protocol"])
	if kind == "shadowsocks" {
		kind = "ss"
	}
	switch kind {
	case "vmess", "vless", "trojan", "ss":
	default:
		return nil, fmt.Errorf("跳过 %s 入站", kind)
	}
	port, err := portNumber(in["port"])
	if err != nil {
		return nil, err
	}
	settings, stream := object(in["settings"]), object(in["streamSettings"])
	clients := items(settings["clients"])
	if len(clients) == 0 && kind == "ss" {
		clients = []any{map[string]any{"password": settings["password"], "method": settings["method"]}}
	}
	if len(clients) == 0 {
		return nil, fmt.Errorf("%s 入站没有可导入的客户端认证信息", kind)
	}
	var nodes []Proxy
	for _, value := range clients {
		client := object(value)
		p := baseProxy(kind, server, port, first(text(client["email"]), text(in["tag"])))
		switch kind {
		case "vless", "vmess":
			if text(client["id"]) == "" {
				return nil, fmt.Errorf("%s 客户端缺少 UUID", kind)
			}
			p["uuid"] = client["id"]
			if kind == "vmess" {
				p["cipher"], p["alterId"] = "auto", 0
			} else {
				put(p, "flow", client["flow"])
			}
		case "trojan", "ss":
			if text(client["password"]) == "" {
				return nil, fmt.Errorf("%s 客户端缺少密码", kind)
			}
			p["password"] = client["password"]
			if kind == "trojan" {
				p["tls"] = true
			} else {
				method := first(text(client["method"]), text(settings["method"]))
				if method == "" {
					return nil, errors.New("Shadowsocks 缺少加密方法")
				}
				p["cipher"] = method
				if strings.HasPrefix(method, "2022-") && len(items(settings["clients"])) > 0 && text(settings["password"]) != "" {
					p["password"] = text(settings["password"]) + ":" + text(client["password"])
				}
			}
		}
		security, network := text(stream["security"]), first(text(stream["network"]), "tcp")
		q := url.Values{}
		q.Set("security", security)
		if security == "reality" {
			reality := object(stream["realitySettings"])
			key, err := realityPublicKey(text(reality["privateKey"]))
			if err != nil {
				return nil, err
			}
			q.Set("sni", firstString(reality["serverNames"]))
			q.Set("fp", "chrome")
			p["reality-opts"] = map[string]any{"public-key": key, "short-id": firstString(reality["shortIds"])}
		} else if security == "tls" {
			tls := object(stream["tlsSettings"])
			q.Set("sni", text(tls["serverName"]))
			if alpn := stringList(tls["alpn"]); len(alpn) > 0 {
				p["alpn"] = alpn
			}
		}
		applyTLS(p, q)
		var path, host string
		switch network {
		case "ws":
			opts := object(stream["wsSettings"])
			path, host = text(opts["path"]), text(object(opts["headers"])["Host"])
		case "httpupgrade":
			opts := object(stream["httpupgradeSettings"])
			path, host = text(opts["path"]), text(opts["host"])
		case "h2", "http":
			opts := object(stream["httpSettings"])
			path, host = text(opts["path"]), strings.Join(stringList(opts["host"]), ",")
		case "grpc":
			path = text(object(stream["grpcSettings"])["serviceName"])
		case "tcp", "raw":
			if header := text(object(object(stream["tcpSettings"])["header"])["type"]); header != "" && header != "none" {
				return nil, errors.New("TCP HTTP 伪装暂不支持，已跳过该入站")
			}
			network = "tcp"
		}
		if kind != "ss" {
			if err := applyTransport(p, network, path, host); err != nil {
				return nil, err
			}
		}
		nodes = append(nodes, p)
	}
	return nodes, nil
}

func firstString(v any) string {
	list := stringList(v)
	if len(list) > 0 {
		return list[0]
	}
	return ""
}
func stringList(v any) []string {
	var r []string
	switch v := v.(type) {
	case []any:
		for _, s := range v {
			r = append(r, text(s))
		}
	case []string:
		return v
	case string:
		if v != "" {
			r = append(r, v)
		}
	}
	return r
}

func singBoxInbound(in map[string]any, server string) ([]Proxy, error) {
	kind := text(in["type"])
	if kind == "shadowsocks" {
		kind = "ss"
	}
	switch kind {
	case "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls", "ss":
	default:
		return nil, fmt.Errorf("跳过 %s 入站", kind)
	}
	port, err := portNumber(in["listen_port"])
	if err != nil {
		return nil, err
	}
	users := items(in["users"])
	if len(users) == 0 && kind == "ss" {
		users = []any{map[string]any{"password": in["password"]}}
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%s 入站没有用户信息", kind)
	}
	var nodes []Proxy
	for _, value := range users {
		user := object(value)
		p := baseProxy(kind, server, port, first(text(user["name"]), text(in["tag"])))
		if kind == "vmess" || kind == "vless" || kind == "tuic" {
			if text(user["uuid"]) == "" {
				return nil, errors.New("用户缺少 UUID")
			}
			p["uuid"] = user["uuid"]
		}
		if kind == "vmess" {
			p["cipher"], p["alterId"] = "auto", 0
		} else if kind == "vless" {
			put(p, "flow", user["flow"])
		} else {
			if text(user["password"]) == "" {
				return nil, errors.New("用户缺少密码")
			}
			p["password"] = user["password"]
		}
		if kind == "ss" {
			p["cipher"] = in["method"]
			if strings.HasPrefix(text(in["method"]), "2022-") && len(items(in["users"])) > 0 {
				p["password"] = text(in["password"]) + ":" + text(user["password"])
			}
		}
		tls := object(in["tls"])
		q := url.Values{}
		if boolean(tls["enabled"]) {
			q.Set("security", "tls")
		}
		q.Set("sni", text(tls["server_name"]))
		if alpn := stringList(tls["alpn"]); len(alpn) > 0 {
			p["alpn"] = alpn
		}
		reality := object(tls["reality"])
		if boolean(reality["enabled"]) {
			if kind != "vless" {
				return nil, errors.New("仅支持 VLESS Reality 入站转换")
			}
			key, err := realityPublicKey(text(reality["private_key"]))
			if err != nil {
				return nil, err
			}
			q.Set("security", "reality")
			q.Set("fp", "chrome")
			if q.Get("sni") == "" {
				q.Set("sni", text(object(reality["handshake"])["server"]))
			}
			p["reality-opts"] = map[string]any{"public-key": key, "short-id": firstString(reality["short_id"])}
		}
		if kind == "trojan" || kind == "anytls" {
			p["tls"] = true
		}
		applyTLS(p, q)
		transport := object(in["transport"])
		network, path, host := text(transport["type"]), text(transport["path"]), ""
		if network == "http" {
			host = strings.Join(stringList(transport["host"]), ",")
		} else {
			host = text(object(transport["headers"])["Host"])
		}
		if network == "grpc" {
			path = text(transport["service_name"])
		}
		if err := applyTransport(p, network, path, host); err != nil {
			return nil, err
		}
		if kind == "hysteria2" {
			obfs := object(in["obfs"])
			put(p, "obfs", obfs["type"])
			put(p, "obfs-password", obfs["password"])
		}
		if kind == "tuic" {
			put(p, "congestion-controller", in["congestion_control"])
		}
		nodes = append(nodes, p)
	}
	return nodes, nil
}

func hysteriaSource(data map[string]any, server string) ([]Proxy, error) {
	port, err := listeningPort(data["listen"])
	if err != nil {
		return nil, err
	}
	auth := object(data["auth"])
	var passwords []string
	switch text(auth["type"]) {
	case "password":
		passwords = []string{text(auth["password"])}
	case "userpass":
		users := object(auth["userpass"])
		for _, user := range sortedKeys(users) {
			pass := users[user]
			passwords = append(passwords, user+":"+text(pass))
		}
	default:
		return nil, errors.New("Hysteria2 使用动态认证，无法仅从配置提取密码")
	}
	var nodes []Proxy
	for _, password := range passwords {
		if password == "" {
			continue
		}
		p := baseProxy("hysteria2", server, port, "")
		p["password"] = password
		obfs := object(data["obfs"])
		put(p, "obfs", obfs["type"])
		put(p, "obfs-password", object(obfs["salamander"])["password"])
		if sni := firstString(object(data["acme"])["domains"]); sni != "" {
			p["sni"] = sni
		}
		nodes = append(nodes, p)
	}
	if len(nodes) == 0 {
		return nil, errors.New("Hysteria2 未找到可导入的密码")
	}
	return nodes, nil
}

func tuicSource(data map[string]any, server string) ([]Proxy, error) {
	port, err := listeningPort(first(text(data["server"]), text(data["listen"])))
	if err != nil {
		return nil, err
	}
	var nodes []Proxy
	users := object(data["users"])
	for _, uuid := range sortedKeys(users) {
		password := users[uuid]
		if uuid == "" || text(password) == "" {
			continue
		}
		p := baseProxy("tuic", server, port, "")
		p["uuid"], p["password"] = uuid, password
		put(p, "congestion-controller", data["congestion_control"])
		if alpn := stringList(data["alpn"]); len(alpn) > 0 {
			p["alpn"] = alpn
		}
		nodes = append(nodes, p)
	}
	if len(nodes) == 0 {
		return nil, errors.New("TUIC 未找到 UUID / 密码用户表")
	}
	return nodes, nil
}

func anytlsSource(data map[string]any, server string) ([]Proxy, error) {
	port, err := listeningPort(data["listen"])
	if err != nil {
		return nil, err
	}
	var passwords []string
	if password := text(data["password"]); password != "" {
		passwords = append(passwords, password)
	}
	for _, value := range items(data["users"]) {
		user := object(value)
		if password := text(user["password"]); password != "" {
			passwords = append(passwords, password)
		}
	}
	if users := object(data["users"]); len(users) > 0 {
		for _, key := range sortedKeys(users) {
			if password := text(users[key]); password != "" {
				passwords = append(passwords, password)
			}
		}
	}
	if len(passwords) == 0 {
		return nil, errors.New("AnyTLS 未找到密码")
	}
	var nodes []Proxy
	for _, password := range passwords {
		p := baseProxy("anytls", server, port, "")
		p["password"], p["tls"] = password, true
		tls := object(data["tls"])
		if text(tls["server_name"]) != "" {
			p["sni"] = tls["server_name"]
		}
		nodes = append(nodes, p)
	}
	return nodes, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
