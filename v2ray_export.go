package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func shareStringList(value any) string {
	switch value := value.(type) {
	case []string:
		return strings.Join(value, ",")
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = text(item)
		}
		return strings.Join(parts, ",")
	default:
		return text(value)
	}
}

func unsupportedShareFields(values map[string]any, supported string) error {
	for key := range values {
		if !strings.Contains(" "+supported+" ", " "+key+" ") {
			return fmt.Errorf("字段 %s 无法无损转换为分享链接，请导入原始分享链接", key)
		}
	}
	return nil
}

func v2rayProxyLink(p Proxy) (string, error) {
	kind := strings.ToLower(text(p["type"]))
	common := "name type server port udp"
	if kind != "ss" {
		common += " tls servername sni skip-cert-verify client-fingerprint alpn"
	}
	extra := ""
	switch kind {
	case "vless":
		extra = "uuid flow network ws-opts h2-opts grpc-opts reality-opts"
	case "vmess":
		extra = "uuid alterId cipher network ws-opts h2-opts grpc-opts"
	case "trojan":
		extra = "password network ws-opts h2-opts grpc-opts"
	case "hysteria2":
		extra = "password obfs obfs-password fingerprint ports"
	case "tuic":
		extra = "uuid password congestion-controller udp-relay-mode"
	case "anytls":
		extra = "password"
	case "ss":
		extra = "cipher password"
	default:
		return "", errors.New("该协议暂不支持转为 v2rayN 分享链接")
	}
	if err := unsupportedShareFields(p, common+" "+extra); err != nil {
		return "", err
	}
	for _, key := range []string{"ws-opts", "h2-opts", "grpc-opts", "reality-opts"} {
		if value, present := p[key]; present && object(value) == nil {
			return "", fmt.Errorf("%s 必须是对象", key)
		}
	}
	server := strings.Trim(text(p["server"]), "[]")
	if !validServer(server) {
		return "", errors.New("缺少有效服务器地址")
	}
	port, err := portNumber(p["port"])
	if err != nil {
		return "", err
	}
	name := first(text(p["name"]), strings.ToUpper(kind)+"-"+server)
	if err := validV2RayName(name); err != nil {
		return "", err
	}
	q := url.Values{}
	set := func(key, value string) {
		if value != "" {
			q.Set(key, value)
		}
	}
	set("sni", first(text(p["servername"]), text(p["sni"])))
	set("fp", text(p["client-fingerprint"]))
	set("alpn", shareStringList(p["alpn"]))
	if boolean(p["skip-cert-verify"]) {
		q.Set("allowInsecure", "1")
		if kind == "vless" {
			return "", errors.New("v2rayN 的 VLESS 分享格式不能保留 skip-cert-verify，请导入原始链接并在客户端确认该设置")
		}
		if kind == "anytls" {
			q.Del("allowInsecure")
			q.Set("insecure", "1")
		}
	}
	security := "none"
	if boolean(p["tls"]) || kind == "trojan" || kind == "anytls" {
		security = "tls"
	}
	if reality := object(p["reality-opts"]); reality != nil {
		if err := unsupportedShareFields(reality, "public-key short-id"); err != nil {
			return "", err
		}
		if text(reality["public-key"]) == "" {
			return "", errors.New("Reality 缺少 public-key")
		}
		security = "reality"
		set("pbk", text(reality["public-key"]))
		set("sid", text(reality["short-id"]))
	}
	if kind == "vless" || kind == "vmess" || kind == "trojan" {
		q.Set("security", security)
		if err := v2rayTransport(p, q); err != nil {
			return "", err
		}
	}
	u := &url.URL{Scheme: kind, Host: net.JoinHostPort(server, strconv.Itoa(port)), Fragment: name}
	if kind == "vless" || kind == "vmess" || kind == "tuic" {
		if text(p["uuid"]) == "" {
			return "", errors.New("缺少 UUID")
		}
		u.User = url.User(text(p["uuid"]))
	} else {
		if text(p["password"]) == "" {
			return "", errors.New("缺少密码")
		}
		u.User = url.User(text(p["password"]))
	}
	switch kind {
	case "vless":
		q.Set("encryption", "none")
		set("flow", text(p["flow"]))
	case "vmess":
		aid := first(text(p["alterId"]), "0")
		if number, err := strconv.Atoi(aid); err != nil || number < 0 {
			return "", errors.New("VMess alterId 无效")
		}
		data := map[string]any{"v": "2", "ps": name, "add": server, "port": strconv.Itoa(port), "id": text(p["uuid"]), "aid": aid, "scy": first(text(p["cipher"]), "auto"), "net": q.Get("type"), "type": "none", "host": q.Get("host"), "path": q.Get("path"), "sni": q.Get("sni"), "fp": q.Get("fp"), "alpn": q.Get("alpn")}
		if q.Get("type") == "grpc" {
			data["path"] = q.Get("serviceName")
			data["type"] = "gun"
		}
		if security == "tls" {
			data["tls"] = "tls"
		}
		if boolean(p["skip-cert-verify"]) {
			data["insecure"] = "1"
		}
		encoded, _ := json.Marshal(data)
		return "vmess://" + base64.StdEncoding.EncodeToString(encoded), nil
	case "tuic":
		if text(p["password"]) == "" {
			return "", errors.New("TUIC 缺少密码")
		}
		u.User = url.UserPassword(text(p["uuid"]), text(p["password"]))
		set("congestion_control", text(p["congestion-controller"]))
		if relay := text(p["udp-relay-mode"]); relay != "" && relay != "native" {
			return "", errors.New("v2rayN 分享格式不能保留该 TUIC udp-relay-mode，请导入原始链接并在客户端确认该设置")
		}
		if boolean(p["skip-cert-verify"]) {
			q.Del("allowInsecure")
			q.Set("allow_insecure", "1")
		}
	case "hysteria2":
		set("obfs", text(p["obfs"]))
		set("obfs-password", text(p["obfs-password"]))
		set("pinSHA256", text(p["fingerprint"]))
		set("mport", text(p["ports"]))
		if boolean(p["skip-cert-verify"]) {
			q.Del("allowInsecure")
			q.Set("insecure", "1")
		}
	case "ss":
		if text(p["cipher"]) == "" {
			return "", errors.New("Shadowsocks 缺少加密方法")
		}
		u.User = url.UserPassword(text(p["cipher"]), text(p["password"]))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func v2rayTransport(p Proxy, q url.Values) error {
	network := first(text(p["network"]), "tcp")
	for key, expected := range map[string]string{"ws-opts": "ws", "h2-opts": "h2", "grpc-opts": "grpc"} {
		if p[key] != nil && network != expected && !(key == "h2-opts" && network == "http") {
			return fmt.Errorf("%s 与 network 不一致，无法无损转换", key)
		}
	}
	q.Set("type", network)
	switch network {
	case "tcp":
	case "ws":
		opts := object(p["ws-opts"])
		if err := unsupportedShareFields(opts, "path headers v2ray-http-upgrade"); err != nil {
			return err
		}
		headers := object(opts["headers"])
		if _, present := opts["headers"]; present && headers == nil {
			return errors.New("WS headers 必须是对象")
		}
		if err := unsupportedShareFields(headers, "Host"); err != nil {
			return err
		}
		q.Set("path", first(text(opts["path"]), "/"))
		if text(headers["Host"]) != "" {
			q.Set("host", text(headers["Host"]))
		}
		if boolean(opts["v2ray-http-upgrade"]) {
			q.Set("type", "httpupgrade")
		}
	case "h2", "http":
		opts := object(p["h2-opts"])
		if err := unsupportedShareFields(opts, "host path"); err != nil {
			return err
		}
		q.Set("type", "h2")
		q.Set("host", shareStringList(opts["host"]))
		q.Set("path", first(text(opts["path"]), "/"))
	case "grpc":
		opts := object(p["grpc-opts"])
		if err := unsupportedShareFields(opts, "grpc-service-name"); err != nil {
			return err
		}
		q.Set("serviceName", text(opts["grpc-service-name"]))
	default:
		return errors.New("该 YAML 传输暂不支持无损导出，请导入原始分享链接")
	}
	return nil
}
