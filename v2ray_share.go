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
	"unicode/utf8"
)

type V2RayNode struct {
	NodeSummary
	Link string `json:"link"`
}

type V2RayRequest struct {
	Links     string   `json:"links"`
	NodesYAML string   `json:"nodesYaml"`
	Existing  []string `json:"existing"`
}

type V2RayEditRequest struct {
	Links       []string `json:"links"`
	Names       []string `json:"names"`
	DeleteIndex *int     `json:"deleteIndex"`
}

type V2RayResult struct {
	Nodes           []V2RayNode `json:"nodes"`
	Added           int         `json:"added"`
	Skipped         int         `json:"skipped"`
	Total           int         `json:"total"`
	Content         string      `json:"content"`
	Subscription    string      `json:"subscription"`
	SubscriptionURL string      `json:"subscriptionURL,omitempty"`
	Warnings        []string    `json:"warnings"`
}

// Sharing URLs retain all original query parameters; Mihomo's model cannot express every core option.
func parseV2RayLink(raw string) (V2RayNode, string, error) {
	node := V2RayNode{}
	raw = normalizeShareLink(raw)
	if len(raw) > 64<<10 || strings.ContainsAny(raw, "\r\n\t") {
		return node, "", errors.New("节点链接过长或包含换行、制表符")
	}
	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return parseV2RayVMess(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return node, "", errors.New("分享链接格式无效")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "hy2":
		u.Scheme = "hysteria2"
	case "shadowsocks":
		u.Scheme = "ss"
	case "vless", "trojan", "hysteria2", "tuic", "anytls", "ss":
	default:
		return node, "", errors.New("不支持该分享协议，请使用 VLESS、VMess、Trojan、Hysteria2、TUIC、AnyTLS 或 Shadowsocks")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return node, "", errors.New("分享链接查询参数编码无效")
	}
	if u.Scheme == "ss" {
		if err := normalizeV2RaySS(u, raw); err != nil {
			return node, "", err
		}
	}
	if !validServer(u.Hostname()) || u.User == nil || u.User.Username() == "" {
		return node, "", errors.New("链接缺少有效服务器地址或认证信息")
	}
	port, err := portNumber(first(u.Port(), "443"))
	if err != nil {
		return node, "", err
	}
	if u.Scheme == "tuic" {
		if pass, ok := u.User.Password(); !ok || pass == "" {
			return node, "", errors.New("TUIC 需要 UUID 和密码")
		}
	}
	if u.Scheme == "vless" && q.Get("security") == "reality" && first(q.Get("pbk"), q.Get("public-key")) == "" {
		return node, "", errors.New("Reality 链接缺少公钥 pbk")
	}
	server := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(server); ip != nil {
		server = ip.String()
	}
	u.Host = net.JoinHostPort(server, strconv.Itoa(port))
	u.RawQuery = q.Encode()
	name := first(u.Fragment, strings.ToUpper(u.Scheme)+"-"+server)
	if err := validV2RayName(name); err != nil {
		return node, "", err
	}
	transport := first(q.Get("type"), q.Get("network"), "tcp")
	if u.Scheme == "tuic" || u.Scheme == "hysteria2" {
		transport = "udp / quic"
	}
	node.NodeSummary = NodeSummary{name, u.Scheme, server, port, transport}
	u.Fragment, u.RawFragment = "", ""
	identity := u.String()
	u.Fragment = name
	node.Link = u.String()
	return node, identity, nil
}

func normalizeV2RaySS(u *url.URL, raw string) error {
	if u.User == nil {
		body := strings.SplitN(strings.SplitN(strings.SplitN(raw, "://", 2)[1], "#", 2)[0], "?", 2)[0]
		decoded, err := decodeBase64(strings.TrimSuffix(body, "/"))
		if err != nil {
			return errors.New("Shadowsocks Base64 无效")
		}
		at := strings.LastIndexByte(string(decoded), '@')
		if at < 0 {
			return errors.New("Shadowsocks 缺少服务器地址")
		}
		auth, address := string(decoded[:at]), string(decoded[at+1:])
		method, password, ok := strings.Cut(auth, ":")
		if !ok {
			return errors.New("Shadowsocks 缺少加密方法或密码")
		}
		parsed, err := url.Parse("ss://" + url.UserPassword(method, password).String() + "@" + address)
		if err != nil {
			return errors.New("Shadowsocks 地址格式无效")
		}
		u.User, u.Host, u.Path = parsed.User, parsed.Host, parsed.Path
	}
	method := u.User.Username()
	password, ok := u.User.Password()
	if !ok {
		decoded, err := decodeBase64(method)
		if err != nil {
			return errors.New("Shadowsocks 认证信息无效")
		}
		method, password, ok = strings.Cut(string(decoded), ":")
	}
	if !ok || method == "" || password == "" {
		return errors.New("Shadowsocks 缺少加密方法或密码")
	}
	// SIP022 uses unencoded userinfo for the 2022 methods; SIP002 uses URL-safe Base64.
	if strings.HasPrefix(method, "2022-") {
		u.User = url.UserPassword(method, password)
	} else {
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password)))
	}
	if u.Path == "/" {
		u.Path = ""
	}
	return nil
}

func parseV2RayVMess(raw string) (V2RayNode, string, error) {
	node := V2RayNode{}
	body, fragment, _ := strings.Cut(strings.SplitN(raw, "://", 2)[1], "#")
	decoded, err := decodeBase64(body)
	if err != nil {
		return node, "", errors.New("VMess Base64 无效")
	}
	var data map[string]any
	if json.Unmarshal(decoded, &data) != nil || data == nil {
		return node, "", errors.New("VMess JSON 无效")
	}
	server := strings.ToLower(first(text(data["add"]), text(data["server"])))
	if !validServer(server) || text(data["id"]) == "" {
		return node, "", errors.New("VMess 缺少服务器地址或 UUID")
	}
	port, err := portNumber(first(text(data["port"]), "443"))
	if err != nil {
		return node, "", err
	}
	name, err := url.PathUnescape(fragment)
	if err != nil {
		return node, "", errors.New("VMess 名称编码无效")
	}
	name = first(name, text(data["ps"]), "VMESS-"+server)
	if err := validV2RayName(name); err != nil {
		return node, "", err
	}
	for _, key := range []string{"id", "aid", "port", "net", "type", "tls", "sni", "host", "path", "scy", "fp", "alpn"} {
		if value, ok := data[key]; ok {
			data[key] = text(value)
		}
	}
	data["v"], data["add"], data["port"] = "2", server, strconv.Itoa(port)
	data["aid"], data["net"], data["type"], data["scy"] = first(text(data["aid"]), "0"), first(text(data["net"]), "tcp"), first(text(data["type"]), "none"), first(text(data["scy"]), "auto")
	if boolean(data["allowInsecure"]) && data["insecure"] == nil {
		data["insecure"] = "1"
	}
	if aid, err := strconv.Atoi(text(data["aid"])); err != nil || aid < 0 {
		return node, "", errors.New("VMess alterId 无效")
	}
	delete(data, "server")
	delete(data, "ps")
	identity, _ := json.Marshal(data)
	data["ps"] = name
	encoded, _ := json.Marshal(data)
	node.NodeSummary = NodeSummary{name, "vmess", server, port, text(data["net"])}
	node.Link = "vmess://" + base64.StdEncoding.EncodeToString(encoded)
	return node, string(identity), nil
}

func validV2RayName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 512 || strings.ContainsAny(name, "\r\n\t") || !utf8.ValidString(name) {
		return errors.New("节点名称不能为空、超过 512 字节或包含换行和制表符")
	}
	return nil
}

func renameV2RayNode(node V2RayNode, name string) (V2RayNode, error) {
	name = strings.TrimSpace(name)
	if err := validV2RayName(name); err != nil {
		return node, err
	}
	if node.Protocol == "vmess" {
		decoded, _ := decodeBase64(strings.TrimPrefix(node.Link, "vmess://"))
		var data map[string]any
		_ = json.Unmarshal(decoded, &data)
		data["ps"] = name
		encoded, _ := json.Marshal(data)
		node.Link = "vmess://" + base64.StdEncoding.EncodeToString(encoded)
	} else {
		u, _ := url.Parse(node.Link)
		u.Fragment, u.RawFragment = name, ""
		node.Link = u.String()
	}
	node.Name = name
	return node, nil
}

func v2rayResult(nodes []V2RayNode) V2RayResult {
	result := V2RayResult{Nodes: nodes, Total: len(nodes), Warnings: []string{}}
	links := make([]string, 0, len(nodes))
	for _, node := range nodes {
		links = append(links, node.Link)
		if node.Transport == "quic" || node.Transport == "kcp" || node.Transport == "h2" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("节点“%s”保留 %s 传输；需选择支持该传输的客户端内核。", node.Name, strings.ToUpper(node.Transport)))
		}
	}
	result.Content = strings.Join(links, "\n")
	result.Subscription = base64.StdEncoding.EncodeToString([]byte(result.Content))
	return result
}

func convertV2Ray(req V2RayRequest) (V2RayResult, error) {
	result := v2rayResult([]V2RayNode{})
	seen, occupied := map[string]bool{}, map[string]bool{}
	add := func(raw string, existing bool) error {
		node, id, err := parseV2RayLink(raw)
		if err != nil {
			return err
		}
		if seen[id] {
			result.Skipped++
			return nil
		}
		if len(result.Nodes) >= 10000 {
			return errors.New("单份订阅最多支持 10000 个节点")
		}
		name := uniqueName(node.Name, occupied)
		node, err = renameV2RayNode(node, name)
		if err != nil {
			return err
		}
		occupied[name], seen[id] = true, true
		result.Nodes = append(result.Nodes, node)
		if !existing {
			result.Added++
		}
		return nil
	}
	for _, link := range req.Existing {
		if err := add(link, true); err != nil {
			return result, fmt.Errorf("当前节点列表无效：%w", err)
		}
	}
	input := strings.TrimSpace(strings.TrimPrefix(req.Links, "\uFEFF"))
	if input != "" && !strings.Contains(input, "://") && !strings.Contains(input, `\://`) {
		decoded, err := decodeBase64(strings.Join(strings.Fields(input), ""))
		if err != nil || !utf8.Valid(decoded) {
			return result, errors.New("请输入分享链接、Base64 订阅内容或切换到节点 YAML")
		}
		input = string(decoded)
	}
	for line, link := range strings.Split(input, "\n") {
		link = strings.TrimSpace(link)
		if link == "" || strings.HasPrefix(link, "#") {
			continue
		}
		if err := add(link, false); err != nil {
			return result, fmt.Errorf("分享链接第 %d 行：%w", line+1, err)
		}
	}
	var conversionWarnings []string
	convertedYAML := 0
	if strings.TrimSpace(req.NodesYAML) != "" {
		nodes, err := decodeNodeList(req.NodesYAML)
		if err != nil {
			return result, err
		}
		for index, proxy := range nodes {
			link, err := v2rayProxyLink(proxy)
			if err != nil {
				conversionWarnings = append(conversionWarnings, fmt.Sprintf("节点 YAML 第 %d 项已跳过：%s", index+1, err))
				continue
			}
			if err := add(link, false); err != nil {
				return result, fmt.Errorf("节点 YAML 第 %d 项：%w", index+1, err)
			}
			convertedYAML++
		}
	}
	if len(conversionWarnings) > 0 && convertedYAML == 0 {
		return result, fmt.Errorf("没有可转换的 YAML 节点：%s", strings.Join(conversionWarnings, "；"))
	}
	final := v2rayResult(result.Nodes)
	final.Added, final.Skipped = result.Added, result.Skipped
	final.Warnings = append(final.Warnings, conversionWarnings...)
	return final, nil
}

func editV2Ray(req V2RayEditRequest) (V2RayResult, error) {
	result := v2rayResult([]V2RayNode{})
	if len(req.Links) > 10000 || (req.Names != nil && len(req.Names) != len(req.Links)) {
		return result, errors.New("名称数量与节点数量不一致或节点数量超过限制")
	}
	if req.DeleteIndex != nil && (*req.DeleteIndex < 0 || *req.DeleteIndex >= len(req.Links)) {
		return result, errors.New("请选择有效的节点进行删除")
	}
	for i, link := range req.Links {
		node, _, err := parseV2RayLink(link)
		if err != nil {
			return result, fmt.Errorf("节点第 %d 项无效：%w", i+1, err)
		}
		if req.DeleteIndex != nil && i == *req.DeleteIndex {
			continue
		}
		if req.Names != nil {
			node, err = renameV2RayNode(node, req.Names[i])
			if err != nil {
				return result, fmt.Errorf("节点第 %d 项：%w", i+1, err)
			}
		}
		result.Nodes = append(result.Nodes, node)
	}
	return v2rayResult(result.Nodes), nil
}
