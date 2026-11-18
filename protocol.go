package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Proxy map[string]any

type UnsupportedTransportError struct {
	Protocol string
	Network  string
}

func (e *UnsupportedTransportError) Error() string {
	return fmt.Sprintf("Clash Verge / Mihomo 不支持 %s 的 %s 传输，无法生成可用节点；请使用支持该传输的客户端，或在服务器端配置 TUIC / Hysteria2", strings.ToUpper(e.Protocol), strings.ToUpper(e.Network))
}

func text(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func items(v any) []any           { a, _ := v.([]any); return a }
func boolean(v any) bool          { return v == true || strings.EqualFold(text(v), "true") || text(v) == "1" }
func first(values ...string) string {
	for _, s := range values {
		if s != "" {
			return s
		}
	}
	return ""
}
func put(p map[string]any, key string, v any) {
	if v != nil && text(v) != "" {
		p[key] = v
	}
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

func portNumber(v any) (int, error) {
	p, err := strconv.Atoi(text(v))
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("端口必须为 1–65535 的整数")
	}
	return p, nil
}

func validServer(s string) bool {
	return s != "" && len(s) <= 253 && !strings.ContainsAny(s, " /\\\r\n\t@?#")
}

func baseProxy(kind, server string, port int, name string) Proxy {
	if name == "" {
		name = strings.ToUpper(kind) + "-" + server
	}
	return Proxy{"name": name, "type": kind, "server": strings.Trim(server, "[]"), "port": port, "udp": true}
}

func applyTransport(p Proxy, network, path, host string) error {
	network = strings.ToLower(network)
	if network == "" || network == "tcp" {
		return nil
	}
	if path == "" {
		path = "/"
	}
	switch network {
	case "quic":
		return &UnsupportedTransportError{Protocol: text(p["type"]), Network: network}
	case "ws", "httpupgrade":
		opts := map[string]any{"path": path}
		if host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if network == "httpupgrade" {
			opts["v2ray-http-upgrade"] = true
		}
		p["network"], p["ws-opts"] = "ws", opts
	case "h2", "http":
		opts := map[string]any{"path": path}
		if host != "" {
			opts["host"] = strings.Split(host, ",")
		}
		p["network"], p["h2-opts"] = "h2", opts
	case "grpc":
		p["network"], p["grpc-opts"] = "grpc", map[string]any{"grpc-service-name": path}
	default:
		return fmt.Errorf("暂不支持传输类型 %q", network)
	}
	return nil
}

func applyTLS(p Proxy, q url.Values) {
	kind := text(p["type"])
	if q.Get("security") == "tls" || q.Get("security") == "reality" || boolean(q.Get("tls")) {
		p["tls"] = true
	}
	sniKey := "sni"
	if kind == "vless" || kind == "vmess" {
		sniKey = "servername"
	}
	put(p, sniKey, first(q.Get("sni"), q.Get("servername"), q.Get("peer")))
	put(p, "client-fingerprint", first(q.Get("fp"), q.Get("client-fingerprint")))
	if boolean(first(q.Get("insecure"), q.Get("allowInsecure"), q.Get("allow_insecure"))) {
		p["skip-cert-verify"] = true
	}
	if q.Get("alpn") != "" {
		p["alpn"] = strings.Split(q.Get("alpn"), ",")
	}
}

func normalizeShareLink(raw string) string {
	raw = strings.TrimSpace(raw)
	// Some copied Markdown links escape the scheme's colon.
	for _, scheme := range []string{"vmess", "vless", "trojan", "hysteria2", "hy2", "tuic", "anytls", "ss", "shadowsocks"} {
		prefix := scheme + `\://`
		if strings.HasPrefix(strings.ToLower(raw), prefix) {
			raw = scheme + "://" + raw[len(prefix):]
			break
		}
	}
	return raw
}

func ParseLink(raw string) (Proxy, error) {
	raw = normalizeShareLink(raw)
	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return parseVMess(raw)
	}
	if strings.HasPrefix(strings.ToLower(raw), "ss://") || strings.HasPrefix(strings.ToLower(raw), "shadowsocks://") {
		return parseSS(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("分享链接格式无效")
	}
	kind := strings.ToLower(u.Scheme)
	if kind == "hy2" {
		kind = "hysteria2"
	}
	switch kind {
	case "vless", "trojan", "hysteria2", "tuic", "anytls":
	default:
		return nil, errors.New("协议不支持，请使用 VLESS、VMess、Trojan、Hysteria2、TUIC、AnyTLS 或 Shadowsocks 链接")
	}
	server := u.Hostname()
	if !validServer(server) {
		return nil, errors.New("缺少有效服务器地址")
	}
	port, err := portNumber(first(u.Port(), "443"))
	if err != nil {
		return nil, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("链接缺少 UUID 或密码")
	}
	auth := u.User.Username()
	password, hasPassword := u.User.Password()
	if hasPassword {
		auth += ":" + password
	}
	q := u.Query()
	p := baseProxy(kind, server, port, u.Fragment)
	switch kind {
	case "vless":
		p["uuid"] = u.User.Username()
		if e := q.Get("encryption"); e != "" && e != "none" {
			return nil, errors.New("暂不支持该 VLESS encryption 参数")
		}
		put(p, "flow", q.Get("flow"))
		if q.Get("security") == "reality" {
			key := first(q.Get("pbk"), q.Get("public-key"))
			if key == "" {
				return nil, errors.New("Reality 链接缺少公钥 pbk")
			}
			reality := map[string]any{"public-key": key}
			put(reality, "short-id", first(q.Get("sid"), q.Get("short-id")))
			p["reality-opts"] = reality
		}
	case "tuic":
		if !hasPassword || password == "" {
			return nil, errors.New("TUIC 需要 UUID 和密码")
		}
		p["uuid"], p["password"] = u.User.Username(), password
		put(p, "congestion-controller", first(q.Get("congestion_control"), q.Get("congestion-controller")))
		put(p, "udp-relay-mode", first(q.Get("udp_relay_mode"), q.Get("udp-relay-mode")))
	case "hysteria2":
		p["password"] = auth
		put(p, "obfs", q.Get("obfs"))
		put(p, "obfs-password", q.Get("obfs-password"))
		put(p, "fingerprint", first(q.Get("pinSHA256"), q.Get("fingerprint")))
		put(p, "ports", q.Get("mport"))
	default:
		p["password"], p["tls"] = auth, true
	}
	applyTLS(p, q)
	if kind == "vless" || kind == "trojan" {
		network := first(q.Get("type"), q.Get("network"), "tcp")
		path := q.Get("path")
		if network == "grpc" {
			path = q.Get("serviceName")
		}
		if err := applyTransport(p, network, path, first(q.Get("host"), q.Get("authority"))); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func parseVMess(raw string) (Proxy, error) {
	body, fragment, _ := strings.Cut(strings.SplitN(raw, "://", 2)[1], "#")
	decoded, err := decodeBase64(body)
	if err != nil {
		return nil, errors.New("VMess Base64 无效")
	}
	var data map[string]any
	if json.Unmarshal(decoded, &data) != nil {
		return nil, errors.New("VMess JSON 无效")
	}
	server := first(text(data["add"]), text(data["server"]))
	if !validServer(server) || text(data["id"]) == "" {
		return nil, errors.New("VMess 缺少服务器地址或 UUID")
	}
	port, err := portNumber(first(text(data["port"]), "443"))
	if err != nil {
		return nil, err
	}
	name, err := url.PathUnescape(fragment)
	if err != nil {
		return nil, errors.New("VMess 节点名称编码无效")
	}
	p := baseProxy("vmess", server, port, first(name, text(data["ps"])))
	p["uuid"], p["cipher"] = data["id"], first(text(data["scy"]), "auto")
	aid, err := strconv.Atoi(first(text(data["aid"]), "0"))
	if err != nil || aid < 0 {
		return nil, errors.New("VMess alterId 无效")
	}
	p["alterId"] = aid
	q := url.Values{}
	if text(data["tls"]) == "tls" {
		q.Set("security", "tls")
	}
	for _, k := range []string{"sni", "fp", "alpn", "allowInsecure", "insecure"} {
		putString := text(data[k])
		if putString != "" {
			q.Set(k, putString)
		}
	}
	if q.Get("sni") == "" {
		q.Set("sni", text(data["host"]))
	}
	applyTLS(p, q)
	if err := applyTransport(p, first(text(data["net"]), "tcp"), text(data["path"]), text(data["host"])); err != nil {
		return nil, err
	}
	return p, nil
}

func parseSS(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("Shadowsocks 链接格式无效")
	}
	if u.User == nil {
		body := strings.SplitN(strings.SplitN(raw, "://", 2)[1], "#", 2)[0]
		body = strings.TrimSuffix(body, "/")
		decoded, err := decodeBase64(body)
		if err != nil {
			return nil, errors.New("Shadowsocks Base64 无效")
		}
		auth, address, ok := strings.Cut(string(decoded), "@")
		if !ok {
			return nil, errors.New("Shadowsocks 缺少服务器地址")
		}
		method, password, ok := strings.Cut(auth, ":")
		if !ok {
			return nil, errors.New("Shadowsocks 缺少加密方法或密码")
		}
		u, err = url.Parse("ss://" + url.UserPassword(method, password).String() + "@" + address + "#" + url.PathEscape(u.Fragment))
		if err != nil {
			return nil, errors.New("Shadowsocks 地址格式无效")
		}
	}
	method, password := u.User.Username(), ""
	if pass, ok := u.User.Password(); ok {
		password = pass
	} else {
		decoded, err := decodeBase64(method)
		if err != nil {
			return nil, errors.New("Shadowsocks 认证信息无效")
		}
		var ok bool
		method, password, ok = strings.Cut(string(decoded), ":")
		if !ok {
			return nil, errors.New("Shadowsocks 缺少加密方法或密码")
		}
	}
	if method == "" || password == "" || !validServer(u.Hostname()) {
		return nil, errors.New("Shadowsocks 缺少必要参数")
	}
	if u.Query().Get("plugin") != "" {
		return nil, errors.New("当前暂不支持 Shadowsocks 插件链接")
	}
	port, err := portNumber(first(u.Port(), "443"))
	if err != nil {
		return nil, err
	}
	p := baseProxy("ss", u.Hostname(), port, u.Fragment)
	p["cipher"], p["password"] = method, password
	return p, nil
}

func realityPublicKey(private string) (string, error) {
	key, err := decodeBase64(private)
	if err != nil {
		return "", errors.New("Reality 私钥编码无效")
	}
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", errors.New("Reality 私钥长度无效")
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func splitServers(input string) ([]string, error) {
	var result []string
	seen := map[string]bool{}
	for _, value := range strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t' }) {
		ip := net.ParseIP(strings.Trim(value, "[]"))
		if ip == nil {
			return nil, errors.New("批量地址必须是有效 IPv4 或 IPv6，每行一个")
		}
		server := ip.String()
		if !seen[server] {
			result = append(result, server)
			seen[server] = true
		}
	}
	return result, nil
}
