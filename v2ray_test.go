package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestV2RayImportDedupPreservesExtraParameters(t *testing.T) {
	link := "vless://uuid@[2001:db8::1]:443?security=reality&pbk=public&sid=ab&type=xhttp&path=%2Fedge&extra=%7B%22x%22%3A1%7D#First"
	result, err := convertV2Ray(V2RayRequest{Links: link + "\n" + strings.Replace(link, "#First", "#OtherName", 1) + "\n" + strings.Replace(link, "sid=ab", "sid=cd", 1)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 2 || result.Skipped != 1 || result.Total != 2 || result.Nodes[1].Name != "First-2" {
		t.Fatal("dedup or name collision handling incorrect")
	}
	u, _ := url.Parse(result.Nodes[0].Link)
	if u.Query().Get("extra") != `{"x":1}` || u.Query().Get("path") != "/edge" || result.Nodes[0].Transport != "xhttp" {
		t.Fatal("extra transport parameters lost")
	}
	decoded, _ := base64.StdEncoding.DecodeString(result.Subscription)
	if string(decoded) != result.Content || len(strings.Split(result.Content, "\n")) != 2 {
		t.Fatal("subscription is not a Base64 sharing-link list")
	}
	second, err := convertV2Ray(V2RayRequest{Existing: []string{result.Nodes[0].Link, result.Nodes[1].Link}, Links: base64.StdEncoding.EncodeToString([]byte(link))})
	if err != nil || second.Added != 0 || second.Skipped != 1 || second.Content != result.Content {
		t.Fatal("Base64 import or incremental import incorrect")
	}
}

func TestV2RaySharingFormatsAndRename(t *testing.T) {
	legacySS := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass@word@node.example:8388")) + "#SS"
	links := []string{
		"vless://uuid@node.example:443?security=reality&pbk=public&sid=ab&type=grpc&serviceName=edge#VLESS",
		"trojan://pass%3Aword%2B@node.example:443?security=tls&type=httpupgrade&path=%2Fedge#Trojan",
		"hy2://user:password@node.example:443?insecure=1&obfs=salamander&obfs-password=obfs#HY2",
		"tuic://uuid:pass%2B@node.example:443?congestion_control=bbr&allow_insecure=1#TUIC",
		"anytls://pass@node.example:443?insecure=1#AnyTLS",
		"ss://2022-blake3-aes-128-gcm:key%3Akey2@[2001:db8::1]:8443#2022",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass")) + "@node.example:443/?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example#Plugin",
		legacySS,
		vmessQUICLink(t),
	}
	for _, link := range links {
		original, id, err := parseV2RayLink(link)
		if err != nil {
			t.Fatal(err)
		}
		renamed, err := renameV2RayNode(original, "日本 节点 / #1 & 测试")
		if err != nil {
			t.Fatal(err)
		}
		parsed, renamedID, err := parseV2RayLink(renamed.Link)
		if err != nil || renamedID != id || parsed.Name != "日本 节点 / #1 & 测试" || parsed.Server != original.Server || parsed.Port != original.Port {
			t.Fatal("rename changed authentication, protocol or transport")
		}
	}
	result, err := convertV2Ray(V2RayRequest{Links: vmessQUICLink(t)})
	if err != nil || result.Nodes[0].Transport != "quic" || len(result.Warnings) != 1 {
		t.Fatal("VMess QUIC must be retained with a core-compatibility warning")
	}
}

func TestV2RayVMessNumericFieldsDedup(t *testing.T) {
	first, _ := json.Marshal(map[string]any{"v": 2, "ps": "A", "add": "node.example", "port": 443, "id": "u", "aid": 0, "net": "ws", "path": "/edge"})
	second, _ := json.Marshal(map[string]any{"v": "2", "ps": "B", "add": "node.example", "port": "443", "id": "u", "aid": "0", "net": "ws", "path": "/edge"})
	result, err := convertV2Ray(V2RayRequest{Links: "vmess://" + base64.StdEncoding.EncodeToString(first) + "\nvmess://" + base64.StdEncoding.EncodeToString(second)})
	if err != nil || result.Total != 1 || result.Skipped != 1 {
		t.Fatal("equivalent VMess JSON fields were not normalized")
	}
}

func TestV2RayYAMLProtocolTransportRoundTrip(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"tcp", "ws", "h2", "httpupgrade", "grpc"} {
			p := baseProxy(kind, "node.example", 8443, "节点")
			p["tls"], p["servername"], p["client-fingerprint"] = true, "sni.example", "chrome"
			p["alpn"] = []any{"h2", "http/1.1"}
			if kind == "trojan" {
				p["password"] = "p:+@word"
			} else {
				p["uuid"] = "uuid"
			}
			if err := applyTransport(p, transport, "/edge", "cdn.example"); err != nil {
				t.Fatal(err)
			}
			link, err := v2rayProxyLink(p)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ParseLink(link)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"name", "server", "port", "uuid", "password", "tls", "network", "ws-opts", "h2-opts", "grpc-opts"} {
				if !reflect.DeepEqual(p[key], decoded[key]) {
					t.Fatalf("%s/%s lost field %s", kind, transport, key)
				}
			}
		}
	}
	for _, kind := range []string{"tuic", "hysteria2", "anytls", "ss"} {
		p := baseProxy(kind, "2001:db8::1", 443, kind)
		p["password"] = "p:+@word"
		if kind != "ss" {
			p["skip-cert-verify"] = true
		}
		if kind == "tuic" {
			p["uuid"], p["congestion-controller"] = "uuid", "bbr"
		}
		if kind == "ss" {
			p["cipher"] = "2022-blake3-aes-128-gcm"
		}
		link, err := v2rayProxyLink(p)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ParseLink(link)
		if err != nil || decoded["password"] != p["password"] || decoded["skip-cert-verify"] != p["skip-cert-verify"] {
			t.Fatal("UDP/TLS/SS auth or certificate option lost")
		}
	}
}

func TestV2RayYAMLUnsupportedOptionsAreNotSilentlyDropped(t *testing.T) {
	input := `proxies:
  - {name: Good, type: trojan, server: node.example, port: 443, password: p}
  - {name: Dependent, type: trojan, server: node.example, port: 443, password: p, dialer-proxy: Good}
`
	result, err := convertV2Ray(V2RayRequest{NodesYAML: input})
	if err != nil || result.Total != 1 || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "dialer-proxy") {
		t.Fatal("unrepresentable YAML options were dropped silently")
	}
	if _, err := convertV2Ray(V2RayRequest{NodesYAML: "proxies: [{name: Bad, type: trojan, server: node.example, port: 443, password: p, smux: {enabled: true}}]"}); err == nil {
		t.Fatal("all unsupported YAML should fail without publishing empty results")
	}
}

func TestV2RayEditAndErrors(t *testing.T) {
	links := []string{"trojan://pass@node.example:443#A", "anytls://password@b.example:443#B"}
	result, err := editV2Ray(V2RayEditRequest{Links: links, Names: []string{"A 重命名", "B 重命名"}})
	if err != nil || result.Nodes[0].Name != "A 重命名" {
		t.Fatal("rename failed")
	}
	result, err = editV2Ray(V2RayEditRequest{Links: []string{result.Nodes[0].Link}, DeleteIndex: newInt(0)})
	if err != nil || result.Total != 0 || len(result.Nodes) != 0 || result.Subscription != "" {
		t.Fatal("delete last node failed")
	}
	for _, req := range []V2RayEditRequest{{Links: links, DeleteIndex: newInt(-1)}, {Links: links, DeleteIndex: newInt(2)}, {Links: links, Names: []string{"only one"}}, {Links: links, Names: []string{"", "B"}}} {
		if _, err := editV2Ray(req); err == nil {
			t.Fatal("invalid edit accepted")
		}
	}
	for _, link := range []string{"trojan://topsecret@host:70000", "tuic://topsecret@host:443", "vless://topsecret@host:443?security=reality", "vmess://topsecret", "ss://topsecret", "https://topsecret.example"} {
		if _, _, err := parseV2RayLink(link); err == nil || strings.Contains(err.Error(), "topsecret") {
			t.Fatal("invalid import accepted or error exposed credentials")
		}
	}
}

func TestV2RayHTTPWorkflowIsolationAndQRCode(t *testing.T) {
	a := testApp()
	a.subscriptionYAML = "saved Clash YAML"
	handler := a.handler()
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "http://127.0.0.1:8732"+path, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-App-Token", a.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	if w := request(http.MethodGet, "/v2ray-subscription.txt", nil); w.Code != http.StatusNotFound {
		t.Fatal("uninitialized subscription must be absent")
	}
	w := request(http.MethodPost, "/api/v2ray/convert", V2RayRequest{Links: "trojan://p@node.example:443#A"})
	var result V2RayResult
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Total != 1 {
		t.Fatalf("v2ray conversion failed: %s", w.Body.String())
	}
	get := request(http.MethodGet, "/v2ray-subscription.txt", nil)
	decoded, _ := base64.StdEncoding.DecodeString(get.Body.String())
	if string(decoded) != result.Content || a.subscriptionYAML != "saved Clash YAML" {
		t.Fatal("wrong subscription contents or Clash subscription overwritten")
	}
	qr := request(http.MethodPost, "/api/v2ray/qrcode", map[string]any{"link": result.Nodes[0].Link})
	image, err := png.Decode(bytes.NewReader(qr.Body.Bytes()))
	if err != nil || qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || image.Bounds().Dx() != 512 || image.Bounds().Dy() != 512 {
		t.Fatal("QR endpoint did not produce a 512px PNG")
	}
	for _, body := range []any{V2RayEditRequest{Links: []string{result.Nodes[0].Link}, DeleteIndex: newInt(1)}, map[string]any{"links": "malformed"}} {
		if w := request(http.MethodPost, "/api/v2ray/edit", body); w.Code != http.StatusBadRequest || a.v2raySubscription != result.Subscription {
			t.Fatal("invalid request replaced saved subscription")
		}
	}
	if w := request(http.MethodPost, "/api/v2ray/qrcode", map[string]any{"link": "vless://uuid@host:443?extra=" + strings.Repeat("a", 5000)}); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "容量") || a.v2raySubscription != result.Subscription {
		t.Fatal("oversized QR not handled without touching subscription")
	}
	w = request(http.MethodPost, "/api/v2ray/edit", V2RayEditRequest{Links: []string{result.Nodes[0].Link}, Names: []string{"新名称"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "新名称") {
		t.Fatal("rename endpoint failed")
	}
	var renamed V2RayResult
	_ = json.Unmarshal(w.Body.Bytes(), &renamed)
	w = request(http.MethodGet, "/api/v2ray/current", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "新名称") {
		t.Fatal("current result was not restored")
	}
	w = request(http.MethodPost, "/api/v2ray/edit", V2RayEditRequest{Links: []string{renamed.Nodes[0].Link}, DeleteIndex: newInt(0)})
	if w.Code != http.StatusOK || request(http.MethodGet, "/v2ray-subscription.txt", nil).Code != http.StatusOK || a.v2raySubscription != "" {
		t.Fatal("empty subscription not published after deleting last node")
	}
	if a.subscriptionYAML != "saved Clash YAML" {
		t.Fatal("Clash configuration changed")
	}
	for _, path := range []string{"/v2ray.html", "/v2ray.js"} {
		if request(http.MethodGet, path, nil).Code != http.StatusOK {
			t.Fatal("new page assets unavailable")
		}
	}
}

func TestV2RayHTTPGuards(t *testing.T) {
	for _, path := range []string{"/api/v2ray/convert", "/api/v2ray/edit", "/api/v2ray/qrcode", "/api/v2ray/current"} {
		for _, origin := range []string{"", "http://evil.example"} {
			method := http.MethodPost
			if strings.HasSuffix(path, "/current") {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, "http://127.0.0.1:8732"+path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", origin)
			if origin != "" {
				req.Header.Set("X-App-Token", "test-token")
			}
			w := httptest.NewRecorder()
			testApp().handler().ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("unguarded v2ray API: %s", path)
			}
		}
	}
}
