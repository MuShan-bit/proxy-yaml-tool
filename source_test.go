package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestXrayJSONCRealityAndHTTPUpgrade(t *testing.T) {
	privateBytes, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	publicBytes, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	private := base64.RawURLEncoding.EncodeToString(privateBytes)
	source := `{
 // Xray split config from a server
 "inbounds":[
 {"protocol":"vless","port":443,"settings":{"clients":[{"id":"uuid","flow":"xtls-rprx-vision"}]},"streamSettings":{"security":"reality","network":"tcp","realitySettings":{"privateKey":"PRIVATE","serverNames":["sni.example"],"shortIds":["ab"]}}},
 {"protocol":"trojan","port":8443,"settings":{"clients":[{"password":"secret"}]},"streamSettings":{"security":"tls","network":"httpupgrade","tlsSettings":{"serverName":"sni.example"},"httpupgradeSettings":{"path":"/edge","host":"cdn.example"}}},
 ],
}`
	source = strings.Replace(source, "PRIVATE", private, 1)
	r := DecodeSource([]byte(source), "/etc/xray/conf/test.json", "192.0.2.1", "", false)
	if len(r.Nodes) != 2 {
		t.Fatalf("wrong count: %d; warnings %v", len(r.Nodes), r.Warnings)
	}
	reality := object(r.Nodes[0]["reality-opts"])
	if reality["public-key"] != base64.RawURLEncoding.EncodeToString(publicBytes) || reality["short-id"] != "ab" {
		t.Fatal("Reality public key incorrect")
	}
	if r.Nodes[0]["servername"] != "sni.example" || r.Nodes[0]["flow"] != "xtls-rprx-vision" {
		t.Fatal("Reality TLS/flow incorrect")
	}
	encoded, _ := json.Marshal(r.Nodes)
	if strings.Contains(string(encoded), private) || strings.Contains(string(encoded), "privateKey") {
		t.Fatal("private key leaked to client nodes")
	}
	if r.Nodes[1]["network"] != "ws" || object(r.Nodes[1]["ws-opts"])["v2ray-http-upgrade"] != true {
		t.Fatal("HTTPUpgrade wrong")
	}
}

func TestSingBoxAndStandaloneSources(t *testing.T) {
	sources := []struct {
		path, input string
		kinds       []string
	}{
		{"/etc/sing-box/config.json", `{"inbounds":[{"type":"anytls","listen_port":443,"users":[{"name":"A","password":"p"}],"tls":{"enabled":true,"server_name":"sni.example"}},{"type":"tuic","listen_port":8443,"users":[{"uuid":"uuid","password":"p"}],"congestion_control":"bbr","tls":{"enabled":true,"server_name":"sni.example","alpn":["h3"]}},{"type":"shadowsocks","listen_port":8388,"method":"2022-blake3-aes-128-gcm","password":"server-key","users":[{"name":"User","password":"user-key"}]}]}`, []string{"anytls", "tuic", "ss"}},
		{"/etc/hysteria/config.yaml", "listen: :443\nauth:\n  type: password\n  password: secret\nobfs:\n  type: salamander\n  salamander:\n    password: obfs-secret\nacme:\n  domains: [sni.example]\n", []string{"hysteria2"}},
		{"/etc/tuic/config.json", `{"server":"[::]:443","users":{"uuid":"p"},"congestion_control":"bbr","alpn":["h3"]}`, []string{"tuic"}},
		{"/etc/anytls/config.json", `{"listen":"0.0.0.0:443","password":"secret"}`, []string{"anytls"}},
		{"/etc/anytls/config.json", `{"listen":"0.0.0.0:443","users":[{"name":"A","password":"secret"}],"tls":{"server_name":"sni.example"}}`, []string{"anytls"}},
		{"/etc/shadowsocks-rust/config.json", `{"server_port":8388,"method":"2022-blake3-aes-128-gcm","password":"server-key"}`, []string{"ss"}},
	}
	for _, tc := range sources {
		t.Run(tc.path, func(t *testing.T) {
			r := DecodeSource([]byte(tc.input), tc.path, "192.0.2.1", "override.example", false)
			if len(r.Nodes) != len(tc.kinds) {
				t.Fatalf("wrong node count: %d warnings=%v", len(r.Nodes), r.Warnings)
			}
			for i, kind := range tc.kinds {
				if r.Nodes[i]["type"] != kind || r.Nodes[i]["server"] != "192.0.2.1" {
					t.Fatal("incorrect node")
				}
				if _, ok := r.Nodes[i]["skip-cert-verify"]; ok {
					t.Fatal("must not disable cert verification by default")
				}
			}
			if len(r.Nodes) == 3 && r.Nodes[2]["password"] != "server-key:user-key" {
				t.Fatal("SS2022 multi-user key chain missing")
			}
			if tc.kinds[0] == "hysteria2" && (r.Nodes[0]["obfs"] != "salamander" || r.Nodes[0]["obfs-password"] != "obfs-secret") {
				t.Fatal("Hysteria2 obfs incorrectly mapped")
			}
		})
	}
}

func TestSourceErrorsAndDynamicAuthentication(t *testing.T) {
	for _, source := range []string{"not json", `{"inbounds":[{"type":"unknown","listen_port":443}]}`, `{"listen":":443","auth":{"type":"http","http":{"url":"https://auth.example"}}}`} {
		r := DecodeSource([]byte(source), "/etc/hysteria/config.json", "192.0.2.1", "", false)
		if len(r.Nodes) != 0 || len(r.Warnings) == 0 {
			t.Fatal("unreadable/unsupported source should produce warning")
		}
	}
}
