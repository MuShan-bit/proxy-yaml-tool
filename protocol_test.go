package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestShareLinks(t *testing.T) {
	cases := []struct{ link, kind, auth string }{
		{"vless://u@node.example:443?security=reality&pbk=public&sid=ab&sni=sni.example&fp=chrome#Name", "vless", "u"},
		{"trojan://pass%3Aword%2B@node.example:443?sni=sni.example#Name", "trojan", "pass:word+"},
		{"hy2://user:pass@node.example:443?obfs=salamander&obfs-password=obfs&insecure=1#Name", "hysteria2", "user:pass"},
		{"tuic://u:pass%2B@node.example:443?congestion_control=bbr&alpn=h3#Name", "tuic", "pass+"},
		{"anytls://pass@node.example:443?sni=sni.example#Name", "anytls", "pass"},
		{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:key:key2")) + "@[2001:4860::1]:8443#Name", "ss", "key:key2"},
		{"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass@node.example:8388")) + "#Name", "ss", "pass"},
	}
	for _, tc := range cases {
		t.Run(tc.kind+tc.auth, func(t *testing.T) {
			p, err := ParseLink(tc.link)
			if err != nil {
				t.Fatal(err)
			}
			if p["type"] != tc.kind || p["name"] != "Name" {
				t.Fatalf("wrong type or name: %s", p["type"])
			}
			key := "password"
			if tc.kind == "vless" {
				key = "uuid"
			}
			if p[key] != tc.auth {
				t.Fatal("authentication not preserved")
			}
			if tc.kind == "hysteria2" && (p["obfs"] != "salamander" || p["obfs-password"] != "obfs") {
				t.Fatal("incorrect Mihomo obfs fields")
			}
		})
	}
}

func TestTransportMatrix(t *testing.T) {
	for _, kind := range []string{"vless", "trojan", "vmess"} {
		for _, transport := range []string{"ws", "h2", "httpupgrade"} {
			t.Run(kind+"-"+transport, func(t *testing.T) {
				link := fmt.Sprintf("%s://auth@node.example:443?security=tls&type=%s&path=%%2Fedge&host=cdn.example&sni=sni.example", kind, transport)
				if kind == "vmess" {
					data, _ := json.Marshal(map[string]any{"add": "node.example", "port": "443", "id": "auth", "net": transport, "type": "none", "path": "/edge", "host": "cdn.example", "sni": "sni.example", "tls": "tls"})
					link = "vmess://" + base64.StdEncoding.EncodeToString(data)
				}
				p, err := ParseLink(link)
				if err != nil {
					t.Fatal(err)
				}
				if p["tls"] != true {
					t.Fatal("TLS missing")
				}
				switch transport {
				case "ws":
					if object(p["ws-opts"])["path"] != "/edge" {
						t.Fatal("WS path missing")
					}
				case "h2":
					if p["network"] != "h2" || object(p["h2-opts"])["path"] != "/edge" {
						t.Fatal("H2 options missing")
					}
				case "httpupgrade":
					if p["network"] != "ws" || object(p["ws-opts"])["v2ray-http-upgrade"] != true {
						t.Fatal("HTTPUpgrade must use Mihomo WS upgrade options")
					}
				}
			})
		}
	}
}

func TestInvalidLinksDoNotEchoCredentials(t *testing.T) {
	for _, link := range []string{"trojan://topsecret@host:70000", "tuic://topsecret@host:443", "vless://topsecret@host:443?security=reality", "vmess://topsecret", "ss://topsecret"} {
		_, err := ParseLink(link)
		if err == nil || strings.Contains(err.Error(), "topsecret") {
			t.Fatal("invalid link accepted or credentials echoed")
		}
	}
}

func vmessQUICLink(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"v": 2, "ps": "VMess-QUIC", "add": "192.0.2.1", "port": "2003",
		"id": "11111111-1111-4111-8111-111111111111", "aid": "0",
		"net": "quic", "type": "none", "tls": "tls", "alpn": "h3",
	})
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(data)
}

func TestVMessQUICReportsClientIncompatibility(t *testing.T) {
	link := vmessQUICLink(t)
	for _, raw := range []string{link, strings.Replace(link, "vmess://", `vmess\://`, 1)} {
		p, err := ParseLink(raw)
		var unsupported *UnsupportedTransportError
		if !errors.As(err, &unsupported) || unsupported.Protocol != "vmess" || unsupported.Network != "quic" || p != nil {
			t.Fatal("VMess QUIC must not produce a TCP or unusable Mihomo node")
		}
		if !strings.Contains(err.Error(), "Clash Verge / Mihomo") || strings.Contains(err.Error(), "11111111") || strings.Contains(err.Error(), "192.0.2.1") {
			t.Fatal("incompatibility message missing or reveals node details")
		}
	}
}

func TestEscapedLinkScheme(t *testing.T) {
	p, err := ParseLink(`trojan\://pass%3Aword@node.example:443?sni=sni.example#Copied`)
	if err != nil {
		t.Fatal(err)
	}
	if p["type"] != "trojan" || p["password"] != "pass:word" || p["name"] != "Copied" || p["sni"] != "sni.example" {
		t.Fatal("scheme normalization changed link parameters")
	}
}
