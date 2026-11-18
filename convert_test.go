package main

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func decodeOutput(t *testing.T, output string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(output), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestConvertDedupAndReferences(t *testing.T) {
	template := `# keep this comment
mixed-port: 7890
proxies:
  - {name: Original, type: trojan, server: node.example, port: 443, password: p, udp: true, tls: true}
  - {password: p, name: Duplicate, port: 443, type: trojan, udp: true, server: node.example, tls: true}
proxy-groups:
  - name: Select
    type: select
    proxies: [Original, Duplicate, DIRECT]
rules:
  - IP-CIDR,8.8.8.8/32,Duplicate,no-resolve
  - AND,((NETWORK,TCP),(DST-PORT,443)),Duplicate
  - SUB-RULE,(NETWORK,TCP),Duplicate
sub-rules:
  Duplicate:
    - MATCH,Duplicate
proxy-providers:
  provider:
    proxy: Duplicate
`
	req := ConvertRequest{Template: template, Links: "trojan://p@node.example:443#NewName\ntrojan://different@node.example:443#Original\ntrojan://different@node.example:443#Again", Options: ConvertOptions{CleanExisting: true, SyncGroups: true}}
	r, err := Convert(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if r.Added != 1 || r.Skipped != 2 || r.Removed != 1 || r.Total != 2 {
		t.Fatalf("wrong counts: added=%d skipped=%d removed=%d total=%d", r.Added, r.Skipped, r.Removed, r.Total)
	}
	if !strings.Contains(r.YAML, "# keep this comment") || !strings.Contains(r.YAML, "Original-2") {
		t.Fatal("comment or collision name lost")
	}
	m := decodeOutput(t, r.YAML)
	refs := items(object(items(m["proxy-groups"])[0])["proxies"])
	if len(refs) != 3 || refs[0] != "Original" || refs[2] != "Original-2" {
		t.Fatal("groups not remapped/deduplicated")
	}
	rules := stringList(m["rules"])
	if rules[0] != "IP-CIDR,8.8.8.8/32,Original,no-resolve" || rules[1] != "AND,((NETWORK,TCP),(DST-PORT,443)),Original" || rules[2] != "SUB-RULE,(NETWORK,TCP),Duplicate" {
		t.Fatal("rule references incorrect")
	}
	if firstString(object(m["sub-rules"])["Duplicate"]) != "MATCH,Original" {
		t.Fatal("subrule target incorrect")
	}
	if object(object(m["proxy-providers"])["provider"])["proxy"] != "Original" {
		t.Fatal("provider target not updated")
	}
	req.Template = r.YAML
	second, err := Convert(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if second.Added != 0 || second.Skipped != 3 || second.Total != 2 || second.YAML != r.YAML {
		t.Fatal("repeat conversion not idempotent")
	}
}

func TestDistinctConfigurationPreserved(t *testing.T) {
	base := "vless://uuid@node.example:443?security=reality&pbk=public&sid=ab&sni=sni.example&type=ws&path=%2Fedge&host=cdn.example#Node"
	links := []string{base, strings.Replace(base, "uuid@", "uuid2@", 1), strings.Replace(base, ":443?", ":8443?", 1), strings.Replace(base, "pbk=public", "pbk=other", 1), strings.Replace(base, "sid=ab", "sid=cd", 1), strings.Replace(base, "path=%2Fedge", "path=%2Fother", 1), strings.Replace(base, "host=cdn.example", "host=other.example", 1)}
	r, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, Links: strings.Join(links, "\n"), Options: ConvertOptions{SyncGroups: true}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != len(links) {
		t.Fatal("distinct auth/TLS/transport was merged")
	}
}

func TestBulkIPAndNoSync(t *testing.T) {
	r, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, Links: "tuic://uuid:p@node.example:443#Node", Servers: "192.0.2.1\n2001:db8::1\n192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Added != 2 || r.Nodes[0].Server != "192.0.2.1" || r.Nodes[1].Server != "2001:db8::1" {
		t.Fatal("bulk IP expansion incorrect")
	}
	if r.Nodes[0].Transport != "udp / quic" {
		t.Fatal("UDP transport not identified")
	}
	m := decodeOutput(t, r.YAML)
	if len(items(object(items(m["proxy-groups"])[1])["proxies"])) != 0 {
		t.Fatal("syncGroups=false ignored")
	}
}

func TestTemplateValidation(t *testing.T) {
	for _, input := range []string{"", "[]", "proxies: bad", "proxies: []\nproxies: []", "proxies: []\n---\nproxies: []", "proxies: [{name: A}, {name: A}]"} {
		if _, err := Convert(context.Background(), ConvertRequest{Template: input}); err == nil {
			t.Fatalf("invalid template accepted: %q", input)
		}
	}
}

func TestNodesYAMLImportAndRename(t *testing.T) {
	input := `- name: First
  type: trojan
  server: node.example
  port: 443
  password: secret
  tls: true
- name: SameName
  type: trojan
  server: node.example
  port: 443
  password: secret
  tls: true`
	r, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, NodesYAML: input, Options: ConvertOptions{SyncGroups: true}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Added != 1 || r.Skipped != 1 || r.Total != 1 {
		t.Fatalf("nodes YAML dedup failed: added=%d skipped=%d total=%d", r.Added, r.Skipped, r.Total)
	}
	if !strings.Contains(r.YAML, "First") {
		t.Fatal("imported node missing")
	}
	renamed, err := renameYAML(r.YAML, []string{"Renamed"})
	if err != nil {
		t.Fatal(err)
	}
	m := decodeOutput(t, renamed)
	if object(items(m["proxies"])[0])["name"] != "Renamed" {
		t.Fatal("node rename not reflected in YAML")
	}
	for _, group := range items(m["proxy-groups"]) {
		refs := stringList(object(group)["proxies"])
		if !strings.Contains(strings.Join(refs, "|"), "Renamed") || strings.Contains(strings.Join(refs, "|"), "First") {
			t.Fatal("group reference not renamed")
		}
	}
}

func TestRenameValidationAndReferences(t *testing.T) {
	input := `proxies:
  - {name: A, type: trojan, server: a.example, port: 443, password: a}
  - {name: B, type: trojan, server: b.example, port: 443, password: b, dialer-proxy: A}
proxy-groups:
  - {name: Select, type: select, proxies: [A, B]}
rules:
  - IP-CIDR,192.0.2.0/24,A,no-resolve
  - MATCH,B
sub-rules:
  nested: ["MATCH,A"]
proxy-providers:
  remote: {proxy: B}
`
	for _, names := range [][]string{{"B", "B"}, {"A", "A"}, {"", "B"}, {"Select", "B"}, {"DIRECT", "B"}, {"bad,name", "B"}, {"A"}} {
		if _, err := renameYAML(input, names); err == nil {
			t.Fatalf("invalid names accepted: %v", names)
		}
	}
	output, err := renameYAML(input, []string{"B", "A"})
	if err != nil {
		t.Fatal(err)
	}
	m := decodeOutput(t, output)
	refs := stringList(object(items(m["proxy-groups"])[0])["proxies"])
	if strings.Join(refs, ",") != "B,A" || stringList(m["rules"])[0] != "IP-CIDR,192.0.2.0/24,B,no-resolve" || stringList(m["rules"])[1] != "MATCH,A" {
		t.Fatal("simultaneous rename corrupted groups/rules")
	}
	if object(items(m["proxies"])[1])["dialer-proxy"] != "B" || object(object(m["proxy-providers"])["remote"])["proxy"] != "A" {
		t.Fatal("dialer/provider references not renamed")
	}
	if stringList(object(m["sub-rules"])["nested"])[0] != "MATCH,B" {
		t.Fatal("subrule target not renamed")
	}
}

func TestNodesYAMLValidation(t *testing.T) {
	for _, input := range []string{"proxies: bad", "[]\n---\n[]", "proxies: []\nproxies: []", "[{type: trojan, server: node.example, port: 443}]", "[{type: trojan, server: node.example, port: 0, password: p}]"} {
		if _, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, NodesYAML: input}); err == nil {
			t.Fatalf("invalid node YAML accepted: %q", input)
		}
	}
}

func TestBatchSkipsUnsupportedVMessQUIC(t *testing.T) {
	links := strings.Join([]string{"# batch", "", "# third line", "trojan://p@node.example:443#Valid", vmessQUICLink(t)}, "\n")
	r, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, Links: links, Options: ConvertOptions{SyncGroups: true}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Added != 1 || r.Total != 1 || r.Skipped != 0 || r.Unsupported != 1 || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "第 5 行已跳过") {
		t.Fatalf("batch compatibility handling incorrect: added=%d total=%d duplicate=%d incompatible=%d warnings=%v", r.Added, r.Total, r.Skipped, r.Unsupported, r.Warnings)
	}
	if strings.Contains(r.YAML, "quic") || strings.Contains(r.YAML, "VMess-QUIC") {
		t.Fatal("unsupported proxy or group reference leaked into output")
	}
	if _, err := Convert(context.Background(), ConvertRequest{Template: r.YAML, Links: vmessQUICLink(t)}); err == nil {
		t.Fatal("entirely unsupported import should fail")
	}
	if _, err := Convert(context.Background(), ConvertRequest{Template: blankTemplate, Links: "trojan://p@node.example:443#Valid\nvmess://invalid"}); err == nil {
		t.Fatal("malformed link must still fail instead of being silently skipped")
	}
	_, err = Convert(context.Background(), ConvertRequest{Template: blankTemplate, NodesYAML: `[{name: Test, type: vmess, server: node.example, port: 443, uuid: u, network: quic}]`})
	if err == nil || !strings.Contains(err.Error(), "Mihomo") {
		t.Fatal("YAML import bypassed transport compatibility check")
	}
}
