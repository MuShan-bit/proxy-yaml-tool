package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const deleteFixture = `# preserve template comment
proxies:
  - {name: A, type: trojan, server: a.example, port: 443, password: a}
  - name: B
    type: vless
    server: b.example
    port: 8443
    uuid: b-uuid
    network: ws
    ws-opts: {path: /edge, headers: {Host: cdn.example}}
  - {name: AA, type: trojan, server: aa.example, port: 443, password: aa}
proxy-groups:
  - {name: Select, type: select, proxies: [A, B, A, AA, DIRECT]}
  - {name: Auto, type: url-test, proxies: [A], url: 'https://example.com', interval: 300}
rules:
  - IP-CIDR,192.0.2.0/24,A,no-resolve
  - AND,((NETWORK,TCP),(DST-PORT,443)),A
  - DOMAIN,a.example,AA
  - SUB-RULE,(NETWORK,TCP),A
  - MATCH,Select
sub-rules:
  A:
    - DOMAIN,delete.example,A
    - MATCH,B
`

func TestDeleteNodeCleansOnlyItsReferences(t *testing.T) {
	index := 0
	result, err := deleteYAML(deleteFixture, &index)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 || result.DeletedName != "A" || result.RemovedRules != 3 || !strings.Contains(result.YAML, "# preserve template comment") {
		t.Fatal("deletion counts or comment incorrect")
	}
	before, after := decodeOutput(t, deleteFixture), decodeOutput(t, result.YAML)
	if !reflect.DeepEqual(items(before["proxies"])[1:], items(after["proxies"])) {
		t.Fatal("surviving authentication or transport configuration changed")
	}
	groups := items(after["proxy-groups"])
	if !reflect.DeepEqual(stringList(object(groups[0])["proxies"]), []string{"B", "AA", "DIRECT"}) || len(items(object(groups[1])["proxies"])) != 0 {
		t.Fatal("group references not cleaned exactly")
	}
	if object(groups[1])["url"] != "https://example.com" || object(groups[1])["interval"] != 300 {
		t.Fatal("group options changed")
	}
	if !reflect.DeepEqual(stringList(after["rules"]), []string{"DOMAIN,a.example,AA", "SUB-RULE,(NETWORK,TCP),A", "MATCH,Select"}) || firstString(object(after["sub-rules"])["A"]) != "MATCH,B" {
		t.Fatal("rule or subrule cleanup incorrect")
	}
}

func TestDeleteLastNodeAndInvalidIndexes(t *testing.T) {
	input := "proxies: [{name: Only, type: trojan, server: node.example, port: 443, password: p}]\nproxy-groups: [{name: Select, type: select, proxies: [Only]}]\nrules: ['MATCH,Select']\n"
	index := 0
	result, err := deleteYAML(input, &index)
	if err != nil {
		t.Fatal(err)
	}
	m := decodeOutput(t, result.YAML)
	if result.Total != 0 || len(items(m["proxies"])) != 0 || len(items(object(items(m["proxy-groups"])[0])["proxies"])) != 0 {
		t.Fatal("last node did not leave empty sequences")
	}
	for _, index := range []*int{nil, newInt(-1), newInt(1)} {
		if _, err := deleteYAML(input, index); err == nil {
			t.Fatal("invalid index accepted")
		}
	}
	if _, err := deleteYAML(result.YAML, newInt(0)); err == nil {
		t.Fatal("deletion from empty list accepted")
	}
	if _, err := deleteYAML("invalid yaml", newInt(0)); err == nil {
		t.Fatal("invalid YAML accepted")
	}
}

func newInt(value int) *int { return &value }

func TestDeleteRejectsDependentRoutes(t *testing.T) {
	for _, dependency := range []string{
		"proxies:\n  - {name: A, type: trojan, server: a.example, port: 443, password: a}\n  - {name: B, type: trojan, server: b.example, port: 443, password: b, dialer-proxy: A}\n",
		"proxies: [{name: A, type: trojan, server: a.example, port: 443, password: a}]\nproxy-providers: {remote: {proxy: A}}\n",
		"proxies: [{name: A, type: trojan, server: a.example, port: 443, password: a}]\nrule-providers: {remote: {proxy: A}}\n",
	} {
		if _, err := deleteYAML(dependency, newInt(0)); err == nil || !strings.Contains(err.Error(), "依赖项") {
			t.Fatal("dependent outbound route was silently bypassed")
		}
	}
}

func TestHTTPDeleteUpdatesSubscriptionOnlyOnSuccess(t *testing.T) {
	a := testApp()
	a.subscriptionYAML = deleteFixture
	handler := a.handler()
	request := func(body, token, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/delete", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-App-Token", token)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	for _, body := range []string{`{}`, `{"yaml":"proxies: []","index":0}`, `{"yaml":"proxies: []"}`, `{"index":-1}`, `{"index":"0"}`} {
		if w := request(body, a.token, ""); w.Code != http.StatusBadRequest || a.subscriptionYAML != deleteFixture {
			t.Fatal("invalid deletion changed subscription")
		}
	}
	body, _ := json.Marshal(DeleteRequest{YAML: deleteFixture, Index: newInt(1)})
	for _, guard := range []struct{ token, origin string }{{"", ""}, {a.token, "https://evil.example"}} {
		if w := request(string(body), guard.token, guard.origin); w.Code != http.StatusForbidden || a.subscriptionYAML != deleteFixture {
			t.Fatal("deletion bypassed request guard")
		}
	}
	w := request(string(body), a.token, "http://127.0.0.1:8732")
	if w.Code != http.StatusOK {
		t.Fatalf("delete API failed: %s", w.Body.String())
	}
	var result DeleteResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, result.SubscriptionURL, nil))
	if result.Total != 2 || result.DeletedName != "B" || get.Code != http.StatusOK || get.Body.String() != result.YAML || strings.Contains(result.YAML, "b-uuid") {
		t.Fatal("subscription does not match deletion result")
	}
	// The same restore operation used by Undo must also restore the served subscription.
	restore, _ := json.Marshal(ConvertRequest{Template: deleteFixture})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/convert", strings.NewReader(string(restore)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Token", a.token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !reflect.DeepEqual(decodeOutput(t, deleteFixture), decodeOutput(t, a.subscriptionYAML)) {
		t.Fatal("undo did not restore subscription")
	}
}
