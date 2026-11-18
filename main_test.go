package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testApp() *application {
	return &application{templatePath: "does-not-exist.yaml", token: "test-token"}
}

func TestHTTPSubscriptionAndRename(t *testing.T) {
	a := testApp()
	empty := httptest.NewRecorder()
	a.handler().ServeHTTP(empty, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8732/subscription.yaml", nil))
	if empty.Code != http.StatusNotFound {
		t.Fatal("empty subscription should return 404")
	}
	body, _ := json.Marshal(ConvertRequest{Template: blankTemplate, Links: "tuic://uuid:p@node.example:443#Node", Options: ConvertOptions{SyncGroups: true}})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/convert", strings.NewReader(string(body)))
	req.Header.Set("X-App-Token", a.token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("convert API status=%d body=%s", w.Code, w.Body.String())
	}
	var result ConvertResult
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result.Added != 1 || result.Total != 1 {
		t.Fatal("API conversion failed")
	}
	if result.SubscriptionURL != "http://127.0.0.1:8732/subscription.yaml" {
		t.Fatalf("subscription URL missing: %q", result.SubscriptionURL)
	}
	get := httptest.NewRecorder()
	a.handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, result.SubscriptionURL, nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "name: Node") {
		t.Fatal("subscription endpoint did not return converted YAML")
	}
	renameBody, _ := json.Marshal(RenameRequest{YAML: result.YAML, Names: []string{"Edited Node"}})
	rename := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/rename", strings.NewReader(string(renameBody)))
	rename.Header.Set("X-App-Token", a.token)
	rename.Header.Set("Content-Type", "application/json")
	rw := httptest.NewRecorder()
	a.handler().ServeHTTP(rw, rename)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "Edited Node") {
		t.Fatalf("rename API failed: %s", rw.Body.String())
	}
	updated := httptest.NewRecorder()
	a.handler().ServeHTTP(updated, httptest.NewRequest(http.MethodGet, result.SubscriptionURL, nil))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "name: Edited Node") || strings.Contains(updated.Body.String(), "name: Node\n") {
		t.Fatal("subscription did not return saved name")
	}
	req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/discover", strings.NewReader(`{"host":"192.0.2.1","password":"ssh-secret"}`))
	req.Header.Set("X-App-Token", a.token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code < 400 || strings.Contains(w.Body.String(), "ssh-secret") {
		t.Fatal("removed SSH endpoint still available or credentials echoed")
	}
}

func TestHTTPBlocksForeignRequestsAndMissingTokens(t *testing.T) {
	for _, tc := range []struct{ host, origin, token string }{{"evil.example:8732", "", "test-token"}, {"127.0.0.1:8732", "https://evil.example", "test-token"}, {"127.0.0.1:8732", "", ""}} {
		req := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/api/discover", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("X-App-Token", tc.token)
		w := httptest.NewRecorder()
		testApp().handler().ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("unsafe request accepted: status %d", w.Code)
		}
	}
}

func TestRemoteHTTPWorkflow(t *testing.T) {
	a := testApp()
	a.allowRemote = true
	handler := a.handler()
	base := "http://198.51.100.10:8732"
	request := func(method, path, body string, token bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, base+path, strings.NewReader(body))
		req.RemoteAddr = "203.0.113.20:45000"
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", base)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if token {
			req.Header.Set("X-App-Token", a.token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	for _, path := range []string{"/", "/app.js", "/api/session", "/api/template"} {
		if w := request(http.MethodGet, path, "", true); w.Code != http.StatusOK {
			t.Fatalf("remote %s failed: %d %s", path, w.Code, w.Body.String())
		}
	}
	body, _ := json.Marshal(ConvertRequest{Template: blankTemplate, Links: "tuic://uuid:password@node.example:443#Remote", Options: ConvertOptions{SyncGroups: true}})
	w := request(http.MethodPost, "/api/convert", string(body), true)
	if w.Code != http.StatusOK {
		t.Fatalf("remote conversion failed: %d %s", w.Code, w.Body.String())
	}
	var result ConvertResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Added != 1 || result.SubscriptionURL != base+"/subscription.yaml" {
		t.Fatal("remote result or subscription URL incorrect")
	}
	rename, _ := json.Marshal(RenameRequest{YAML: result.YAML, Names: []string{"Remote-Renamed"}})
	if w := request(http.MethodPost, "/api/rename", string(rename), true); w.Code != http.StatusOK {
		t.Fatalf("remote rename failed: %s", w.Body.String())
	}
	if w := request(http.MethodGet, "/subscription.yaml", "", false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Remote-Renamed") {
		t.Fatal("remote Clash Verge subscription unavailable")
	}
	if w := request(http.MethodPost, "/api/convert", string(body), false); w.Code != http.StatusForbidden {
		t.Fatal("remote API accepted a request without its session token")
	}
}

func TestRemoteHTTPStillRejectsCrossSiteRequests(t *testing.T) {
	for _, tc := range []struct{ origin, site string }{
		{"http://other.example", "same-origin"},
		{"null", ""},
		{"http://198.51.100.10:8732", "cross-site"},
	} {
		a := testApp()
		a.allowRemote = true
		req := httptest.NewRequest(http.MethodPost, "http://198.51.100.10:8732/api/convert", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Sec-Fetch-Site", tc.site)
		req.Header.Set("X-App-Token", a.token)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-site request accepted: origin=%s site=%s status=%d", tc.origin, tc.site, w.Code)
		}
	}
}

func TestEmbeddedPageAndBlankTemplate(t *testing.T) {
	a := testApp()
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8732"+path, nil))
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("static asset failed: %s", path)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8732/api/template", nil)
	req.Header.Set("X-App-Token", a.token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "未找到本机") {
		t.Fatal("blank template fallback failed")
	}
}

func TestUnsupportedImportKeepsLastSubscription(t *testing.T) {
	a := testApp()
	a.subscriptionYAML = "last valid subscription"
	body, _ := json.Marshal(ConvertRequest{Template: blankTemplate, Links: vmessQUICLink(t)})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8732/api/convert", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Token", a.token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "QUIC") {
		t.Fatalf("incompatible import error missing: %s", w.Body.String())
	}
	get := httptest.NewRecorder()
	a.handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8732/subscription.yaml", nil))
	if get.Code != http.StatusOK || get.Body.String() != "last valid subscription" {
		t.Fatal("unsupported import overwrote the last valid subscription")
	}
}
