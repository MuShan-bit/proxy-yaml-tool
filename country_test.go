package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCountryLookupCachingAndNoPrivateIPs(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/8.8.8.8" {
			t.Error("unexpected query")
		}
		fmt.Fprint(w, `{"success":true,"ip":"8.8.8.8","country_code":"US","country":"United States"}`)
	}))
	defer server.Close()
	lookup := NewCountryLookup()
	lookup.baseURL = server.URL + "/"
	for i := 0; i < 2; i++ {
		if got := lookup.Label(context.Background(), "Node", "8.8.8.8"); got != "🇺🇸 美国 | Node" {
			t.Fatal("wrong country label")
		}
	}
	if got := lookup.Label(context.Background(), "🇯🇵 日本 | Node", "8.8.8.8"); got != "🇺🇸 美国 | Node" {
		t.Fatal("existing country prefix not replaced")
	}
	for _, ip := range []string{"node.example", "127.0.0.1", "10.0.0.1", "192.168.1.1", "192.0.2.1", "::1", "2001:db8::1", "fe80::1"} {
		if lookup.Label(context.Background(), "Node", ip) != "Node" {
			t.Fatal("private/domain not skipped")
		}
	}
	if requests != 1 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestCountryFailureIsCachedAndGraceful(t *testing.T) {
	for _, body := range []string{"not json", `{"success":false}`, `{"success":true,"ip":"1.1.1.1","country_code":"US"}`, `{"success":true,"ip":"8.8.8.8","country_code":"XX"}`} {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, body) }))
		lookup := NewCountryLookup()
		lookup.baseURL = server.URL + "/"
		for i := 0; i < 2; i++ {
			if lookup.Label(context.Background(), "Node", "8.8.8.8") != "Node" {
				t.Fatal("failed query renamed node")
			}
		}
		server.Close()
		if requests != 1 || len(lookup.Warnings) != 1 || strings.Contains(lookup.Warnings[0], body) {
			t.Fatal("failed lookup not cached or raw response leaked")
		}
	}
}
