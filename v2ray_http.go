package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

func (a *application) registerV2Ray(mux *http.ServeMux) {
	publish := func(w http.ResponseWriter, r *http.Request, result V2RayResult, err error) {
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		a.subscriptionMu.Lock()
		a.v2raySubscription, a.v2rayReady = result.Subscription, true
		a.subscriptionMu.Unlock()
		result.SubscriptionURL = "http://" + r.Host + "/v2ray-subscription.txt"
		writeJSON(w, http.StatusOK, result)
	}
	mux.HandleFunc("POST /api/v2ray/convert", func(w http.ResponseWriter, r *http.Request) {
		var request V2RayRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		result, err := convertV2Ray(request)
		publish(w, r, result, err)
	})
	mux.HandleFunc("POST /api/v2ray/edit", func(w http.ResponseWriter, r *http.Request) {
		var request V2RayEditRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		result, err := editV2Ray(request)
		publish(w, r, result, err)
	})
	mux.HandleFunc("GET /api/v2ray/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-App-Token") != a.token {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "请刷新页面后重试"})
			return
		}
		a.subscriptionMu.RLock()
		content, ready := a.v2raySubscription, a.v2rayReady
		a.subscriptionMu.RUnlock()
		if !ready {
			writeJSON(w, http.StatusOK, map[string]any{"ready": false})
			return
		}
		decoded, _ := base64.StdEncoding.DecodeString(content)
		links := []string{}
		if len(decoded) > 0 {
			links = strings.Split(string(decoded), "\n")
		}
		result, err := editV2Ray(V2RayEditRequest{Links: links})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "当前订阅读取失败"})
			return
		}
		result.SubscriptionURL = "http://" + r.Host + "/v2ray-subscription.txt"
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /v2ray-subscription.txt", func(w http.ResponseWriter, r *http.Request) {
		a.subscriptionMu.RLock()
		content, ready := a.v2raySubscription, a.v2rayReady
		a.subscriptionMu.RUnlock()
		if !ready {
			http.Error(w, "尚未生成 v2rayN 订阅，请先导入节点。", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename=v2ray-subscription.txt")
		_, _ = io.WriteString(w, content)
	})
	mux.HandleFunc("POST /api/v2ray/qrcode", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Link string `json:"link"`
		}
		if !decodeJSON(w, r, &request) {
			return
		}
		node, _, err := parseV2RayLink(request.Link)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		png, err := qrcode.Encode(node.Link, qrcode.Medium, 512)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "节点链接超过二维码容量，请复制分享链接导入"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	})
}
