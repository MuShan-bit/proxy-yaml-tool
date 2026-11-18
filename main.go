package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var assets embed.FS

type application struct {
	templatePath, token string
	allowRemote         bool
	subscriptionMu      sync.RWMutex
	subscriptionYAML    string
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, 415, map[string]any{"error": "请使用 JSON 请求"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误或超过 4 MB"})
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]any{"error": "请求只能包含一个 JSON 对象"})
		return false
	}
	return true
}

func (a *application) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"token": a.token}) })
	mux.HandleFunc("GET /api/template", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-App-Token") != a.token {
			writeJSON(w, 403, map[string]any{"error": "请刷新页面后重试"})
			return
		}
		if r.URL.Query().Get("blank") == "1" {
			writeJSON(w, 200, map[string]any{"yaml": blankTemplate, "name": "空白模板"})
			return
		}
		content, err := os.ReadFile(a.templatePath)
		if err != nil {
			writeJSON(w, 200, map[string]any{"yaml": blankTemplate, "name": "空白模板", "warning": "未找到本机 template.yaml，已加载空白模板；也可以上传配置文件"})
			return
		}
		if len(content) > 4<<20 {
			writeJSON(w, 400, map[string]any{"error": "模板超过 4 MB"})
			return
		}
		writeJSON(w, 200, map[string]any{"yaml": string(content), "name": filepath.Base(a.templatePath)})
	})
	mux.HandleFunc("GET /subscription.yaml", func(w http.ResponseWriter, r *http.Request) {
		a.subscriptionMu.RLock()
		content := a.subscriptionYAML
		a.subscriptionMu.RUnlock()
		if content == "" {
			http.Error(w, "尚未生成订阅，请先在网页中转换节点。", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename=proxy-yaml-subscription.yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, content)
	})
	mux.HandleFunc("POST /api/convert", func(w http.ResponseWriter, r *http.Request) {
		var request ConvertRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		result, err := Convert(r.Context(), request)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		a.subscriptionMu.Lock()
		a.subscriptionYAML = result.YAML
		a.subscriptionMu.Unlock()
		result.SubscriptionURL = "http://" + r.Host + "/subscription.yaml"
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/rename", func(w http.ResponseWriter, r *http.Request) {
		var request RenameRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		content, err := renameYAML(request.YAML, request.Names)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		a.subscriptionMu.Lock()
		a.subscriptionYAML = content
		a.subscriptionMu.Unlock()
		writeJSON(w, 200, map[string]any{"yaml": content, "subscriptionURL": "http://" + r.Host + "/subscription.yaml"})
	})
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if !a.allowRemote && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			writeJSON(w, 403, map[string]any{"error": "仅允许本机访问"})
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != "http" || parsed.Host != r.Host {
				writeJSON(w, 403, map[string]any{"error": "跨站请求已拒绝"})
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeJSON(w, 403, map[string]any{"error": "跨站请求已拒绝"})
			return
		}
		if r.Method == "POST" && r.Header.Get("X-App-Token") != a.token {
			writeJSON(w, 403, map[string]any{"error": "会话已变化，请刷新页面"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func run() error {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "convert" {
		return convertCLI(args[1:])
	}
	if len(args) > 0 && args[0] == "bbr" {
		return bbrCLI(args[1:])
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("proxy-yaml-web", flag.ContinueOnError)
	addr := flags.String("listen", "127.0.0.1:8732", "网页监听地址；0.0.0.0:8732 允许远程访问")
	templatePath := flags.String("template", "./template.yaml", "默认 YAML 模板路径")
	if err := flags.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return fmt.Errorf("监听地址格式错误，请使用 IP:端口，例如 0.0.0.0:8732：%w", err)
	}
	ip := net.ParseIP(host)
	allowRemote := host != "localhost" && (ip == nil || !ip.IsLoopback())
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	a := &application{templatePath: *templatePath, token: hex.EncodeToString(random[:]), allowRemote: allowRemote}
	server := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	fmt.Printf("节点配置转换工具：http://%s\n按 Ctrl+C 停止。配置仅预览 / 下载，不覆盖原模板。\n", listener.Addr())
	if allowRemote {
		fmt.Println("已启用远程访问，请在其他设备使用 http://服务器IP:端口 访问。当前页面和订阅无需登录。")
	}
	return server.Serve(listener)
}

func convertCLI(args []string) error {
	flags := flag.NewFlagSet("convert", flag.ContinueOnError)
	template := flags.String("template", "./template.yaml", "模板路径")
	links := flags.String("links", "", "分享链接文件，每行一个")
	output := flags.String("output", "", "输出文件（省略则写到 stdout）")
	country := flags.Bool("country", false, "通过 ipwho.is 查询 IP 国家")
	clean := flags.Bool("dedup", true, "清理模板内重复配置")
	if err := flags.Parse(args); err != nil {
		return err
	}
	content, err := os.ReadFile(*template)
	if err != nil {
		return err
	}
	request := ConvertRequest{Template: string(content), Options: ConvertOptions{CleanExisting: *clean, SyncGroups: true, Country: *country, MarkExisting: *country}}
	if *links != "" {
		raw, err := os.ReadFile(*links)
		if err != nil {
			return err
		}
		request.Links = string(raw)
	}
	result, err := Convert(context.Background(), request)
	if err != nil {
		return err
	}
	for _, warning := range result.Warnings {
		fmt.Fprintln(os.Stderr, warning)
	}
	if *output == "" {
		fmt.Print(result.YAML)
		return nil
	}
	if _, err := os.Stat(*output); err == nil {
		backup := *output + ".bak"
		for i := 2; ; i++ {
			if _, err := os.Stat(backup); errors.Is(err, os.ErrNotExist) {
				break
			}
			backup = fmt.Sprintf("%s.bak.%d", *output, i)
		}
		original, err := os.ReadFile(*output)
		if err != nil {
			return err
		}
		if err := os.WriteFile(backup, original, 0600); err != nil {
			return err
		}
	}
	return os.WriteFile(*output, []byte(result.YAML), 0600)
}

func bbrCLI(args []string) error {
	flags := flag.NewFlagSet("bbr", flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "只打印 BBR 配置")
	if err := flags.Parse(args); err != nil {
		return err
	}
	const settings = "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
	if *dryRun {
		fmt.Print(settings)
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("BBR 仅支持 Linux；请在目标服务器运行该命令")
	}
	file, err := os.CreateTemp("", "proxy-bbr-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(settings); err != nil {
		_ = file.Close()
		return err
	}
	_ = file.Close()
	for _, args := range [][]string{{"install", "-m", "0644", file.Name(), "/etc/sysctl.d/99-proxy-yaml-tool-bbr.conf"}, {"sysctl", "--system"}} {
		command := exec.Command(args[0], args[1:]...)
		if os.Geteuid() != 0 {
			command = exec.Command("sudo", args...)
		}
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
