package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SSHRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Password    string `json:"password"`
	PrivateKey  string `json:"privateKey"`
	Passphrase  string `json:"passphrase"`
	Fingerprint string `json:"fingerprint"`
	Paths       string `json:"paths"`
	SNI         string `json:"sni"`
	Insecure    bool   `json:"insecure"`
}

type TrustError struct {
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
}

func (e *TrustError) Error() string {
	return "首次连接：请核对 SSH 主机指纹后再读取配置"
}

type Discovery struct {
	Nodes       []Proxy  `json:"nodes"`
	Warnings    []string `json:"warnings"`
	Files       []string `json:"files"`
	Fingerprint string   `json:"fingerprint"`
}

var defaultPaths = []string{
	"/etc/xray/config.json", "/usr/local/etc/xray/config.json", "/etc/v2ray/config.json", "/usr/local/etc/v2ray/config.json",
	"/etc/sing-box/config.json", "/usr/local/etc/sing-box/config.json",
	"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/hysteria/config.json", "/etc/hysteria2/config.yaml", "/etc/hysteria2/config.json",
	"/etc/tuic/config.json", "/etc/tuic/tuic.json", "/opt/tuic/config.json", "/etc/anytls/config.json", "/etc/anytls/config.yaml",
	"/etc/shadowsocks-libev/config.json", "/etc/shadowsocks-rust/config.json", "/etc/shadowsocks/config.json",
}
var defaultDirectories = []string{"/etc/xray/conf", "/etc/xray/confs", "/usr/local/etc/xray/conf", "/etc/sing-box/conf", "/etc/sing-box/conf.d", "/etc/hysteria", "/etc/tuic", "/etc/anytls"}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func connectSSH(ctx context.Context, req SSHRequest) (*ssh.Client, string, error) {
	if !validServer(req.Host) {
		return nil, "", errors.New("请输入有效的服务器 IP 或域名")
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Port < 1 || req.Port > 65535 || strings.TrimSpace(req.User) == "" {
		return nil, "", errors.New("SSH 端口或用户名无效")
	}
	var methods []ssh.AuthMethod
	if req.Password != "" {
		methods = append(methods, ssh.Password(req.Password))
	}
	if req.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if req.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(req.PrivateKey), []byte(req.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(req.PrivateKey))
		}
		if err != nil {
			return nil, "", errors.New("SSH 私钥无法解析，请检查格式或解密口令")
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if len(methods) == 0 {
		return nil, "", errors.New("请填写 SSH 密码或私钥")
	}
	address := net.JoinHostPort(strings.Trim(req.Host, "[]"), fmt.Sprint(req.Port))
	var hostCallback ssh.HostKeyCallback
	if home, err := os.UserHomeDir(); err == nil {
		if cb, err := knownhosts.New(filepath.Join(home, ".ssh", "known_hosts")); err == nil {
			hostCallback = cb
		}
	}
	var trustErr *TrustError
	var fingerprint string
	config := &ssh.ClientConfig{User: req.User, Auth: methods, Timeout: 8 * time.Second}
	config.HostKeyCallback = func(host string, remote net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		if req.Fingerprint != "" {
			if subtle.ConstantTimeCompare([]byte(req.Fingerprint), []byte(fingerprint)) != 1 {
				return errors.New("SSH 主机指纹不匹配，连接已终止")
			}
			return nil
		}
		if hostCallback != nil {
			err := hostCallback(host, remote, key)
			if err == nil {
				return nil
			}
			var mismatch *knownhosts.KeyError
			if !errors.As(err, &mismatch) || len(mismatch.Want) > 0 {
				return errors.New("SSH 主机密钥与 known_hosts 不一致，请先核对服务器身份")
			}
		}
		trustErr = &TrustError{Fingerprint: fingerprint, Algorithm: key.Type()}
		return trustErr
	}
	conn, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", errors.New("无法连接 SSH，请检查 IP、端口和网络")
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		if trustErr != nil {
			return nil, "", trustErr
		}
		return nil, "", errors.New("SSH 连接或认证失败，请检查凭据与主机指纹")
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), fingerprint, nil
}

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("远程文件超过大小限制")
	}
	return b.Buffer.Write(p)
}

func remoteRead(client *ssh.Client, command string, maxBytes int) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	out := &cappedBuffer{max: maxBytes}
	stderr := &cappedBuffer{max: 4096}
	session.Stdout, session.Stderr = out, stderr
	if err := session.Run(command); err != nil {
		return nil, errors.New("远程文件不可读、超过限制或命令执行失败")
	}
	return out.Bytes(), nil
}

func Discover(ctx context.Context, req SSHRequest) (Discovery, error) {
	r := Discovery{Nodes: []Proxy{}, Files: []string{}, Warnings: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	client, fingerprint, err := connectSSH(ctx, req)
	if err != nil {
		return r, err
	}
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-done:
		}
	}()
	r.Fingerprint = fingerprint
	paths := append([]string{}, defaultPaths...)
	customPathCount := 0
	for _, path := range strings.Split(req.Paths, "\n") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		customPathCount++
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") || len(path) > 512 {
			return r, errors.New("自定义配置路径必须是合法绝对路径，每行一个")
		}
		paths = append(paths, path)
	}
	if customPathCount > 20 {
		return r, errors.New("自定义配置路径过多，最多 20 个")
	}
	var quoted []string
	for _, path := range paths {
		quoted = append(quoted, shellQuote(path))
	}
	command := "for p in " + strings.Join(quoted, " ") + "; do if test -f \"$p\"; then printf '%s\\n' \"$p\"; fi; done; "
	for _, dir := range defaultDirectories {
		command += "if test -d " + shellQuote(dir) + "; then find " + shellQuote(dir) + " -maxdepth 2 -type f \\( -name '*.json' -o -name '*.yaml' -o -name '*.yml' \\) -print 2>/dev/null; fi; "
	}
	command += "true"
	listing, err := remoteRead(client, command, 64<<10)
	if err != nil {
		return r, err
	}
	unique := map[string]bool{}
	for _, path := range strings.Split(string(listing), "\n") {
		path = strings.TrimSpace(path)
		if strings.HasPrefix(path, "/") && !strings.ContainsAny(path, "\x00\r\n") && len(path) <= 512 {
			unique[path] = true
		}
	}
	paths = nil
	for path := range unique {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) > 40 {
		paths = paths[:40]
		r.Warnings = append(r.Warnings, "发现文件超过 40 个，仅读取前 40 个；可通过自定义路径指定配置")
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			r.Warnings = append(r.Warnings, "读取超时，已保留当前识别结果")
			break
		}
		content, err := remoteRead(client, "cat -- "+shellQuote(path), 2<<20)
		if err != nil {
			r.Warnings = append(r.Warnings, path+"：无法读取，请检查当前 SSH 用户权限")
			continue
		}
		decoded := DecodeSource(content, path, strings.Trim(req.Host, "[]"), req.SNI, req.Insecure)
		r.Nodes = append(r.Nodes, decoded.Nodes...)
		r.Warnings = append(r.Warnings, decoded.Warnings...)
		if len(decoded.Nodes) > 0 {
			r.Files = append(r.Files, path)
		}
		if len(r.Nodes) > 500 {
			return r, errors.New("识别节点超过 500 个，请缩小配置路径范围")
		}
	}
	if len(r.Nodes) == 0 {
		r.Warnings = append(r.Warnings, "未识别到可导入节点。检查用户读取权限，或在高级选项填写实际配置路径；Docker 容器配置需填写宿主机挂载路径。")
	}
	return r, nil
}
