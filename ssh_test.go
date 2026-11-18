package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHTrustAuthenticationAndReadOnlyDiscovery(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var authentications atomic.Int32
	var commandsMu sync.Mutex
	var commands []string
	config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authentications.Add(1)
		if meta.User() != "root" || string(password) != "test-password" {
			return nil, errors.New("bad password")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				server, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for request := range requests {
							if request.Type != "exec" {
								_ = request.Reply(false, nil)
								continue
							}
							var payload struct{ Command string }
							if ssh.Unmarshal(request.Payload, &payload) != nil {
								_ = request.Reply(false, nil)
								continue
							}
							commandsMu.Lock()
							commands = append(commands, payload.Command)
							commandsMu.Unlock()
							_ = request.Reply(true, nil)
							status := uint32(0)
							if strings.HasPrefix(payload.Command, "for p in ") {
								_, _ = io.WriteString(channel, "/etc/xray/config.json\n/etc/tuic/config.json\n")
							} else if payload.Command == "cat -- '/etc/xray/config.json'" {
								_, _ = io.WriteString(channel, `{"inbounds":[{"protocol":"trojan","port":443,"settings":{"clients":[{"password":"node-password"}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"sni.example"}}}]}`)
							} else if payload.Command == "cat -- '/etc/tuic/config.json'" {
								_, _ = io.WriteString(channel, `{"server":"[::]:8443","users":{"uuid":"tuic-password"},"alpn":["h3"]}`)
							} else {
								status = 1
							}
							message := make([]byte, 4)
							binary.BigEndian.PutUint32(message, status)
							_, _ = channel.SendRequest("exit-status", false, message)
							return
						}
					}()
				}
			}()
		}
	}()
	defer func() { _ = listener.Close(); <-acceptDone; workers.Wait() }()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	req := SSHRequest{Host: host, Port: port, User: "root", Password: "test-password"}
	_, err = Discover(context.Background(), req)
	var trust *TrustError
	if !errors.As(err, &trust) || trust.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("unknown host did not require fingerprint confirmation")
	}
	if authentications.Load() != 0 {
		t.Fatal("credentials sent before host key was trusted")
	}
	req.Fingerprint = trust.Fingerprint
	result, err := Discover(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 2 || len(result.Files) != 2 || result.Nodes[0]["type"] != "tuic" || result.Nodes[1]["type"] != "trojan" {
		t.Fatalf("discovery did not read files: nodes=%d files=%d", len(result.Nodes), len(result.Files))
	}
	if authentications.Load() != 1 {
		t.Fatal("authentication missing")
	}
	commandsMu.Lock()
	for _, command := range commands {
		if !strings.HasPrefix(command, "for p in ") && !strings.HasPrefix(command, "cat -- '") {
			t.Error("unexpected remote command")
		}
		for _, bad := range []string{"sudo ", "systemctl ", "rm ", "curl ", "wget ", "install "} {
			if strings.Contains(command, bad) {
				t.Error("non-read-only command")
			}
		}
	}
	commandsMu.Unlock()
	req.Fingerprint = "SHA256:incorrect"
	if _, err := Discover(context.Background(), req); err == nil {
		t.Fatal("incorrect fingerprint accepted")
	}
}

func TestShellQuoteCannotEscapePath(t *testing.T) {
	if got := shellQuote("/opt/node's config.json"); got != "'/opt/node'\"'\"'s config.json'" {
		t.Fatalf("unsafe quote: %q", got)
	}
}
