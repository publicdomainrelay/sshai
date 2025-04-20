// AGI_SOCK=/tmp/agi.sock go run agi_sshd.go
//
//	ssh -NnT -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no \
//	  -R /tmux.sock:$(echo $TMUX | sed -e 's/,.*//g') \
//	  -R /input.sock:$(mktemp -d)/input.sock user@localhost
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// forward represents a single remote->local UNIX socket forward
// stored in a temporary directory on the server.
type forward struct {
	listener  net.Listener
	localPath string
	rawPath   string
}

func main() {
	log.Println("▶️ Starting SSH-forward server")

	signer, err := loadOrGenerateHostKey("host_key")
	if err != nil {
		log.Fatalf("❌ host key load/generate failed: %v", err)
	}

	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("❌ listen tcp: %v", err)
	}
	log.Println("✅ SSH listening on :2222")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("⚠️ accept error: %v", err)
			continue
		}
		go handleSSH(conn, cfg)
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	log.Printf("ℹ️ host_key not found — generating ephemeral RSA key")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	return ssh.ParsePrivateKey(privPEM)
}

func handleSSH(raw net.Conn, cfg *ssh.ServerConfig) {
	defer raw.Close()
	log.Printf("🔌 New raw connection from %s", raw.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		log.Printf("❌ SSH handshake failed: %v", err)
		cancel()
		return
	}
	log.Printf("✅ SSH handshake OK — user=%s", serverConn.User())
	go func() { serverConn.Wait(); cancel() }()

	go func() {
		for ch := range chans {
			log.Printf("❌ rejecting channel type=%s", ch.ChannelType())
			ch.Reject(ssh.UnknownChannelType, "not supported")
		}
	}()

	tmpDir, err := os.MkdirTemp("", "ssh-fwd-*")
	if err != nil {
		log.Printf("❌ temp dir creation failed: %v", err)
		return
	}
	log.Printf("📂 using temp dir %s", tmpDir)
	defer os.RemoveAll(tmpDir)

	forwards := make(map[string]*forward)
	var mu sync.Mutex
	notified := false

	for req := range reqs {
		switch req.Type {
		case "streamlocal-forward@openssh.com":
			var p struct{ SocketPath string }
			_ = ssh.Unmarshal(req.Payload, &p)
			base := filepath.Base(p.SocketPath)
			localPath := filepath.Join(tmpDir, base)
			log.Printf("📨 forward request: remote=%s → local=%s", p.SocketPath, localPath)

			listener, err := net.Listen("unix", localPath)
			if err != nil {
				log.Printf("❌ failed to listen on %s: %v", localPath, err)
				req.Reply(false, nil)
				continue
			}

			mu.Lock()
			forwards[base] = &forward{listener, localPath, p.SocketPath}
			count := len(forwards)
			mu.Unlock()

			req.Reply(true, nil)
			go acceptLoop(ctx, listener, serverConn, p.SocketPath)

			if !notified && count >= 5 {
				notified = true
				go notifyAGI(ctx, &mu, forwards)
			}

		case "cancel-streamlocal-forward@openssh.com":
			var p struct{ SocketPath string }
			_ = ssh.Unmarshal(req.Payload, &p)
			base := filepath.Base(p.SocketPath)
			log.Printf("📨 cancel-forward request: %s", p.SocketPath)

			mu.Lock()
			if f, ok := forwards[base]; ok {
				f.listener.Close()
				delete(forwards, base)
				log.Printf("🗑 removed forward %s", base)
			}
			mu.Unlock()
			req.Reply(true, nil)

		default:
			log.Printf("❓ unknown request: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	<-ctx.Done()
	log.Println("🔒 SSH session closed, cleaning up")
}

func acceptLoop(ctx context.Context, listener net.Listener, sc *ssh.ServerConn, remotePath string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ℹ️ listener closed for %s", remotePath)
			return
		}
		log.Printf("🔗 incoming connection on %s", listener.Addr())
		go handleConn(ctx, conn, sc, remotePath)
	}
}

func handleConn(ctx context.Context, conn net.Conn, sc *ssh.ServerConn, remotePath string) {
	defer conn.Close()
	log.Printf("↔ proxying data for %s", remotePath)

	payload := ssh.Marshal(struct {
		SocketPath string
		Reserved   uint32
	}{remotePath, 0})
	channel, reqs, err := sc.OpenChannel("forwarded-streamlocal@openssh.com", payload)
	if err != nil {
		log.Printf("❌ OpenChannel failed %s: %v", remotePath, err)
		return
	}
	go ssh.DiscardRequests(reqs)

	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
	}()
	io.Copy(conn, channel)
	channel.Close()
	log.Printf("✅ closed proxy for %s", remotePath)
}

func notifyAGI(ctx context.Context, mu *sync.Mutex, forwards map[string]*forward) {
	agi := os.Getenv("AGI_SOCK")
	if agi == "" {
		return
	}

	mu.Lock()
	data := make(map[string]string, len(forwards))
	for base, f := range forwards {
		data[base] = f.localPath
		if strings.HasSuffix(f.rawPath, "input.sock") {
			data["client-side-input.sock"] = f.rawPath
		}
		if strings.HasSuffix(f.rawPath, "text-output.sock") {
			data["client-side-text-output.sock"] = f.rawPath
		}
		if strings.HasSuffix(f.rawPath, "ndjson-output.sock") {
			data["client-side-ndjson-output.sock"] = f.rawPath
		}
		if strings.HasSuffix(f.rawPath, "mcp-reverse-proxy.sock") {
			data["client-side-mcp-reverse-proxy.sock"] = f.rawPath
		}
	}
	mu.Unlock()

	body, _ := json.Marshal(data)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", agi)
			},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://unix/connect/tmux", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ AGI POST error: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("✅ AGI POST success: %d forwards sent: %v", len(data), data)
}
