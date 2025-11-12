package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	proxyAddr = "127.0.0.1:8888"
	uiAddr = "127.0.0.1:8081"
	caCertPath = "ca.pem"
	caKeyPath = "ca.key"
	crlPath = "ca.crl"
	logBodyLimit = 64 * 1024
	maxEntries = 1000
	readTimeout = 15 * time.Second
	writeTimeout = 30 * time.Second
	idleTimeout = 60 * time.Second
)

type LogEntry struct {
	ID int64 `json:"id"`
	StartedAt time.Time `json:"startedAt"`
	DurationMs int64 `json:"durationMs"`
	ClientIP string `json:"clientIp"`
	Method string `json:"method"`
	URL string `json:"url"`
	Status int `json:"status"`
	ReqHeaders map[string]string `json:"reqHeaders"`
	RespHeaders map[string]string `json:"respHeaders"`
	ReqBody string `json:"reqBody"`
	RespBody string `json:"respBody"`
	Truncated bool `json:"truncated"`
}

type Ring struct {
	mu sync.RWMutex
	data []LogEntry
	nextID int64
}

func NewRing() *Ring { return &Ring{data: make([]LogEntry, 0, maxEntries)} }

func (r *Ring) add(e LogEntry) LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.ID = r.nextID
	r.nextID++
	if len(r.data) == maxEntries {
		copy(r.data[0:], r.data[1:])
		r.data[len(r.data)-1] = e
	} else {
		r.data = append(r.data, e)
	}
	return e
}

func (r *Ring) all() []LogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]LogEntry, len(r.data))
	copy(out, r.data)
	return out
}

func (r *Ring) get(id int64) (LogEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, it := range r.data {
		if it.ID == id {
			return it, true
		}
	}
	return LogEntry{}, false
}

var store = NewRing()

var (
	caCert *x509.Certificate
	caKey *rsa.PrivateKey
)

func loadOrCreateCA() error {
	if _, err := os.Stat(caCertPath); err == nil {
		certPEM, _ := os.ReadFile(caCertPath)
		keyPEM, _ := os.ReadFile(caKeyPath)
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" { return fmt.Errorf("bad ca cert") }
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil { return err }
		kb, _ := pem.Decode(keyPEM)
		if kb == nil || kb.Type != "RSA PRIVATE KEY" { return fmt.Errorf("bad ca key") }
		k, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil { return err }
		caCert, caKey = c, k
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return err }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: "myproxy CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(5, 0, 0),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{"http://" + uiAddr + "/ca.crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil { return err }
	if err := os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); 
  err != nil { 
    return err 
  }

	if err := os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); 
  err != nil { 
    return err 
  }

	caCert, _ = x509.ParseCertificate(der)
	caKey = key
	return nil
}

func writeEmptyCRL() error {
  rl := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: []pkix.RevokedCertificate{},
		Number: big.NewInt(time.Now().Unix()),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().AddDate(0, 1, 0),
		Issuer: caCert.Subject,
	}
	
  der, err := x509.CreateRevocationList(rand.Reader, rl, caCert, caKey)
	if err != nil { 
    return err 
  }

	return os.WriteFile(crlPath, der, 0644)
}

func certForHost(host string) (tls.Certificate, error) {
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return tls.Certificate{}, err }
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{CommonName: host},
		DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil { 
    return tls.Certificate{}, err 
  }
	
  certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

var sensitiveHeader = map[string]struct{}{
	"authorization": {},
	"cookie": {},
	"set-cookie": {},
}

var bodyFieldMasks = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(password|passwd|senha|token|secret|api_key|cpf|cnpj)"\s*:\s*"(.*?)"`),
}

func maskHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		val := strings.Join(v, "; ")
		if _, ok := sensitiveHeader[lk]; ok {
			out[k] = "***"
		} else {
			out[k] = val
		}
	}
	return out
}

func isTextual(ct string) bool {
	if ct == "" { return true }
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "text") || strings.Contains(ct, "form") || strings.Contains(ct, "javascript")
}

func maskBody(ct string, b []byte) (string, bool) {
	trunc := false
	if len(b) > logBodyLimit {
		b = b[:logBodyLimit]
		trunc = true
	}
	if !isTextual(ct) { 
    return fmt.Sprintf("(%d [BYTES])", len(b)), trunc 
  }

	s := string(b)
	for _, rx := range bodyFieldMasks { s = rx.ReplaceAllString(s, `"$1":"***"`) }
	return s, trunc
}

func fullURLFromReq(r *http.Request) string {
	if r.URL.IsAbs() { return r.URL.String() }
	scheme := "http"
	if r.TLS != nil { scheme = "https" }
	return (&url.URL{ Scheme: scheme, Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery }).String()
}

var upstreamTransport = &http.Transport{
	Proxy: nil,
	TLSClientConfig: &tls.Config{ MinVersion: tls.VersionTLS12 },
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Connection")
	start := time.Now()
	var reqPeek []byte
	var reqCT string
	if r.Body != nil {
		reqCT = r.Header.Get("Content-Type")
		buf, _ := io.ReadAll(io.LimitReader(r.Body, logBodyLimit))
		reqPeek = buf
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
	}

	r.RequestURI = ""
  resp, err := upstreamTransport.RoundTrip(r)
	if err != nil { 
    http.Error(w, err.Error(), 502);
    return 
  }
	
  defer resp.Body.Close()
	for k, vv := range resp.Header { for _, v := range vv { w.Header().Add(k, v) }}
	
  w.WriteHeader(resp.StatusCode)
	var respPeek []byte
	var buf bytes.Buffer
	tee := io.TeeReader(resp.Body, &buf)
	tmp, _ := io.ReadAll(io.LimitReader(tee, logBodyLimit))
	
  respPeek = tmp
	w.Write(respPeek)
	io.Copy(w, &buf)
	reqBodyS, reqTrunc := maskBody(reqCT, reqPeek)
	respBodyS, respTrunc := maskBody(resp.Header.Get("Content-Type"), respPeek)
	
  entry := LogEntry{
		StartedAt: start,
		DurationMs: time.Since(start).Milliseconds(),
		ClientIP: clientIPFromReq(r),
		Method: r.Method,
		URL: fullURLFromReq(r),
		Status: resp.StatusCode,
		ReqHeaders: maskHeaders(r.Header),
		RespHeaders: maskHeaders(resp.Header),
		ReqBody: reqBodyS,
		RespBody: respBodyS,
		Truncated: reqTrunc || respTrunc,
	}
	entry = store.add(entry)
	publishSSE(entry)
}

var mitmBypass = map[string]struct{}{}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker); if !ok { http.Error(w, "no hijack", 500); return }
	clientConn, _, err := hj.Hijack()
	
  if err != nil { 
    return 
  }
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	host := r.Host
	serverName := strings.Split(host, ":")[0]
	
  if _, skip := mitmBypass[strings.ToLower(serverName)]; skip {
		up, err := net.Dial("tcp", host)
		if err != nil { clientConn.Close(); return }
		go io.Copy(up, clientConn)
		io.Copy(clientConn, up)
		up.Close()
		return
	}

	leaf, err:= certForHost(serverName)
	
  if err != nil { 
    clientConn.Close();
    return 
  }

	tlsSrv := tls.Server(clientConn, &tls.Config{ Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"} })
	
  if err := tlsSrv.Handshake(); 
  err != nil { 
    tlsSrv.Close();
    return 
  }

	up, err := tls.Dial("tcp", host, &tls.Config{ ServerName: serverName, MinVersion: tls.VersionTLS12 })
	
  if err != nil { 
    tlsSrv.Close();
    return 
  }
	
  defer tlsSrv.Close(); 
  defer up.Close()
	
  cr := bufio.NewReader(tlsSrv)
	cw := bufio.NewWriter(tlsSrv)
	
  for {
		req, err := http.ReadRequest(cr)
		if err != nil { 
      return 
    }
		
    start := time.Now()
		
    absForLog := *req.URL
		if !absForLog.IsAbs() { 
      absForLog.Scheme = "https"; 
      absForLog.Host = host 
    }
		
    var reqPeek []byte
		var reqCT string
		
    if req.Body != nil {
			reqCT = req.Header.Get("Content-Type")
			buf, _ := io.ReadAll(io.LimitReader(req.Body, logBodyLimit))
			reqPeek = buf
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), req.Body))
		}

		req.Header.Del("Proxy-Connection");
    req.Header.Del("Connection"); 
    req.Header.Del("Keep-Alive"); 
    req.Header.Del("TE"); 
    req.Header.Del("Trailer"); 
    req.Header.Del("Upgrade"); 
    req.Header.Del("Proxy-Authenticate"); 
    req.Header.Del("Proxy-Authorization");

		req.RequestURI = ""; 
    req.URL.Scheme = ""; 
    req.URL.Host = ""
		
    if err := req.Write(up); err != nil { return }
		ur := bufio.NewReader(up)
		
    resp, err := http.ReadResponse(ur, req)
		
    if err != nil { 
      return 
    }


		var respPeek []byte
		var tmp bytes.Buffer
		
    tee := io.TeeReader(resp.Body, &tmp)
		rb, _ := io.ReadAll(io.LimitReader(tee, logBodyLimit))
		
    respPeek = rb
    resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(respPeek), &tmp))
		
    if err := resp.Write(cw);
    err != nil { 
      return 
    }
		
    cw.Flush()
		
    reqBodyS, reqTrunc := maskBody(reqCT, reqPeek)
		respBodyS, respTrunc := maskBody(resp.Header.Get("Content-Type"), respPeek)
		
    entry := LogEntry{
			StartedAt: start,
			DurationMs: time.Since(start).Milliseconds(),
			ClientIP: clientIPFromReq(req),
			Method: req.Method,
			URL: absForLog.String(),
			Status: resp.StatusCode,
			ReqHeaders: maskHeaders(req.Header),
			RespHeaders: maskHeaders(resp.Header),
			ReqBody: reqBodyS,
			RespBody: respBodyS,
			Truncated: reqTrunc || respTrunc,
		}
		entry = store.add(entry)
		publishSSE(entry)
	}
}

func clientIPFromReq(r *http.Request) string {
	if r == nil { return "" }
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil { return host }
	return r.RemoteAddr
}

type subscriber struct { ch chan string; done chan struct{} }

var (
	subsMu sync.Mutex
	subs = map[int]*subscriber{}
	nextSubID = 0
)

func publishSSE(entry LogEntry) {
	b, _ := json.Marshal(entry)
	ev := "data: " + string(b) + "\n\n"
	subsMu.Lock(); defer subsMu.Unlock()
	for id, s := range subs {
		select { case s.ch <- ev: default: close(s.done); delete(subs, id) }
	}
}

func sseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
  flusher, ok := w.(http.Flusher); if !ok { http.Error(w, "no flusher", 500); return }
	s := &subscriber{ch: make(chan string, 256), done: make(chan struct{})}
	
  subsMu.Lock(); id := nextSubID; nextSubID++; subs[id] = s; subsMu.Unlock()
	io.WriteString(w, ":ok\n\n"); flusher.Flush()
	
  notify := r.Context().Done()
	
  for {
		select {
		  case <-notify: subsMu.Lock(); delete(subs, id); subsMu.Unlock(); return
		  case msg := <-s.ch: io.WriteString(w, msg); flusher.Flush()
		  case <-s.done: return
		}
	}
}

func apiList(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	limitParam := r.URL.Query().Get("limit")
	limit:= 200
	
  if limitParam != "" {
		if n, err := strconv.Atoi(limitParam); err == nil && n > 0 && n <= 1000 { limit = n }
	}
	
  all := store.all()
	out := make([]LogEntry, 0, len(all))
	
  for i := len(all)-1; i >= 0; i-- {
		e := all[i]
		if q == "" || strings.Contains(strings.ToLower(e.URL), q) || strings.Contains(strings.ToLower(e.Method), q) || strings.Contains(strings.ToLower(e.ClientIP), q) {
			out = append(out, e)
			if len(out) >= limit { break }
		}
	}

	writeJSON(w, out)
}

func apiGet(w http.ResponseWriter, r *http.Request) {
	idStr:= strings.TrimPrefix(r.URL.Path, "/api/requests/")
	var id int64
	
  fmt.Sscanf(idStr, "%d", &id)
	e, ok:= store.get(id)
	
  if !ok { 
    http.NotFound(w, r); 
    return
  }
	
  writeJSON(w, e)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc:= json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func uiHandler(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join("ui", "index.html")
	http.ServeFile(w, r, p)
}

func health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "ok\n")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := loadOrCreateCA(); err != nil { log.Fatal(err) }
	_ = writeEmptyCRL()
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect { handleConnect(w, r); return }
		handleHTTP(w, r)
	})
	proxySrv := &http.Server{ Addr: proxyAddr, Handler: proxyHandler, ReadHeaderTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout }
	
  uiMux := http.NewServeMux()
	uiMux.HandleFunc("/", uiHandler)
	uiMux.HandleFunc("/api/requests", apiList)
	uiMux.HandleFunc("/api/requests/", apiGet)
	uiMux.HandleFunc("/api/stream", sseHandler)
	uiMux.HandleFunc("/health", health)
	
  uiMux.HandleFunc("/ca.crl", func(w http.ResponseWriter, r *http.Request) { 
    w.Header().Set("Content-Type", "application/pkix-crl"); 
    http.ServeFile(w, r, crlPath) 
  })
	
  uiSrv := &http.Server{ Addr: uiAddr, Handler: cors(uiMux), ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout }
	go func(){ if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Fatal(err) } }()
	if err := uiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Fatal(err) }
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions { w.WriteHeader(http.StatusNoContent); return }
		next.ServeHTTP(w, r)
	})
}

func esc(s string) string { 
  return html.EscapeString(s) 
}
