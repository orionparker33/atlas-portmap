package gui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/output"
)

const host = "127.0.0.1:8765"

func testServer() *Server { return NewServer("test", []string{host, "localhost:8765"}) }

type call struct {
	method, path, body string
	hdr                map[string]string
	noToken            bool
	host               string
}

func do(t *testing.T, s *Server, c call) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	r := httptest.NewRequest(c.method, "http://"+host+c.path, body)
	r.Host = host
	if c.host != "" {
		r.Host = c.host
	}
	if !c.noToken {
		r.Header.Set(tokenHeader, s.Token())
	}
	if c.body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestStaticAndHeaders(t *testing.T) {
	s := testServer()
	w := do(t, s, call{method: "GET", path: "/", noToken: true})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `src="/js/app.js"`) {
		t.Fatalf("index: %d %s", w.Code, w.Body.String())
	}
	for k, want := range map[string]string{"Content-Security-Policy": "script-src 'self'", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if !strings.Contains(w.Header().Get(k), want) {
			t.Errorf("%s = %q", k, w.Header().Get(k))
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe") {
		t.Errorf("CSP allows unsafe sources: %s", csp)
	}
	w = do(t, s, call{method: "GET", path: "/js/app.js", noToken: true})
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("app.js: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestHostGuard(t *testing.T) {
	s := testServer()
	for _, h := range []string{"evil.example:8765", "127.0.0.1:9999", "attacker.test"} {
		for _, p := range []string{"/", "/api/meta"} {
			if w := do(t, s, call{method: "GET", path: p, host: h}); w.Code != http.StatusForbidden {
				t.Errorf("Host %s %s: %d", h, p, w.Code)
			}
		}
	}
	if w := do(t, s, call{method: "GET", path: "/api/meta", host: "LOCALHOST:8765"}); w.Code != 200 {
		t.Errorf("localhost (case-insensitive): %d", w.Code)
	}
}

func TestTokenAndRequestChecks(t *testing.T) {
	s := testServer()
	if w := do(t, s, call{method: "GET", path: "/api/meta", noToken: true}); w.Code != 401 {
		t.Errorf("no token: %d", w.Code)
	}
	if w := do(t, s, call{method: "GET", path: "/api/meta", noToken: true, hdr: map[string]string{tokenHeader: strings.Repeat("0", 64)}}); w.Code != 401 {
		t.Errorf("wrong token: %d", w.Code)
	}
	if w := do(t, s, call{method: "GET", path: "/api/meta"}); w.Code != 200 {
		t.Errorf("meta: %d", w.Code)
	}
	if w := do(t, s, call{method: "GET", path: "/api/meta", hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}}); w.Code != 403 {
		t.Errorf("cross-site fetch: %d", w.Code)
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{}`, hdr: map[string]string{"Origin": "http://evil.example"}}); w.Code != 403 {
		t.Errorf("foreign origin: %d", w.Code)
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{}`, hdr: map[string]string{"Content-Type": "text/plain"}}); w.Code != 415 {
		t.Errorf("text/plain body: %d", w.Code)
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{"switches":"","bogus":1}`, hdr: map[string]string{"Origin": "http://" + host}}); w.Code != 400 || !strings.Contains(w.Body.String(), "bogus") {
		t.Errorf("unknown field: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{"snmp":{"version":"2c"}}`}); w.Code != 400 || !strings.Contains(w.Body.String(), "at least one switch") {
		t.Errorf("no switches: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{"switches":"10.0.0.1","snmp":{"version":"3"}}`}); w.Code != 400 || !strings.Contains(w.Body.String(), "user") {
		t.Errorf("v3 without user: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: `{"switches":"10.0.0.1","snmp":{"version":"2c","timeout_ms":5}}`}); w.Code != 400 {
		t.Errorf("timeout bound: %d", w.Code)
	}
}

func TestMetaNeverLeaksSecrets(t *testing.T) {
	t.Setenv("PORTMAP_COMMUNITY", "s3cret-community")
	t.Setenv("PORTMAP_V3_AUTH_PASS", "s3cret-auth-pass")
	w := do(t, testServer(), call{method: "GET", path: "/api/meta"})
	b := w.Body.String()
	if strings.Contains(b, "s3cret") {
		t.Fatalf("meta leaked a secret: %s", b)
	}
	var m struct{ Env map[string]bool }
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || !m.Env["community"] || !m.Env["v3_auth_pass"] || m.Env["v3_priv_pass"] {
		t.Errorf("env flags: %+v %v", m, err)
	}
}

func sampleReport(label string) string {
	b, _ := json.Marshal(output.Report{Tool: "atlas-portmap", Version: "test", Label: label, Generated: "2026-10-27T03:30:00Z",
		Switches: []output.SwitchSummary{{Target: "10.0.0.2", Name: "core"}}})
	return string(b)
}

func TestReportLifecycle(t *testing.T) {
	s := testServer()
	if w := do(t, s, call{method: "POST", path: "/api/reports?name=x.json", body: `{"entries":[]}`}); w.Code != 400 {
		t.Errorf("foreign JSON accepted: %d", w.Code)
	}
	w := do(t, s, call{method: "POST", path: "/api/reports?name=site-a.json", body: sampleReport("../../Contoso HQ\x1b[2J")})
	if w.Code != 201 {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	var v jobView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.Report == nil || v.Source != "file" || strings.ContainsRune(v.Label, 0x1b) {
		t.Errorf("imported view: %+v", v)
	}
	w = do(t, s, call{method: "GET", path: "/api/scans"})
	var list []jobView
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Report != nil {
		t.Errorf("list (summaries only): %v %s", err, w.Body.String())
	}
	w = do(t, s, call{method: "GET", path: "/api/scans/" + v.ID + "/export?format=csv"})
	cd := w.Header().Get("Content-Disposition")
	if w.Code != 200 || !strings.Contains(cd, "Contoso-HQ-2J-20261027-0330.csv") || strings.Contains(cd, "/") {
		t.Errorf("export: %d %q", w.Code, cd)
	}
	if w := do(t, s, call{method: "GET", path: "/api/scans/" + v.ID + "/export?format=xml"}); w.Code != 400 {
		t.Errorf("bad format: %d", w.Code)
	}
	if w := do(t, s, call{method: "DELETE", path: "/api/scans/" + v.ID}); w.Code != 204 {
		t.Errorf("delete: %d", w.Code)
	}
	if w := do(t, s, call{method: "GET", path: "/api/scans/" + v.ID}); w.Code != 404 {
		t.Errorf("after delete: %d", w.Code)
	}
}

func TestJobEviction(t *testing.T) {
	s := testServer()
	for i := 0; i < maxJobs+7; i++ {
		do(t, s, call{method: "POST", path: "/api/reports", body: sampleReport(fmt.Sprintf("r%d", i))})
	}
	var list []jobView
	_ = json.Unmarshal(do(t, s, call{method: "GET", path: "/api/scans"}).Body.Bytes(), &list)
	if len(list) != maxJobs || list[0].Label != fmt.Sprintf("r%d", maxJobs+6) {
		t.Errorf("eviction: %d jobs, newest %q", len(list), list[0].Label)
	}
}

func wait(t *testing.T, s *Server, id string, until func(jobView) bool) jobView {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var v jobView
		_ = json.Unmarshal(do(t, s, call{method: "GET", path: "/api/scans/" + id}).Body.Bytes(), &v)
		if until(v) {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting; last %+v", v)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestScanFailsCleanlyAndRejectsConcurrentScans(t *testing.T) {
	s := testServer()
	body := fmt.Sprintf(`{"label":"dead","switches":%q,"snmp":{"version":"2c","community":"x","timeout_ms":1500,"retries":0},"options":{"arp_from_switches":true}}`, silentPort(t))
	w := do(t, s, call{method: "POST", path: "/api/scans", body: body})
	if w.Code != 202 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	var v jobView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.Total != 2 || len(v.Tasks) != 2 || v.Tasks[0].Role != "switch" || v.Tasks[1].Role != "arp" {
		t.Errorf("plan: %+v", v)
	}
	if w := do(t, s, call{method: "POST", path: "/api/scans", body: body}); w.Code != 409 {
		t.Errorf("second scan while running: %d", w.Code)
	}
	if w := do(t, s, call{method: "DELETE", path: "/api/scans/" + v.ID}); w.Code != 409 {
		t.Errorf("delete while running: %d", w.Code)
	}
	v = wait(t, s, v.ID, func(v jobView) bool { return v.State != "running" })
	if v.State != "failed" || v.Report == nil || v.Report.Switches[0].Error == "" || v.Tasks[1].State != "skipped" {
		t.Errorf("finished: state %s tasks %+v", v.State, v.Tasks)
	}
	if strings.Contains(fmt.Sprint(v), `"x"`) {
		t.Error("community echoed")
	}
}

func TestCancel(t *testing.T) {
	s := testServer()
	body := fmt.Sprintf(`{"switches":%q,"snmp":{"version":"2c","community":"x","timeout_ms":5000,"retries":1}}`, silentPort(t))
	var v jobView
	_ = json.Unmarshal(do(t, s, call{method: "POST", path: "/api/scans", body: body}).Body.Bytes(), &v)
	if w := do(t, s, call{method: "POST", path: "/api/scans/" + v.ID + "/cancel"}); w.Code != 200 {
		t.Fatalf("cancel: %d", w.Code)
	}
	v = wait(t, s, v.ID, func(v jobView) bool { return v.State != "running" })
	if v.State != "cancelled" {
		t.Errorf("state %s", v.State)
	}
}

func TestQuit(t *testing.T) {
	s := testServer()
	var stopped atomic.Bool
	s.stop = func() { stopped.Store(true) }
	if w := do(t, s, call{method: "POST", path: "/api/quit"}); w.Code != 200 {
		t.Fatalf("quit: %d", w.Code)
	}
	time.Sleep(400 * time.Millisecond)
	if !stopped.Load() {
		t.Error("quit did not stop the server")
	}
}

func TestHelpers(t *testing.T) {
	if got := exportName("../../etc/passwd", "2026-10-27T03:30:00Z", "csv"); got != "etc-passwd-20261027-0330.csv" {
		t.Errorf("exportName = %s", got)
	}
	if got := exportName("", "bad", "json"); !strings.HasPrefix(got, "portmap-") {
		t.Errorf("exportName empty = %s", got)
	}
	if got := cleanLabel("  Site\x00A\x1b\u009b " + strings.Repeat("x", 200)); strings.ContainsAny(got, "\x00\x1b\u009b") || len([]rune(got)) > 120 {
		t.Errorf("cleanLabel = %q", got)
	}
	if !bytes.Contains([]byte(csp), []byte("frame-ancestors 'none'")) {
		t.Error("csp")
	}
}

// silentPort is a UDP port that receives and never answers, so SNMP requests to it time out.
func silentPort(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestConcurrentStartsRunOneScan(t *testing.T) {
	s := testServer()
	body := fmt.Sprintf(`{"switches":%q,"snmp":{"version":"2c","community":"x","timeout_ms":3000}}`, silentPort(t))
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if do(t, s, call{method: "POST", path: "/api/scans", body: body}).Code == 202 {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Errorf("%d scans started", accepted.Load())
	}
	s.cancelAll()
}

func TestEvictionPrefersSavedReports(t *testing.T) {
	s := testServer()
	scan := &job{id: "scan-1", source: "scan", state: "done", started: time.Now()}
	s.add(scan)
	for i := 0; i < maxJobs; i++ {
		do(t, s, call{method: "POST", path: "/api/reports", body: sampleReport(fmt.Sprintf("r%d", i))})
	}
	if s.get("scan-1") == nil {
		t.Error("unsaved scan evicted before saved reports")
	}
}

func TestServeOnOtherLoopbackPrintsReachableURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &lockedBuffer{}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, Options{Addr: "127.0.0.2:0", Stdout: out, Stderr: io.Discard}) }()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(out.String(), "#token=") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "http://127.0.0.2:") {
		t.Errorf("printed %q", out.String())
	}
	cancel()
	<-done
	if err := Serve(context.Background(), Options{Addr: "0.0.0.0:0", Stdout: io.Discard, Stderr: io.Discard}); err == nil || !strings.Contains(err.Error(), "not a loopback") {
		t.Errorf("wildcard bind without -allow-remote: %v", err)
	}
}

// lockedBuffer is a bytes.Buffer safe for one writer goroutine and one reader goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
