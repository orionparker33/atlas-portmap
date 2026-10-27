// Package gui serves the atlas-portmap web interface on a loopback address: a single-page app
// embedded in the binary (no external assets, so it works offline at a client site) and a small
// JSON API that drives the same engine as the CLI.
//
// Security model: the listener is loopback by default; every API call must carry the per-launch
// session token in the X-Portmap-Token header (a custom header, so browsers will not send it
// cross-origin without a preflight this server never grants); the Host header must name the
// listener (DNS-rebinding defence); writes also check Origin and Sec-Fetch-Site and require JSON.
// SNMP credentials live only in memory for the duration of a scan and are never returned.
package gui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/engine"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

//go:embed web
var webFS embed.FS

// Preload is a report to show at start (gui -open).
type Preload struct {
	Name   string
	Report *output.Report
}

// Options configures Serve.
type Options struct {
	Addr        string // listen address; default 127.0.0.1:0 (random port)
	AllowRemote bool   // permit a non-loopback address (plain HTTP: token and credentials unencrypted)
	Version     string
	OpenBrowser bool
	Preload     []Preload
	Stdout      io.Writer
	Stderr      io.Writer
}

const (
	maxJobs     = 100
	maxBody     = 32 << 20
	tokenHeader = "X-Portmap-Token"
)

// Server is the HTTP application. Use Serve, or NewServer + Handler in tests.
type Server struct {
	token   string
	version string
	hosts   map[string]bool // acceptable Host header values
	stop    func()

	mu    sync.Mutex
	jobs  map[string]*job
	order []string // oldest first
}

// NewServer prepares a server that accepts the given Host header values.
func NewServer(version string, hosts []string) *Server {
	s := &Server{token: randomHex(32), version: version, hosts: map[string]bool{}, jobs: map[string]*job{}, stop: func() {}}
	for _, h := range hosts {
		s.hosts[strings.ToLower(h)] = true
	}
	return s
}

// Token is the session token clients must present.
func (s *Server) Token() string { return s.token }

// Serve runs the GUI until ctx is cancelled or the user quits from the browser.
func Serve(ctx context.Context, opt Options) error {
	if opt.Addr == "" {
		opt.Addr = "127.0.0.1:0"
	}
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return err
	}
	addr := ln.Addr().(*net.TCPAddr)
	port := strconv.Itoa(addr.Port)
	hosts := []string{"127.0.0.1:" + port, "localhost:" + port, "[::1]:" + port}
	urlHost := "127.0.0.1:" + port
	switch {
	case addr.IP.IsLoopback():
		urlHost = net.JoinHostPort(addr.IP.String(), port) // 127.0.0.2, ::1, …
		hosts = append(hosts, urlHost)
	case !opt.AllowRemote:
		ln.Close()
		return fmt.Errorf("%s is not a loopback address: the GUI speaks plain HTTP, so the session token and any credentials typed in would cross the network unencrypted; reach it over SSH instead (ssh -L 8765:127.0.0.1:8765 host, then gui -addr 127.0.0.1:8765), or pass -allow-remote to accept that", ln.Addr())
	case addr.IP.IsUnspecified():
		if ifAddrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range ifAddrs {
				if ipn, ok := a.(*net.IPNet); ok {
					hosts = append(hosts, net.JoinHostPort(ipn.IP.String(), port))
				}
			}
		}
		fmt.Fprintf(opt.Stderr, "warning: listening on every interface over plain HTTP: the session token and any credentials typed into the form travel unencrypted\n")
	default:
		urlHost = net.JoinHostPort(addr.IP.String(), port)
		hosts = append(hosts, urlHost)
		fmt.Fprintf(opt.Stderr, "warning: listening on %s over plain HTTP: the session token and any credentials typed into the form travel unencrypted\n", urlHost)
	}
	s := NewServer(opt.Version, hosts)
	for _, p := range opt.Preload {
		s.addReport(p.Report, p.Name)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.stop = cancel
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	url := fmt.Sprintf("http://%s/#token=%s", urlHost, s.token)
	fmt.Fprintf(opt.Stdout, "atlas-portmap GUI: %s\n", url)
	fmt.Fprintln(opt.Stdout, "Keep this window open while you work; press Ctrl-C (or Quit in the GUI) to stop.")
	if opt.OpenBrowser {
		if cleanup, err := openBrowser(url); err != nil {
			fmt.Fprintf(opt.Stderr, "could not open a browser (%v); open the URL above yourself\n", err)
		} else {
			defer cleanup()
		}
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	s.cancelAll()
	shut, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	_ = srv.Shutdown(shut)
	return nil
}

// Handler is the full HTTP handler (static app + API) behind the host guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/meta", s.api(s.meta))
	mux.HandleFunc("GET /api/scans", s.api(s.listScans))
	mux.HandleFunc("POST /api/scans", s.api(s.startScan))
	mux.HandleFunc("GET /api/scans/{id}", s.api(s.getScan))
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.api(s.cancelScan))
	mux.HandleFunc("DELETE /api/scans/{id}", s.api(s.deleteScan))
	mux.HandleFunc("GET /api/scans/{id}/export", s.api(s.export))
	mux.HandleFunc("POST /api/reports", s.api(s.importReport))
	mux.HandleFunc("POST /api/quit", s.api(s.quit))
	return s.guard(mux)
}

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !s.hosts[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden: unexpected Host header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) api(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(tokenHeader)), []byte(s.token)) != 1 {
			jsonError(w, http.StatusUnauthorized, "missing or wrong session token: open the link printed by 'atlas-portmap gui'")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			jsonError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && !s.originOK(o) {
				jsonError(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			if r.ContentLength != 0 {
				if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
					jsonError(w, http.StatusUnsupportedMediaType, "requests must be application/json")
					return
				}
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		fn(w, r)
	}
}

func (s *Server) originOK(origin string) bool {
	for _, scheme := range []string{"http://"} {
		if strings.HasPrefix(origin, scheme) && s.hosts[strings.ToLower(strings.TrimPrefix(origin, scheme))] {
			return true
		}
	}
	return false
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	env := func(k string) bool { return os.Getenv(k) != "" }
	writeJSON(w, http.StatusOK, map[string]any{
		"version":  s.version,
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
		"env": map[string]bool{
			"community": env("PORTMAP_COMMUNITY"), "v3_user": env("PORTMAP_V3_USER"),
			"v3_auth_pass": env("PORTMAP_V3_AUTH_PASS"), "v3_priv_pass": env("PORTMAP_V3_PRIV_PASS"),
		},
	})
}

// ---- jobs ----

type job struct {
	mu       sync.Mutex
	id       string
	label    string
	source   string // scan or file
	state    string // running, done, failed, cancelled
	started  time.Time
	finished time.Time
	tasks    []engine.Event
	report   *output.Report
	err      string
	cancel   context.CancelFunc
}

type jobView struct {
	ID       string         `json:"id"`
	Label    string         `json:"label,omitempty"`
	Source   string         `json:"source"`
	State    string         `json:"state"`
	Started  string         `json:"started"`
	Finished string         `json:"finished,omitempty"`
	Done     int            `json:"done"`
	Total    int            `json:"total"`
	Switches int            `json:"switches"`
	Entries  int            `json:"entries"`
	Error    string         `json:"error,omitempty"`
	Tasks    []engine.Event `json:"tasks,omitempty"`
	Report   *output.Report `json:"report,omitempty"`
}

func (j *job) update(e engine.Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e.ID >= 0 && e.ID < len(j.tasks) {
		j.tasks[e.ID] = e
	}
}

func (j *job) view(detail bool) jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := jobView{ID: j.id, Label: j.label, Source: j.source, State: j.state, Started: j.started.UTC().Format(time.RFC3339), Total: len(j.tasks), Error: j.err}
	if !j.finished.IsZero() {
		v.Finished = j.finished.UTC().Format(time.RFC3339)
	}
	for _, t := range j.tasks {
		switch t.State {
		case engine.StateDone, engine.StateFailed, engine.StateSkipped:
			v.Done++
		}
	}
	if j.report != nil {
		v.Switches = len(j.report.Switches)
		for _, e := range j.report.Entries {
			if e.MAC != "" && !e.Secondary {
				v.Entries++
			}
		}
	}
	if detail {
		v.Tasks = append([]engine.Event(nil), j.tasks...)
		if j.state != "running" {
			v.Report = j.report
		}
	}
	return v
}

func (s *Server) add(j *job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(j)
}

// addLocked registers a job; s.mu must be held. Beyond maxJobs the oldest report opened from a
// file goes first (it is on disk), then the oldest finished scan.
func (s *Server) addLocked(j *job) {
	s.jobs[j.id] = j
	s.order = append(s.order, j.id)
	for len(s.order) > maxJobs {
		victim := -1
		for _, wantFile := range []bool{true, false} {
			for i, id := range s.order {
				old := s.jobs[id]
				old.mu.Lock()
				ok := old.state != "running" && (old.source == "file") == wantFile
				old.mu.Unlock()
				if ok {
					victim = i
					break
				}
			}
			if victim >= 0 {
				break
			}
		}
		if victim < 0 {
			return
		}
		delete(s.jobs, s.order[victim])
		s.order = append(s.order[:victim], s.order[victim+1:]...)
	}
}

func (s *Server) get(id string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

func (s *Server) addReport(r *output.Report, name string) *job {
	label := r.Label
	if label == "" {
		label = strings.TrimSuffix(name, filepath.Ext(name))
	}
	now := time.Now()
	j := &job{id: randomHex(8), label: cleanLabel(label), source: "file", state: "done", started: now, finished: now, report: r}
	if t, err := time.Parse(time.RFC3339, r.Generated); err == nil {
		j.started, j.finished = t, t
	}
	s.add(j)
	return j
}

func (s *Server) cancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.cancel != nil {
			j.cancel()
		}
	}
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ids := append([]string(nil), s.order...)
	s.mu.Unlock()
	out := []jobView{}
	for i := len(ids) - 1; i >= 0; i-- { // newest first
		if j := s.get(ids[i]); j != nil {
			out = append(out, j.view(false))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var sr scanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sr); err != nil {
		jsonError(w, http.StatusBadRequest, "bad scan request: "+err.Error())
		return
	}
	req, err := sr.build()
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock() // held across the check and the registration, so two requests cannot both start
	for _, j := range s.jobs {
		j.mu.Lock()
		running := j.state == "running"
		j.mu.Unlock()
		if running {
			s.mu.Unlock()
			jsonError(w, http.StatusConflict, "a scan is already running")
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{id: randomHex(8), label: req.Label, source: "scan", state: "running", started: time.Now(), tasks: engine.Plan(req), cancel: cancel}
	s.addLocked(j)
	s.mu.Unlock()
	go func() {
		defer cancel()
		res := engine.Run(ctx, req, s.version, j.update)
		j.mu.Lock()
		defer j.mu.Unlock()
		j.report, j.finished = res.Report, time.Now()
		switch {
		case ctx.Err() != nil:
			j.state, j.err = "cancelled", "scan cancelled"
		case res.SwitchesFailed == len(req.Switches):
			j.state, j.err = "failed", failureMessage(res.Report)
		default:
			j.state = "done"
			if !res.Complete() {
				j.err = "some devices did not answer in full; see Switches"
			}
		}
	}()
	writeJSON(w, http.StatusAccepted, j.view(true))
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	j := s.get(r.PathValue("id"))
	if j == nil {
		jsonError(w, http.StatusNotFound, "no such scan")
		return
	}
	writeJSON(w, http.StatusOK, j.view(true))
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	j := s.get(r.PathValue("id"))
	if j == nil {
		jsonError(w, http.StatusNotFound, "no such scan")
		return
	}
	if j.cancel != nil {
		j.cancel()
	}
	writeJSON(w, http.StatusOK, j.view(false))
}

func (s *Server) deleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil {
		jsonError(w, http.StatusNotFound, "no such scan")
		return
	}
	j.mu.Lock()
	running := j.state == "running"
	j.mu.Unlock()
	if running {
		jsonError(w, http.StatusConflict, "cancel the scan before removing it")
		return
	}
	delete(s.jobs, id)
	for i, x := range s.order {
		if x == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

var exportTypes = map[string]struct{ ext, ctype string }{
	"csv":   {"csv", "text/csv; charset=utf-8"},
	"json":  {"json", "application/json"},
	"table": {"txt", "text/plain; charset=utf-8"},
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	j := s.get(r.PathValue("id"))
	if j == nil {
		jsonError(w, http.StatusNotFound, "no such scan")
		return
	}
	format := r.URL.Query().Get("format")
	t, ok := exportTypes[format]
	if !ok {
		jsonError(w, http.StatusBadRequest, "format must be csv, json or table")
		return
	}
	j.mu.Lock()
	rep, label := j.report, j.label
	j.mu.Unlock()
	if rep == nil {
		jsonError(w, http.StatusConflict, "the scan has no report yet")
		return
	}
	var buf bytes.Buffer
	if err := output.Write(&buf, format, rep); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", t.ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, exportName(label, rep.Generated, t.ext)))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) importReport(w http.ResponseWriter, r *http.Request) {
	var rep output.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		jsonError(w, http.StatusBadRequest, "not a report: "+err.Error())
		return
	}
	if rep.Tool != "atlas-portmap" {
		jsonError(w, http.StatusBadRequest, "not an atlas-portmap report (tool field missing)")
		return
	}
	j := s.addReport(&rep, r.URL.Query().Get("name"))
	writeJSON(w, http.StatusCreated, j.view(true))
}

func (s *Server) quit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	time.AfterFunc(200*time.Millisecond, s.stop)
}

// failureMessage says why the switches failed, from the error kinds in the report:
// "1 switch rejected the SNMPv3 credentials: check …", or with several kinds
// "3 switches failed: 2 did not respond, 1 rejected the SNMPv3 credentials".
func failureMessage(r *output.Report) string {
	type reason struct{ what, advice string }
	var order []reason
	count := map[reason]int{}
	n := 0
	for _, s := range r.Switches {
		if s.Error == "" || s.Partial {
			continue
		}
		var why reason
		switch k := snmpc.Kind(s.ErrorKind); {
		case k == snmpc.KindV3NoResponse:
			why = reason{"answered SNMPv3 discovery but not the request", "check the SNMPv3 user, passphrases and protocols (some agents only do DES privacy) and access lists"}
		case k.NoResponse():
			why = reason{"did not respond", "check the addresses, the community or SNMPv3 credentials, SNMP access lists and firewalls"}
		case k == snmpc.KindPortClosed:
			why = reason{"had no SNMP agent listening", "enable SNMP on the device (Cisco Small Business: snmp-server server)"}
		case k.Credentials():
			why = reason{"rejected the SNMPv3 credentials", "check the user, the passphrases and the auth and privacy protocols"}
		case k == snmpc.KindAccessDenied:
			why = reason{"refused access", "the community or SNMPv3 group may not read; check the security level and view"}
		default:
			why = reason{"failed", ""}
		}
		if count[why] == 0 {
			order = append(order, why)
		}
		count[why]++
		n++
	}
	switches := func(k int) string {
		if k == 1 {
			return "1 switch"
		}
		return fmt.Sprintf("%d switches", k)
	}
	switch {
	case n == 0:
		return "no switch answered; see Switches"
	case len(order) == 1 && order[0].advice != "":
		return fmt.Sprintf("%s %s: %s; see Switches", switches(n), order[0].what, order[0].advice)
	case len(order) == 1:
		return fmt.Sprintf("%s %s; see Switches", switches(n), order[0].what)
	}
	parts := make([]string, len(order))
	for i, why := range order {
		parts[i] = fmt.Sprintf("%d %s", count[why], why.what)
	}
	return fmt.Sprintf("%s failed: %s; see Switches", switches(n), strings.Join(parts, ", "))
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func exportName(label, generated, ext string) string {
	base := strings.Trim(unsafeName.ReplaceAllString(label, "-"), "-.")
	if base == "" {
		base = "portmap"
	}
	if len(base) > 60 {
		base = base[:60]
	}
	stamp := time.Now().UTC().Format("20060102-1504")
	if t, err := time.Parse(time.RFC3339, generated); err == nil {
		stamp = t.UTC().Format("20060102-1504")
	}
	return base + "-" + stamp + "." + ext
}

// openBrowser opens url through a private redirect file (as Jupyter does), so the session
// token never appears on a command line other local users can read. The returned cleanup
// removes the file.
func openBrowser(url string) (func(), error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	dir = filepath.Join(dir, "atlas-portmap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "open-*.html") // mode 0600
	if err != nil {
		return nil, err
	}
	u := html.EscapeString(url)
	fmt.Fprintf(f, "<!doctype html><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=%s\"><title>atlas-portmap</title><a href=\"%s\">Open atlas-portmap</a>\n", u, u)
	if err := f.Close(); err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", f.Name())
	case "darwin":
		cmd = exec.Command("open", f.Name())
	default:
		cmd = exec.Command("xdg-open", f.Name())
	}
	if err := cmd.Start(); err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	var once sync.Once
	cleanup := func() { once.Do(func() { os.Remove(f.Name()) }) }
	time.AfterFunc(2*time.Minute, cleanup)
	return cleanup, nil
}

// sortedKeys is used by tests and the scan request builder.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var errNoSwitch = errors.New("add at least one switch (or an inventory with switch lines)")
