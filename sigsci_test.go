package sigsci

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	sigsci "github.com/signalsciences/sigsci-module-golang"
	"github.com/signalsciences/sigsci-module-golang/schema"
	"go.uber.org/zap"

	"github.com/stepbrobd/caddy-sigsci/internal/fakeagent"
)

// fakeInspector answers PreRequest from a fixed reply and records every call
type fakeInspector struct {
	reply   sigsci.RPCMsgOut
	preErr  error
	mu      sync.Mutex
	pre     []*sigsci.RPCMsgIn
	post    []*sigsci.RPCMsgIn
	update  []*sigsci.RPCMsgIn2
	settled chan struct{}
}

func newFake(reply sigsci.RPCMsgOut) *fakeInspector {
	return &fakeInspector{reply: reply, settled: make(chan struct{}, 8)}
}

func (f *fakeInspector) ModuleInit(*sigsci.RPCMsgIn, *sigsci.RPCMsgOut) error { return nil }

func (f *fakeInspector) PreRequest(in *sigsci.RPCMsgIn, out *sigsci.RPCMsgOut) error {
	f.mu.Lock()
	f.pre = append(f.pre, in)
	f.mu.Unlock()
	if f.preErr != nil {
		return f.preErr
	}
	*out = f.reply
	return nil
}

func (f *fakeInspector) PostRequest(in *sigsci.RPCMsgIn, _ *sigsci.RPCMsgOut) error {
	f.mu.Lock()
	f.post = append(f.post, in)
	f.mu.Unlock()
	f.settled <- struct{}{}
	return nil
}

func (f *fakeInspector) UpdateRequest(in *sigsci.RPCMsgIn2, _ *sigsci.RPCMsgOut) error {
	f.mu.Lock()
	f.update = append(f.update, in)
	f.mu.Unlock()
	f.settled <- struct{}{}
	return nil
}

func (f *fakeInspector) wait(t *testing.T) {
	t.Helper()
	select {
	case <-f.settled:
	case <-time.After(2 * time.Second):
		t.Fatal("no post or update call")
	}
}

func newHandler(t *testing.T, insp sigsci.Inspector) *Handler {
	t.Helper()
	cfg, err := sigsci.NewModuleConfig()
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{config: cfg, inspector: insp, logger: zap.NewNop()}
}

func request(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	return r.WithContext(ctx)
}

func TestAllowSetsHeadersAndUpdates(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200, RequestID: "req-1", RequestHeaders: [][2]string{{"X-Sigsci-Tags", "SQLI"}}})
	h := newHandler(t, f)
	var seen http.Header
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte("hello"))
		return err
	})
	rec := httptest.NewRecorder()
	r := request("GET", "http://example.com/x", nil)
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, "203.0.113.5")
	if err := h.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusCreated || rec.Body.String() != "hello" {
		t.Fatalf("response %d %q", rec.Code, rec.Body.String())
	}
	if seen.Get("X-Sigsci-Requestid") != "req-1" || seen.Get("X-Sigsci-Agentresponse") != "200" || seen.Get("X-Sigsci-Tags") != "SQLI" {
		t.Fatalf("upstream headers %v", seen)
	}
	if f.pre[0].RemoteAddr != "203.0.113.5" {
		t.Fatalf("remote %q", f.pre[0].RemoteAddr)
	}
	if v, _ := caddyhttp.GetVar(r.Context(), "sigsci.agent_response").(int); v != 200 {
		t.Fatalf("var %v", v)
	}
	f.wait(t)
	if len(f.update) != 1 || f.update[0].ResponseCode != 201 || f.update[0].ResponseSize != 5 || f.update[0].RequestID != "req-1" {
		t.Fatalf("update %+v", f.update)
	}
}

func TestAgentHeadersSurviveConnectionOptions(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	f := newFake(sigsci.RPCMsgOut{
		WAFResponse:    200,
		RequestID:      "req-connection",
		RequestHeaders: [][2]string{{"X-Sigsci-Tags", "SQLI"}},
	})
	h := newHandler(t, f)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		proxy.ServeHTTP(w, r)
		return nil
	})
	r := request("GET", "http://example.com/", nil)
	r.Header.Set("Connection", "X-Sigsci-Requestid, x-sigsci-agentresponse, X-SIGSCI-TAGS, Keep-Me")
	r.Header.Set("Keep-Me", "client")
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	if seen.Get("X-Sigsci-Requestid") != "req-connection" ||
		seen.Get("X-Sigsci-Agentresponse") != "200" ||
		seen.Get("X-Sigsci-Tags") != "SQLI" {
		t.Fatalf("upstream headers %v", seen)
	}
	if seen.Get("Keep-Me") != "" {
		t.Fatalf("unprotected connection option reached upstream: %v", seen)
	}
}

func TestPostRequestUsesInspectedURI(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200})
	h := newHandler(t, f)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		r.RequestURI = "/rewritten"
		r.URL.Path = "/rewritten"
		http.Error(w, "missing", http.StatusNotFound)
		return nil
	})
	r := request("GET", "/original?x=1", nil)
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	f.wait(t)
	if len(f.post) != 1 {
		t.Fatalf("post request count %d", len(f.post))
	}
	if f.post[0].URI != "/original?x=1" {
		t.Fatalf("post request URI %q", f.post[0].URI)
	}
}

func TestBlockAndRedirect(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 406})
	h := newHandler(t, f)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { t.Fatal("next called"); return nil })
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, request("GET", "http://example.com/attack", nil), next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 406 || !strings.Contains(rec.Body.String(), "406 Not Acceptable") {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	f.wait(t)
	if len(f.post) != 1 || f.post[0].ResponseCode != 406 || f.post[0].WAFResponse != 406 {
		t.Fatalf("post %+v", f.post)
	}

	f = newFake(sigsci.RPCMsgOut{WAFResponse: 302, RequestHeaders: [][2]string{{"X-Sigsci-Redirect", "https://example.org/"}}})
	h = newHandler(t, f)
	rec = httptest.NewRecorder()
	if err := h.ServeHTTP(rec, request("GET", "http://example.com/", nil), next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 302 || rec.Header().Get("Location") != "https://example.org/" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	f.wait(t)
}

func TestFailOpen(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{})
	f.preErr = errors.New("dial unix: no such file")
	h := newHandler(t, f)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get("X-Sigsci-Agentresponse") != "" {
			t.Fatal("forged verdict survived fail open")
		}
		w.WriteHeader(204)
		return nil
	})
	r := request("GET", "http://example.com/", nil)
	r.Header.Set("X-Sigsci-Agentresponse", "200")
	if err := h.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 204 || !h.down.Load() {
		t.Fatalf("code=%d down=%v", rec.Code, h.down.Load())
	}
}

func TestBodyInspectedAndReplayed(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200})
	h := newHandler(t, f)
	r := request("POST", "http://example.com/form", strings.NewReader("a=1&b=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var got string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, err := io.ReadAll(r.Body)
		got = string(b)
		return err
	})
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	if got != "a=1&b=2" || f.pre[0].PostBody != "a=1&b=2" {
		t.Fatalf("replayed=%q inspected=%q", got, f.pre[0].PostBody)
	}

	// a body of unknown length past the limit is replayed untouched and not inspected
	h.config.SetOptions(sigsci.MaxContentLength(4), sigsci.AllowUnknownContentLength(true))
	r = request("POST", "http://example.com/form", strings.NewReader("a=1&b=2"))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	if err := h.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	if got != "a=1&b=2" || f.pre[1].PostBody != "" {
		t.Fatalf("replayed=%q inspected=%q", got, f.pre[1].PostBody)
	}
}

func TestBodyReadErrorReplayed(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200})
	h := newHandler(t, f)
	const body = `{"q":"attack"}`
	r := request("POST", "http://example.com/form", nil)
	r.Body = io.NopCloser(io.MultiReader(
		strings.NewReader(body),
		iotest.ErrReader(io.ErrUnexpectedEOF),
	))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/json")

	var got []byte
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		var err error
		got, err = io.ReadAll(r.Body)
		return err
	})
	err := h.ServeHTTP(httptest.NewRecorder(), r, next)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("downstream error %v", err)
	}
	if string(got) != body {
		t.Fatalf("downstream body %q", got)
	}
	if f.pre[0].PostBody != "" {
		t.Fatalf("inspected partial body %q", f.pre[0].PostBody)
	}
}

// the wrapper must keep Unwrap so a flush through http.ResponseController
// reaches the real writer, and header actions land on the first write
func TestRespActionsAndFlush(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200, RespActions: []schema.Action{
		{Code: schema.SetHdr, Args: []string{"X-Waf", "seen"}},
		{Code: schema.DelHdr, Args: []string{"Server"}},
	}})
	h := newHandler(t, f)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Server", "hidden")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatalf("flush through wrapper: %v", err)
		}
		_, err := w.Write([]byte("streamed"))
		return err
	})
	if err := h.ServeHTTP(rec, request("GET", "http://example.com/", nil), next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || rec.Header().Get("X-Waf") != "seen" || rec.Header().Get("Server") != "" || !rec.Flushed {
		t.Fatalf("code=%d hdr=%v flushed=%v", rec.Code, rec.Header(), rec.Flushed)
	}
}

// an error leaves the writing to caddy, the status and header actions must still land
func TestErrorStatusReported(t *testing.T) {
	f := newFake(sigsci.RPCMsgOut{WAFResponse: 200, RequestID: "req-err",
		RespActions: []schema.Action{{Code: schema.SetHdr, Args: []string{"X-Waf", "seen"}}}})
	h := newHandler(t, f)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("upstream down"))
	})
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, request("GET", "http://example.com/", nil), next)
	if err == nil {
		t.Fatal("error swallowed")
	}
	if rec.Header().Get("X-Waf") != "seen" {
		t.Fatalf("hdr %v", rec.Header())
	}
	f.wait(t)
	if f.update[0].ResponseCode != 502 {
		t.Fatalf("update code %d", f.update[0].ResponseCode)
	}
}

// the msgpack framing of the real client against the fake agent
func TestRPCRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fakeagent.Serve(ln, fakeagent.Agent{Quiet: true})

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	h := &Handler{Network: "tcp", Address: ln.Addr().String(), Timeout: caddy.Duration(time.Second)}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if h.down.Load() {
		t.Fatal("moduleinit failed")
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, err := io.WriteString(w, r.Header.Get("X-Sigsci-Tags"))
		return err
	})
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, request("GET", "/tag", nil), next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || rec.Body.String() != "SCANNER" || rec.Header().Get("X-Waf") != "seen" {
		t.Fatalf("code=%d body=%q hdr=%v", rec.Code, rec.Body.String(), rec.Header())
	}

	r := request("POST", "/form", strings.NewReader(`{"q":"attack"}`))
	r.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	if err := h.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 406 {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
}
