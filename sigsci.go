// Package sigsci is a Caddy HTTP handler for the Fastly Next-Gen WAF agent
// it sends each request to the agent over the module RPC socket, enforces
// the verdict and reports the response, driving the RPC client of
// sigsci-module-golang the way that package's gin example does, with a
// Caddy native response writer so flushing and hijacking work behind it
package sigsci

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
	sigsci "github.com/signalsciences/sigsci-module-golang"
	"github.com/signalsciences/sigsci-module-golang/schema"
	"go.uber.org/zap"
)

var (
	// implementing these interfaces
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ io.ReaderFrom               = (*recorder)(nil)
)

const modulePath = "github.com/stepbrobd/caddy-sigsci"

// the request headers the official modules hand to the application
var agentHeaders = []string{"X-Sigsci-Requestid", "X-Sigsci-Agentresponse", "X-Sigsci-Tags", "X-Sigsci-Redirect"}

func init() {
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("sigsci", parseCaddyfile)
	// after vars, header and request_body so body limits and deferred
	// response headers apply, before anything that rewrites or answers
	httpcaddyfile.RegisterDirectiveOrder("sigsci", httpcaddyfile.After, "request_body")
}

// Handler inspects requests with the Next-Gen WAF agent
type Handler struct {
	// network of the agent RPC listener, unix or tcp, default unix
	Network string `json:"network,omitempty"`
	// address of the agent RPC listener, default /var/run/sigsci.sock
	Address string `json:"address,omitempty"`
	// timeout of each RPC call, the request fails open when it elapses, default 100ms
	Timeout caddy.Duration `json:"timeout,omitempty"`
	// largest request body sent for inspection, default 100000
	MaxContentLength int64 `json:"max_content_length,omitempty"`
	// response size from which an unflagged request is still reported, default 512 KiB
	AnomalySize int64 `json:"anomaly_size,omitempty"`
	// response time from which an unflagged request is still reported, default 1s
	AnomalyDuration caddy.Duration `json:"anomaly_duration,omitempty"`
	// free form label shown in the console
	ServerFlavor string `json:"server_flavor,omitempty"`
	// extra request content types whose bodies are inspected
	ExpectedContentTypes []string `json:"expected_content_types,omitempty"`
	// inspect request bodies regardless of content type
	ExtendContentTypes bool `json:"extend_content_types,omitempty"`
	// inspect bodies of unknown length up to max_content_length
	AllowUnknownContentLength bool `json:"allow_unknown_content_length,omitempty"`
	// report the transport peer instead of the trusted proxy resolved client ip
	PeerAddress bool `json:"peer_address,omitempty"`

	config    *sigsci.ModuleConfig
	inspector sigsci.Inspector
	logger    *zap.Logger
	down      atomic.Bool
}

func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.sigsci",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision builds the module configuration and announces the module to the agent
// an unreachable agent is not fatal because every request fails open
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	simple, _ := caddy.Version()
	opts := []sigsci.ModuleConfigOption{
		// the console resolves the module type from the identifier name and knows only fastly's own modules,
		// fastly's traefik plugin reports the golang module with a suffixed version the same way
		sigsci.ModuleIdentifier("sigsci-module-golang", strings.TrimPrefix(version(), "v")+"-caddy"),
		sigsci.ServerIdentifier("caddy " + simple),
		sigsci.AllowUnknownContentLength(h.AllowUnknownContentLength),
	}
	if h.Network != "" || h.Address != "" {
		network, address := h.Network, h.Address
		if network == "" {
			network = sigsci.DefaultRPCNetwork
		}
		if address == "" {
			address = sigsci.DefaultRPCAddress
		}
		opts = append(opts, sigsci.Socket(network, address))
	}
	if h.Timeout > 0 {
		opts = append(opts, sigsci.Timeout(time.Duration(h.Timeout)))
	}
	if h.MaxContentLength > 0 {
		opts = append(opts, sigsci.MaxContentLength(h.MaxContentLength))
	}
	if h.AnomalySize > 0 {
		opts = append(opts, sigsci.AnomalySize(h.AnomalySize))
	}
	if h.AnomalyDuration > 0 {
		opts = append(opts, sigsci.AnomalyDuration(time.Duration(h.AnomalyDuration)))
	}
	if h.ServerFlavor != "" {
		opts = append(opts, sigsci.ServerFlavor(h.ServerFlavor))
	}
	for _, ct := range h.ExpectedContentTypes {
		opts = append(opts, sigsci.ExpectedContentType(ct))
	}

	cfg, err := sigsci.NewModuleConfig(opts...)
	if err != nil {
		return err
	}
	h.config = cfg
	if h.inspector == nil {
		h.inspector = &sigsci.RPCInspector{
			Network: cfg.RPCNetwork(),
			Address: cfg.RPCAddress(),
			Timeout: cfg.Timeout(),
		}
	}

	now := time.Now()
	in := sigsci.RPCMsgIn{
		ModuleVersion: cfg.ModuleIdentifier(),
		ServerVersion: cfg.ServerIdentifier(),
		ServerFlavor:  cfg.ServerFlavor(),
		Timestamp:     now.Unix(),
		NowMillis:     now.UnixMilli(),
	}
	if err := h.inspector.ModuleInit(&in, &sigsci.RPCMsgOut{}); err != nil {
		h.down.Store(true)
		h.logger.Warn("agent unreachable, requests fail open until it answers",
			zap.String("address", cfg.RPCAddressString()), zap.Error(err))
	}
	return nil
}

// version is the module version go recorded at build time
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	if info.Main.Path == modulePath {
		return info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			return dep.Replace.Version
		}
		return dep.Version
	}
	return "devel"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()

	body := h.readBody(r)
	in := sigsci.NewRPCMsgIn(h.config, r, body, -1, -1, 0)
	if !h.PeerAddress {
		if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
			in.RemoteAddr = ip
		}
	}

	var out sigsci.RPCMsgOut
	if err := h.inspector.PreRequest(in, &out); err != nil {
		if h.down.CompareAndSwap(false, true) {
			h.logger.Warn("agent unreachable, failing open", zap.Error(err))
		}
		// a client must not be able to forge a verdict while the agent is away
		for _, k := range agentHeaders {
			r.Header.Del(k)
		}
		return next.ServeHTTP(w, r)
	}
	if h.down.CompareAndSwap(true, false) {
		h.logger.Info("agent reachable again")
	}

	for _, k := range agentHeaders {
		r.Header.Del(k)
	}
	if out.RequestID != "" {
		r.Header.Set("X-Sigsci-Requestid", out.RequestID)
	}
	r.Header.Set("X-Sigsci-Agentresponse", strconv.Itoa(int(out.WAFResponse)))
	for _, kv := range out.RequestHeaders {
		if strings.HasPrefix(http.CanonicalHeaderKey(kv[0]), "X-Sigsci-") {
			r.Header.Set(kv[0], kv[1])
		} else {
			r.Header.Add(kv[0], kv[1])
		}
	}
	caddyhttp.SetVar(r.Context(), "sigsci.request_id", out.RequestID)
	caddyhttp.SetVar(r.Context(), "sigsci.agent_response", int(out.WAFResponse))
	caddyhttp.SetVar(r.Context(), "sigsci.tags", r.Header.Get("X-Sigsci-Tags"))

	h.logger.Debug("prerequest",
		zap.String("uri", in.URI), zap.String("remote", in.RemoteAddr),
		zap.Int32("waf_response", out.WAFResponse), zap.String("request_id", out.RequestID))

	rw := &recorder{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		actions:               out.RespActions,
	}

	var err error
	waf := int(out.WAFResponse)
	switch {
	case h.config.IsAllowCode(waf):
		err = next.ServeHTTP(rw, r)
	case h.config.IsBlockCode(waf):
		if waf >= 300 && waf <= 399 {
			if loc := r.Header.Get("X-Sigsci-Redirect"); loc != "" {
				http.Redirect(rw, r, loc, waf)
				break
			}
		}
		http.Error(rw, fmt.Sprintf("%d %s", waf, http.StatusText(waf)), waf)
	default:
		h.logger.Error("invalid agent response code, failing open", zap.Int("code", waf))
		err = next.ServeHTTP(rw, r)
	}

	duration := time.Since(start)
	code := rw.status
	if code == 0 {
		// nothing written yet, the error handler answers on the same header
		// map, so the agent's header actions still apply
		rw.apply()
		switch herr := err.(type) {
		case nil:
			code = http.StatusOK
		case caddyhttp.HandlerError:
			code = herr.StatusCode
		default:
			code = http.StatusInternalServerError
		}
	}
	headersOut := headers(rw.Header())

	if out.RequestID != "" {
		upd := sigsci.RPCMsgIn2{
			RequestID:      out.RequestID,
			ResponseCode:   int32(code),
			ResponseSize:   rw.size,
			ResponseMillis: duration.Milliseconds(),
			HeadersOut:     headersOut,
		}
		go func() {
			if err := h.inspector.UpdateRequest(&upd, &sigsci.RPCMsgOut{}); err != nil {
				h.logger.Debug("updaterequest failed", zap.Error(err))
			}
		}()
	} else if code >= 300 || rw.size >= h.config.AnomalySize() || duration >= h.config.AnomalyDuration() {
		post := sigsci.NewRPCMsgIn(h.config, r, nil, code, rw.size, duration)
		post.RemoteAddr = in.RemoteAddr
		post.WAFResponse = out.WAFResponse
		post.HeadersOut = headersOut
		go func() {
			if err := h.inspector.PostRequest(post, &sigsci.RPCMsgOut{}); err != nil {
				h.logger.Debug("postrequest failed", zap.Error(err))
			}
		}()
	}
	return err
}

// readBody buffers an inspectable request body and hands the handler chain
// an equivalent reader, never holding more than max_content_length plus one byte
func (h *Handler) readBody(r *http.Request) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	cfg := h.config
	if !(cfg.AllowUnknownContentLength() && r.ContentLength == -1) {
		if r.ContentLength <= 0 || r.ContentLength > cfg.MaxContentLength() {
			return nil
		}
	}
	if !h.ExtendContentTypes && !h.inspectable(r.Header) {
		return nil
	}

	buf, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxContentLength()+1))
	if err != nil || int64(len(buf)) > cfg.MaxContentLength() {
		// too large or truncated, replay what was consumed and skip inspection
		r.Body = readCloser{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
		return nil
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf
}

type readCloser struct {
	io.Reader
	io.Closer
}

// inspectable mirrors the content type selection of sigsci-module-golang
func (h *Handler) inspectable(hdr http.Header) bool {
	ct := hdr.Get("Content-Type")
	if h.config.IsExpectedContentType(ct) {
		return true
	}
	if len(hdr.Values("Content-Type")) > 1 || strings.Contains(ct, ",") {
		return true
	}
	s := strings.ToLower(ct)
	switch {
	case s == "",
		strings.HasPrefix(s, "application/x-www-form-urlencoded"),
		strings.HasPrefix(s, "multipart/form-data"),
		strings.Contains(s, "json"),
		strings.Contains(s, "javascript"),
		strings.HasPrefix(s, "text/xml"),
		strings.HasPrefix(s, "application/xml"),
		strings.Contains(s, "+xml"),
		strings.HasPrefix(s, "application/grpc"),
		strings.HasPrefix(s, "application/graphql"):
		return true
	}
	return false
}

func headers(h http.Header) [][2]string {
	out := make([][2]string, 0, len(h))
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

// recorder tracks the status and size of the response and applies the agent's
// response header actions on the first write
// embedding ResponseWriterWrapper keeps Unwrap, so http.ResponseController
// reaches the real writer for Flush, Hijack and the deadline methods
type recorder struct {
	*caddyhttp.ResponseWriterWrapper
	status  int
	size    int64
	actions []schema.Action
}

// apply merges the agent's header actions once
func (rw *recorder) apply() {
	hdr := rw.Header()
	for _, a := range rw.actions {
		switch a.Code {
		case schema.AddHdr:
			hdr.Add(a.Args[0], a.Args[1])
		case schema.SetHdr:
			hdr.Set(a.Args[0], a.Args[1])
		case schema.SetNEHdr:
			if hdr.Get(a.Args[0]) == "" {
				hdr.Set(a.Args[0], a.Args[1])
			}
		case schema.DelHdr:
			hdr.Del(a.Args[0])
		}
	}
	rw.actions = nil
}

func (rw *recorder) WriteHeader(code int) {
	// informational responses pass through and are never recorded
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		rw.ResponseWriterWrapper.WriteHeader(code)
		return
	}
	if rw.status != 0 {
		return
	}
	rw.apply()
	rw.status = code
	rw.ResponseWriterWrapper.WriteHeader(code)
}

func (rw *recorder) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriterWrapper.Write(b)
	rw.size += int64(n)
	return n, err
}

func (rw *recorder) ReadFrom(src io.Reader) (int64, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriterWrapper.ReadFrom(src)
	rw.size += n
	return n, err
}

// FlushError writes the implicit 200 before flushing so the status is recorded
func (rw *recorder) FlushError() error {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(rw.ResponseWriterWrapper).Flush()
}

// Hijack records the protocol switch and hands the connection over
func (rw *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw.status = http.StatusSwitchingProtocols
	return http.NewResponseController(rw.ResponseWriterWrapper).Hijack()
}

// UnmarshalCaddyfile parses
//
//	sigsci [<network> <address>] {
//	    socket <unix|tcp> <address>
//	    timeout <duration>
//	    max_content_length <size>
//	    anomaly_size <size>
//	    anomaly_duration <duration>
//	    server_flavor <label>
//	    expected_content_types <type...>
//	    extend_content_types
//	    allow_unknown_content_length
//	    peer_address
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if args := d.RemainingArgs(); len(args) > 0 {
		if len(args) != 2 {
			return d.ArgErr()
		}
		h.Network, h.Address = args[0], args[1]
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "socket":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Network = d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Address = d.Val()
		case "timeout", "anomaly_duration":
			key := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad %s: %v", key, err)
			}
			if key == "timeout" {
				h.Timeout = caddy.Duration(dur)
			} else {
				h.AnomalyDuration = caddy.Duration(dur)
			}
		case "max_content_length", "anomaly_size":
			key := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			size, err := humanize.ParseBytes(d.Val())
			if err != nil {
				return d.Errf("bad %s: %v", key, err)
			}
			if key == "max_content_length" {
				h.MaxContentLength = int64(size)
			} else {
				h.AnomalySize = int64(size)
			}
		case "server_flavor":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ServerFlavor = d.Val()
		case "expected_content_types":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.ExpectedContentTypes = append(h.ExpectedContentTypes, args...)
		case "extend_content_types":
			h.ExtendContentTypes = true
		case "allow_unknown_content_length":
			h.AllowUnknownContentLength = true
		case "peer_address":
			h.PeerAddress = true
		default:
			return d.Errf("unknown subdirective %q", d.Val())
		}
		if d.NextArg() {
			return d.ArgErr()
		}
	}
	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var h Handler
	err := h.UnmarshalCaddyfile(helper.Dispenser)
	return &h, err
}
