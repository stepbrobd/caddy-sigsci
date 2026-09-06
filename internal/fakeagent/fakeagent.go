// Package fakeagent stands in for the module RPC listener of sigsci-agent
// it speaks the msgpack net/rpc framing of sigsci-module-golang's client codec
// and applies a fixed policy (for testing only)

package fakeagent

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/rpc"
	"strings"

	"github.com/signalsciences/sigsci-module-golang/schema"
	"github.com/tinylib/msgp/msgp"
)

type codec struct {
	dec *msgp.Reader
	enc *msgp.Writer
	c   io.Closer
}

func (c *codec) ReadRequestHeader(r *rpc.Request) error {
	sz, err := c.dec.ReadArrayHeader()
	if err != nil {
		return err
	}
	if sz != 4 {
		return fmt.Errorf("request array size %d", sz)
	}
	typ, err := c.dec.ReadInt()
	if err != nil {
		return err
	}
	if typ != 0 {
		return fmt.Errorf("request type %d", typ)
	}
	r.Seq, err = c.dec.ReadUint64()
	if err != nil {
		return err
	}
	r.ServiceMethod, err = c.dec.ReadString()
	return err
}

func (c *codec) ReadRequestBody(x any) error {
	sz, err := c.dec.ReadArrayHeader()
	if err != nil {
		return err
	}
	if sz != 1 {
		return fmt.Errorf("argument array size %d", sz)
	}
	if d, ok := x.(msgp.Decodable); ok {
		return d.DecodeMsg(c.dec)
	}
	return c.dec.Skip()
}

func (c *codec) WriteResponse(r *rpc.Response, x any) error {
	c.enc.WriteArrayHeader(4)
	c.enc.WriteUint64(1)
	c.enc.WriteUint64(r.Seq)
	if r.Error != "" {
		c.enc.WriteString(r.Error)
		c.enc.WriteNil()
		return c.enc.Flush()
	}
	c.enc.WriteNil()
	switch v := x.(type) {
	case msgp.Encodable:
		if err := v.EncodeMsg(c.enc); err != nil {
			return err
		}
	case *int:
		c.enc.WriteInt(*v)
	default:
		if err := c.enc.WriteIntf(x); err != nil {
			return err
		}
	}
	return c.enc.Flush()
}

func (c *codec) Close() error { return c.c.Close() }

// Agent holds the fixed policy, the method names match the agent's RPC service
// a request whose uri or body mentions attack is blocked with 406, /redir is
// redirected, /tag is allowed with a request id, a tag and a response header
type Agent struct {
	Quiet bool
}

func (a Agent) logf(format string, args ...any) {
	if !a.Quiet {
		log.Printf(format, args...)
	}
}

func (a Agent) ModuleInit(in *schema.RPCMsgIn, out *schema.RPCMsgOut) error {
	a.logf("ModuleInit module=%q server=%q", in.ModuleVersion, in.ServerVersion)
	out.WAFResponse = 200
	return nil
}

func (a Agent) PreRequest(in *schema.RPCMsgIn, out *schema.RPCMsgOut) error {
	a.logf("PreRequest %s %s remote=%s scheme=%s host=%s body=%q headers=%d", in.Method, in.URI, in.RemoteAddr, in.Scheme, in.ServerName, in.PostBody, len(in.HeadersIn))
	out.WAFResponse = 200
	switch {
	case strings.Contains(in.URI, "attack") || strings.Contains(in.PostBody, "attack"):
		out.WAFResponse = 406
		out.RequestID = "req-blocked"
		out.RequestHeaders = [][2]string{{"X-Sigsci-Tags", "SQLI"}}
	case strings.HasPrefix(in.URI, "/redir"):
		out.WAFResponse = 302
		out.RequestHeaders = [][2]string{{"X-Sigsci-Redirect", "https://example.org/"}}
	case strings.HasPrefix(in.URI, "/tag"):
		out.RequestID = "req-tagged"
		out.RequestHeaders = [][2]string{{"X-Sigsci-Tags", "SCANNER"}}
		out.RespActions = []schema.Action{{Code: schema.SetHdr, Args: []string{"X-Waf", "seen"}}}
	}
	return nil
}

func (a Agent) PostRequest(in *schema.RPCMsgIn, out *int) error {
	a.logf("PostRequest %s %s code=%d size=%d ms=%d waf=%d", in.Method, in.URI, in.ResponseCode, in.ResponseSize, in.ResponseMillis, in.WAFResponse)
	*out = 0
	return nil
}

func (a Agent) UpdateRequest(in *schema.RPCMsgIn2, out *int) error {
	a.logf("UpdateRequest id=%s code=%d size=%d ms=%d headers=%d", in.RequestID, in.ResponseCode, in.ResponseSize, in.ResponseMillis, len(in.HeadersOut))
	*out = 0
	return nil
}

// Serve answers module RPC on ln until Accept fails
func Serve(ln net.Listener, agent Agent) error {
	srv := rpc.NewServer()
	if err := srv.RegisterName("RPC", agent); err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go srv.ServeCodec(&codec{dec: msgp.NewReader(conn), enc: msgp.NewWriter(conn), c: conn})
	}
}
