# Caddy SigSci

Caddy HTTP handler for the Fastly Next-Gen WAF agent, formerly the Signal
Sciences agent.

The handler sends each request to a local `sigsci-agent` over its module RPC
socket, enforces the verdict and reports the response back, the same contract
the official nginx, apache and Go modules implement. It drives the RPC client of
[sigsci-module-golang](https://github.com/signalsciences/sigsci-module-golang)
directly, with Caddy native response writer (for flushing, websockets and
HTTP/2, etc.).

## Guide

Build

```sh
xcaddy build --with github.com/stepbrobd/caddy-sigsci
```

Caddyfile example

```caddyfile
example.com {
    sigsci unix /run/sigsci-agent/sigsci.sock

    reverse_proxy localhost:8080
}
```

Subdirectives and defaults:

```caddyfile
sigsci [<network> <address>] {
    socket <unix|tcp> <address>      # unix /var/run/sigsci.sock
    timeout <duration>               # 100ms, the request fails open past it
    max_content_length <size>        # 100000, larger bodies are not inspected
    anomaly_size <size>              # 512 KiB, larger responses are reported
    anomaly_duration <duration>      # 1s, slower responses are reported
    server_flavor <label>            # shown in the console
    expected_content_types <type...> # extra body types to inspect
    extend_content_types             # inspect every body
    allow_unknown_content_length     # inspect chunked bodies too
    peer_address                     # report the peer, not client_ip
}
```

JSON config example

```json
{
  "handler": "sigsci",
  "network": "unix",
  "address": "/run/sigsci-agent/sigsci.sock",
  "timeout": "100ms"
}
```

## Behavior

- The directive orders itself after `request_body`, body limits apply before
  inspection and deferred `header` ops land on blocked responses. The `order`
  global option overrides that.
- The agent answers 200 to allow. Any code from 300 to 599 blocks the request
  with that status, and a 3xx together with an `X-Sigsci-Redirect` header
  redirects.
- The next handler receives `X-Sigsci-Requestid`, `X-Sigsci-Agentresponse` and
  `X-Sigsci-Tags`, so `reverse_proxy` forwards them upstream. Values a client
  sent under those names are dropped first.
- `{http.vars.sigsci.request_id}`, `{http.vars.sigsci.agent_response}` and
  `{http.vars.sigsci.tags}` are set for later directives and for `log`.
- The address reported to the agent is Caddy's `client_ip`, resolved through
  `trusted_proxies`, unless `peer_address` is set.
- Bodies of form, json, xml, grpc and graphql requests up to
  `max_content_length` are buffered for inspection and replayed to the next
  handler.
- An unreachable or slow agent fails open. The `X-Sigsci-*` request headers are
  stripped and the `sigsci` variables stay unset on that path. One warning is
  logged when the agent goes away and one info line when it is back, and the
  global `debug` option shows every verdict.

## Development

`make agent` runs a fake agent on `127.0.0.1:9999` that blocks anything
mentioning `attack`, `make build` builds Caddy with the plugin from the working
tree and `make run` serves the example `caddyfile` against it.

The `exclude` block in `go.mod` blocks releases that Caddy 2.11.4 cannot compile
against, since an xcaddy build takes the higher of Caddy's and the plugin's
requirements, and it goes away with the next Caddy bump.

## License

Apache 2.0, see `license.txt`. Body selection and verdict handling follow
sigsci-module-golang, whose MIT notice is in `notice.txt`.
