# Caddy SigSci

Caddy HTTP handler for the Fastly Next-Gen WAF agent, formerly the Signal
Sciences agent. Like the official nginx, Apache and Go modules, it sends each
request to a local `sigsci-agent` over the module RPC socket, enforces the
verdict and reports the response, using the RPC client of
[sigsci-module-golang](https://github.com/signalsciences/sigsci-module-golang).

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
    skip_unknown_content_length      # do not buffer bodies of unknown length
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

- The directive runs after `header`, `request_body` and `timeouts`, so deferred
  `header` ops land on blocked responses and body limits apply before
  inspection. A custom `order` must keep it after `timeouts`.
- The agent allows with 200 and blocks with any status from 300 to 599,
  redirecting a 3xx that carries `X-Sigsci-Redirect`.
- The next handler receives `X-Sigsci-Requestid`, `X-Sigsci-Agentresponse` and
  `X-Sigsci-Tags` in place of any the client sent, and
  `{http.vars.sigsci.request_id}`, `{http.vars.sigsci.agent_response}` and
  `{http.vars.sigsci.tags}` are set for later directives and `log`.
- An unreachable or slow agent fails open, without these headers and variables.
  A warning marks each outage and an info line its end, and the global `debug`
  option logs every verdict.
- The agent sees Caddy's `client_ip`, resolved through `trusted_proxies`.
- Bodies are buffered for inspection and replayed, with or without a
  Content-Length, when the Content-Type is absent, a list, or form, multipart,
  json, javascript, xml, grpc or graphql. CONNECT tunnels, such as WebSockets
  over HTTP/2 or HTTP/3, are never buffered. The `max_size` of `request_body`
  and the server's `read_body_idle` timeout bound the read, and a
  `max_content_length` of 0 turns body inspection off.
- A handler error is reported with its status, a size of zero and the headers at
  that point, which already carry the agent's header actions, since Caddy runs
  `handle_errors` after the middleware returns. A request cut off by `abort` or
  a failed proxy stream is reported as well, as 444 when nothing was sent.
- The module announces itself as `sigsci-module-golang <version>-caddy`, a type
  the console recognizes, as Fastly's Traefik plugin does, and the server as
  `caddy <version>`.

## Development

`make agent` runs a fake agent on `127.0.0.1:9999` that blocks anything
mentioning `attack`, `make build` builds Caddy with the plugin from the working
tree and `make run` serves the example `caddyfile` against it.

## License

Apache 2.0, see `license.txt`. Body selection and verdict handling follow
sigsci-module-golang, whose MIT notice is in `notice.txt`.
