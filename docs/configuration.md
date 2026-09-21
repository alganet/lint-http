<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Configuration

`lint-http` is configured by a TOML file, and every command may be given none.
Without `--config`, it runs the configuration compiled into the binary: the
whole rule catalogue enabled, with `[general]` and `[tls]` set to values that
work unattended. That built-in is `config_example.toml` in the repository, byte
for byte, and `lint-http config export` prints it:

```bash
lint-http config export > lint-http.toml
lint-http proxy-start --config lint-http.toml
```

A named config **replaces** the built-in rather than layering over it. Rules are
off unless a config names them, so a file listing three rules enables three
rules; export and edit if you want the catalogue minus a few. `[general]` and
`[tls]` are optional: every key in both has a default, so a file may hold
nothing but a `[rules]` table.

The file has four sections: `[general]` (the proxy), `[tls]` (interception),
`[rules]` (which analyses run) and `[violations]` (how each defect reports).

## `[general]`

```toml
[general]
listen = "127.0.0.1:3000"          # address to listen on
captures = "captures.jsonl"        # capture file, appended to
ttl_seconds = 300                  # how long stateful records live
max_history = 10                   # transactions kept per client and resource
max_protocol_event_history = 200   # protocol events kept per connection or session
captures_seed = false              # seed state from the capture file on startup
captures_include_body = false      # write bodies into the capture file (base64)
captures_max_body_bytes = 1048576  # bytes of each body kept for rules and the capture
max_body_bytes = 67108864          # the one body still buffered whole: a WebSocket handshake
max_connections = 1024             # simultaneous live TCP connections
shutdown_timeout_seconds = 30      # seconds to drain in-flight handlers on Ctrl-C
live_stream_enabled = false        # serve the live SSE feed at /_lint_http/stream
```

- **listen**: the address and port the proxy binds. Loopback by default; the
  proxy decrypts what crosses it, so widen this only on a network you trust.
- **captures**: where transaction records are appended, as JSON Lines. The
  `--captures` flag overrides it. The format is described under
  [Usage](usage.md#capture-file-format).
- **ttl_seconds**: how long records stay in the state store stateful rules read.
- **max_history**: how many transactions the store keeps for each client and
  resource pair, which bounds how far back a rule can look.
- **max_protocol_event_history**: the same bound for protocol events, per
  connection or session. WebSocket frame-sequencing rules may need a longer
  window than transactions do.
- **captures_seed**: when `true`, the proxy loads the existing capture file on
  startup and seeds the state store from it, so stateful rules continue from a
  previous session, and a hand-written capture can stage an elaborate prior
  state.
- **captures_include_body**: bodies are always captured in memory for the rules;
  this decides whether they are also written to the file, base64-encoded.
- **captures_max_body_bytes**: how much of each body is kept for the rules and
  the capture file. Bodies are forwarded in full regardless; a longer one is
  kept as a prefix and the record marks `request_body_over_limit` or
  `response_body_over_limit`, while `body_length` still records the real size.
  Rules that need a whole body decline to judge a truncated one.
- **max_body_bytes**: the cap on the one body still buffered fully in memory,
  the WebSocket upgrade handshake request, which must be replayed upstream as a
  single buffer. An over-limit handshake is rejected with `413`. HTTP/1.1,
  HTTP/2 and HTTP/3 bodies stream through and are not bounded by this.
- **max_connections**: further connections wait for a slot rather than being
  accepted unboundedly, so a burst cannot exhaust the process.
- **shutdown_timeout_seconds**: on graceful shutdown, how long to wait for
  in-flight handlers before exiting anyway. The capture file is flushed and
  synced as part of shutdown, so the last records are never truncated.
- **live_stream_enabled**: when `true`, `GET /_lint_http/stream` on the proxy
  port is a [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
  feed of each transaction as it commits, in the same JSON shape as a capture
  line. It shows every proxied transaction to anyone who can reach the port,
  so it is off by default and the endpoint answers `404`. Reachable over
  HTTP/1.1 and HTTP/2, not HTTP/3.

### HTTP/3 listener

```toml
[general]
h3_listen = "127.0.0.1:3443"       # QUIC address to accept HTTP/3 clients on; off when omitted
h3_server_name = "localhost"       # SNI name the HTTP/3 certificate is issued for
```

When `h3_listen` is set, a QUIC endpoint speaking HTTP/3 is started beside the
TCP listener. It requires TLS to be enabled, and clients must connect using the
name in `h3_server_name`, which defaults to `localhost`.

### HTTP/3 upstream

By default the proxy forwards to origins over HTTP/1.1 or HTTP/2. It can also
forward the *proxy to origin* leg over HTTP/3, so that leg is exercised and
linted like any other traffic. Selection is capability-driven: HTTP/3 is used
for an origin that is on the allowlist or was discovered through `Alt-Svc`, and
the proxy falls back to HTTP/1.1 or HTTP/2 when HTTP/3 is unavailable. All of
these keys live in `[general]` and none has an effect until the first is `true`.

```toml
[general]
h3_upstream_enabled = false                       # master switch
h3_upstream_authorities = ["origin.example:443"]  # origins always tried over HTTP/3
h3_upstream_denylist = ["legacy.example:443"]     # origins never tried over HTTP/3
h3_upstream_trust_alt_svc = true                  # learn HTTP/3 endpoints from Alt-Svc
h3_upstream_bind = "[::]:0"                       # UDP address the QUIC client binds
h3_upstream_extra_ca_certs = []                   # extra CA PEM files to trust for origins
h3_upstream_connect_timeout_ms = 5000             # connect and handshake budget
h3_upstream_response_timeout_ms = 30000           # budget for the response head
h3_upstream_negative_ttl_seconds = 30             # backoff after a failed attempt
h3_upstream_pool_idle_ms = 25000                  # idle time before a pooled connection is dropped
h3_upstream_pool_max = 256                        # pooled connections, one per origin
```

- **h3_upstream_authorities**: `host[:port]`, port defaulting to `443`, matched
  case-insensitively. This pre-seeds selection: the first request to an origin
  cannot have learned `Alt-Svc` yet, so without an entry here HTTP/3 begins on
  the second connection.
- **h3_upstream_denylist**: the same shape, and it wins over both the allowlist
  and discovery.
- **h3_upstream_trust_alt_svc**: an origin's `Alt-Svc: h3=...` adds a route at
  runtime, honouring `ma` and `clear`. A discovered endpoint is used only once
  its certificate validates for the origin authority (RFC 7838 §2.1); a mismatch
  fails the handshake and the proxy falls back. `false` routes HTTP/3 from the
  allowlist alone.
- **h3_upstream_bind**: the IPv6 wildcard by default, which quinn makes
  dual-stack, so origins of either family are reachable. A host without IPv6
  falls back to `0.0.0.0:0`; pinning an IPv4 address here makes IPv6-only
  origins fall back to HTTP/1.1 or HTTP/2.
- **h3_upstream_extra_ca_certs**: private CAs trusted for origin certificates,
  layered on the system roots.
- **h3_upstream_connect_timeout_ms** and **h3_upstream_response_timeout_ms**:
  the first bounds QUIC connect and handshake, the second bounds origin think
  time and is deliberately far more generous. An idempotent, bodyless request
  that hits the second is retried over HTTP/1.1 or HTTP/2 (RFC 9110 §9.2.2);
  anything else answers `502`.
- **h3_upstream_negative_ttl_seconds**: after a connect or handshake failure an
  origin is not retried over HTTP/3 for this window, doubling per consecutive
  failure. A successful exchange clears it. A response-head timeout does not
  negative-cache, because that origin is healthy, just slow.
- **h3_upstream_pool_idle_ms** and **h3_upstream_pool_max**: pooled connections
  are evicted when idle past the first, and least-recently-used past the second.

Which leg served each request is in the capture: `response.version` is
`HTTP/3.0` when the origin leg used HTTP/3.

## `[tls]`

```toml
[tls]
enabled = true                    # intercept HTTPS; false tunnels it opaque
ca_cert_path = "ca.crt"           # CA certificate, generated if missing
ca_key_path = "ca.key"            # CA private key, generated if missing
passthrough_domains = []          # domains tunnelled without interception
suppress_headers = []             # request headers removed before forwarding
```

- **enabled**: `true` intercepts HTTPS with certificates minted under the CA;
  `false` tunnels HTTPS opaque, so only the `CONNECT` is seen. A file that omits
  `[tls]` entirely behaves as `true`, like the built-in.
- **ca_cert_path** and **ca_key_path**: generated on first use when the files
  do not exist, relative to the working directory. The key is written with
  owner-only permissions on Unix. **It can decrypt anything intercepted with
  it: keep it private.** `run` and `use` ignore these and generate a CA in a
  temporary directory they delete.
- **passthrough_domains**: hosts whose TLS is never intercepted, tunnelled
  opaque instead (`["bank.example"]`).
- **suppress_headers**: request header names removed before the request is
  forwarded upstream (`["Authorization"]` keeps a credential off the wire while
  testing). The rules still see the header the client sent; suppression changes
  what the origin receives, and therefore its response, not the linting of the
  request.

## `[rules]`

A rule is the unit of analysis. Each is off unless its table says otherwise,
and `enabled` is the one key every table must carry:

```toml
[rules.cache_control_present]
enabled = true
```

Some rules take options of their own, and require them: a rule with a `paths`
list has no default list, so its table without one is refused at startup by
rule name. Each rule's page under [`rules/`](rules.md) shows its example table,
and `config export` prints every one.

```toml
[rules.clear_site_data_present]
enabled = true
paths = ["/logout", "/signout", "/auth/logout", "/api/v1/logout"]
```

Two things are refused at startup rather than ignored. A table naming a rule id
that does not exist is an error: ids are never aliased, and the message points
at the rule index. A `severity` key in a rule table is an error too, with a
message naming the section below: severity belongs to the defect a rule reports,
not to the rule, because a rule that checks four things would otherwise say one
thing about all four.

## `[violations]`

A *violation* is the unit of report: one named defect a rule may find, the name
a finding carries after the rule's own (`rule/defect`), and the name this
section tunes. A rule that checks four things reports four violations, and each
is tuned separately here.

Every violation carries a default severity and reports unless told otherwise,
so this section is optional and mostly stays empty: write a table only to
disagree with a default.

```toml
# The rule is on...
[rules.strict_transport_security_valid]
enabled = true

# ...this one defect it reports is an error, where the rest keep whatever
# the catalogue gives them...
[violations.strict_transport_security_max_age_missing]
severity = "error"

# ...and this one is not reported at all.
[violations.strict_transport_security_directive_duplicated]
enabled = false
```

`severity` and `enabled` are the only keys, and a table that is written must set
at least one of them. A table naming an id that does not exist is refused, the
same way an unknown rule id is. Every id and its default is listed in
`config_example.toml` and indexed in [`violations.md`](violations.md), where each
page names the sentences the defect enforces and the rules that report it.

**The default severity is derived, not chosen.** A defect states what the
specification sentence it enforces obliges of the *sender* of the message it is
in, and the level follows: a `MUST` is `error`, a `SHOULD` is `warn`, a `MAY` is
`info`, and an ABNF production is `error` because RFC 9110 §2.2 obliges every
sender not to break one. So `--fail-on error` means "a sentence addressed to you
was broken", which is a line a CI policy can hold. About half the catalogue
states nothing, because no sentence obliges the sender or because the keyword
binds the recipient; those levels are the catalogue's judgement, and each page
argues for its own under **Obligation**. A finding carries the reading as
`strength` in JSON when it is not unstated.

`enabled = false` drops that defect's findings and leaves the rule's other
defects reporting. It does not bring a *different* defect of the same rule into
view on a transaction where the switched-off one fired: most rules report their
first finding and stop, and that truncation was there before anything was
switched off.

Turning a whole rule down therefore means one table per defect it reports,
which its page lists. To quiet a rule wholesale, `[rules.<id>] enabled = false`
switches it off, and `--min-severity` still filters the report.
