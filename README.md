<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http

[![CI](https://github.com/alganet/lint-http/actions/workflows/ci.yml/badge.svg)](https://github.com/alganet/lint-http/actions/workflows/ci.yml)
[![Citations](https://github.com/alganet/lint-http/actions/workflows/citations.yml/badge.svg)](https://github.com/alganet/lint-http/actions/workflows/citations.yml)
[![License: ISC](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)

**Lint HTTP traffic against the specifications it claims to follow.**

lint-http is a forward proxy for development and testing. Point a command, a
tool or a browser at it and it reads every request and response that crosses,
checks them against the RFCs and web standards that define them, and reports
each finding with the sentence it enforces.

```bash
lint-http use curl https://example.com
```

```
curl through 127.0.0.1:39125 — reporting example.com
CONNECT example.com:443 -> 200 (this proxy's own reply)
  info  proxy_connection_obsolete (induced by this proxy)
        Request carries a Proxy-Connection header field: 'Keep-Alive'. RFC 9112
        Appendix C.2.2 encourages clients not to send it in any request — it was
        an attempted fix for HTTP/1.0 proxies that did not understand
        Connection, and is unworkable because proxies are often deployed in
        multiple layers, which brings the same hung connection back. The section
        states this as advice and not as a requirement
        [RFC 9112 §C.2.2 https://www.rfc-editor.org/rfc/rfc9112.html#appendix-C.2.2]
GET https://example.com/ -> 200
  info  accept_encoding_missing
        Request expresses no content-coding preference (no Accept-Encoding
        header); any coding is acceptable, but most servers will not compress
        without an explicit signal
        [RFC 9110 §12.5.3 https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3]
  info  cache_control_missing
        Response 200 carries neither Cache-Control nor Expires, so every cache
        that stores it may assign a heuristic freshness lifetime of its own
        [RFC 9111 §4.2.2 https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2]
  info  content_type_charset_missing
        Content-Type 'text/html' names no charset, so HTML requires the page
        itself to declare its encoding, with a byte order mark or a `<meta
        charset>` element, which a reader of the header fields cannot see;
        naming it here, as in `text/html; charset=utf-8` for a UTF-8 page,
        declares it without relying on the markup
        [RFC 9110 §8.3.2 https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2]
  info  x_content_type_options_missing
        Response of type 'text/html' carries no `X-Content-Type-Options:
        nosniff`; with it, Fetch §3.6.1 would refuse the response to a script
        load and to a stylesheet load, whose destinations accept only a
        JavaScript MIME type and only `text/css`
        [Fetch §3.6 https://fetch.spec.whatwg.org/#x-content-type-options-header]

5 findings (5 info) in 2 transactions
```

curl ran exactly as typed and printed the page to stdout; the report went to
stderr. Each finding names the defect, the message, and the sentence it rests
on. The labels on the first block are the proxy being honest about itself: the
`CONNECT` was answered by lint-http, and the `Proxy-Connection` header only
exists because curl was talking to a proxy.

## Why lint-http

- **Cited, not opinionated.** Every rule quotes the sentence it enforces, and
  the quote is checked against the published document in CI. A finding says
  what was broken, where that is written, and which side of the exchange is
  answerable for it.
- **Severity follows the keyword.** A broken `MUST` is an error, a `SHOULD` a
  warning, a `MAY` a note. Where no sentence binds the sender, the defect's own
  page argues for the level it carries.
- **Nothing is installed.** `run` and `use` stand up a proxy on an ephemeral
  port with a certificate authority that exists only for that run, then remove
  both.
- **Works with what you already have.** curl, Chromium-family browsers, npm,
  pip, cargo, git, the AWS CLI: `run` exports the proxy and CA variables their
  clients read, and `use` configures a tool the way its own manual says.

## Try it

Build from source with Rust 1.94 or newer:

```bash
git clone https://github.com/alganet/lint-http
cd lint-http
cargo install --path lint-http
```

Then pick the door that fits:

| Command | What it does |
|---|---|
| `lint-http run -- <command>` | Wraps any command. Its HTTP traffic is linted; its stdout and exit code are untouched. |
| `lint-http use curl <url>`<br>`lint-http use browser <url>` | Drives a tool lint-http knows, reading its arguments and configuring it the way that tool documents. |
| `lint-http proxy-start` | Leaves a proxy listening on `127.0.0.1:3000` for anything you point at it. |
| `lint-http lint-captures <file>` | Replays a recorded capture offline and exits non-zero on what it finds. Made for CI. |

A few things worth typing early:

```bash
lint-http run --fail-on error -- pytest              # gate a test suite on broken MUSTs
lint-http use --about server curl https://api.test    # only what the origin is answerable for
lint-http run -v -- curl https://example.com          # rule, spec text, docs page, how to hush it
lint-http rules list                                  # the whole catalogue
lint-http config export > lint-http.toml              # the built-in configuration, ready to edit
```

## What it reads

HTTP/1.1, HTTP/2 and HTTP/3 over QUIC, WebSocket frames, and the TLS handshakes
in front of them. Interception is Rust-native (rustls), so there is no system
OpenSSL to configure. Rules read a request, a response, the pair, or the history
of an origin, so caching, conditional requests, cookies and CORS are judged
across exchanges rather than one message at a time.

Every rule and every defect it can report has a generated page:
[rules](docs/rules.md) · [violations](docs/violations.md).

## Documentation

- [Usage](docs/usage.md): every command, option and report shape, and the
  capture file format.
- [Configuration](docs/configuration.md): the TOML file, and how rules and
  defects are switched and tuned.
- [Development](docs/development.md): the quality gates, and how a rule is
  written and cited.

## A word on safety

lint-http decrypts HTTPS by acting as a certificate authority your client is
told to trust. The CA private key can decrypt anything intercepted with it, so
keep it private; `run` and `use` never write one outside a temporary directory
they delete. The proxy listens on loopback by default and is a development
tool, not something to put in front of production traffic. Vulnerabilities go
to [SECURITY.md](.github/SECURITY.md).

## Contributing and license

Contributions are welcome. [CONTRIBUTING.md](.github/CONTRIBUTING.md) has the
setup and the gates a change is held to. lint-http is released under the
[ISC license](LICENSE).
