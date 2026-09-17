<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# lint-http

⚠️ **Early stage, experimental and incomplete.** ⚠️

**A TLS-terminating HTTP/HTTPS forward proxy that lints traffic and writes captures.** 🔧

lint-http inspects HTTP(S) traffic, runs protocol best-practice checks (rules), and writes detailed JSONL captures for debugging and analysis. It's intended as a development and testing tool — not for production use.

---

## Highlights

- TLS interception using Rust-native stacks (rustls / tokio-rustls / hyper-rustls)
- HTTP/2 and HTTP/1.1 support (via ALPN)
- JSONL traffic captures (`captures.jsonl`) with request/response metadata + timing
- Configurable, stateful lint rules (enable/disable via TOML)
- Easy to use with curl, browsers, and other HTTP clients

## Quick start — lint a command

`run` wraps any command, sends its HTTP traffic through a proxy that exists only
for that run, and reports what the rules found. Nothing to configure, nothing to
install, nothing left behind:

```bash
lint-http run -- curl https://example.com
```

```
<!doctype html>...

GET https://example.com/ -> 200
  info  cache_control_missing
        Response 200 without Cache-Control header
        RFC 9111 §4.2.2
  info  content_type_charset_missing
        Text-based Content-Type header missing charset parameter.
        RFC 9110 §8.3.2

2 findings (2 info) in 1 transaction
```

The finding is named by the **defect** — the name `[violations.*]` tunes and the
one to grep a capture for; `-v` adds the rule that reported it, the
specification text, and the stanza that switches it off. The citation is a
terminal hyperlink, so `RFC 9111 §4.2.2` opens the section. Piped rather than
watched, the same report is one line per finding with the URL spelled out, which
is what it has always been.

It is not curl-specific — the proxy lints whatever crosses it, so `run` works on
anything that reads the usual proxy and CA environment variables:

```bash
lint-http run -- npm install
lint-http run -- pytest tests/integration
lint-http run --fail-on error -- ./my-test-suite
```

The wrapped command keeps stdout and keeps its exit code, so `run` can sit in
front of a command without changing what that command's success means. The
report gets stderr — the wrapped command's own stderr is discarded so the two do
not compete — which means a plain redirect separates them:

```bash
lint-http run -- curl -sS https://example.com > body.html 2> report.txt
```

`--show-child-stderr` hands the child's stderr back; `--fail-on <severity>` is
what makes a finding fail the run; `--only-host <HOST>` / `--all-hosts` decide
which origins the report is about. All four work on `use` too — they are the
options a session takes, not options one command grew.

- `lint-http run --print-env` — the variables a wrapped command receives, and
  which client reads each one.
- `--captures <PATH>` keeps the capture file; by default the run leaves nothing
  on disk, including the CA, which is generated fresh per run and deleted with it.
  It is the same flag `lint-captures` reads, so `run --captures x.jsonl` then
  `lint-captures x.jsonl` replays the same file. Not the same report, though: a
  capture carries no bodies, so the rules that read one are in the run's report
  and not in the replay's.

`--config`, `--format`, `--min-severity` and `--captures` are global: they work
before or after the subcommand, and mean the same thing on each. See
`docs/configuration.md`.

Some clients cannot be reached this way — Go on macOS and Windows, Java, and any
binary with its trust anchors compiled in. The list, with reasons, is in the
module header of `lint-http-proxy/src/client_env.rs`.

## Quick start — drive a tool it knows

`run --` hands a command an environment and hopes it reads it. `use` reads the
tool's own arguments and configures it the way that tool documents:

```bash
lint-http use curl https://api.example.com/orders
lint-http use browser https://example.com
```

```
chromium through 127.0.0.1:34013 — reporting example.com
GET https://example.com/ -> 200
  info  cache_control_missing
        Response 200 without Cache-Control header
        RFC 9111 §4.2.2

▲  3 findings (1 warning, 2 info) in 8 transactions
hidden: 26 on other hosts in 7 transactions (--all-hosts)
```

A session that makes hundreds of requests repeats its findings hundreds of
times. `--group` gives one entry per defect with a count and the targets it
happened on, and `-q` narrows that to a single line each — the defect's
catalogue title and how often it happened:

```
warn  ×26  ALPN protocol name identifies a draft of a shipped protocol
info  ×84  Response 200 without Cache-Control header
```

Reading the command line is worth four things:

- **The tool is configured, not the environment.** `curl --proxy` and `--cacert`
  are two options with no precedence to reason about. In particular an exported
  `NO_PROXY` can no longer take the traffic away from the session and leave a
  report saying zero — curl documents `--noproxy ""` as the override, so `use`
  passes it.
- **The report knows what you aimed at**, so it covers those hosts rather than
  every origin the page or the transfer reached. `--only-host <HOST>` picks the
  scope yourself, `--all-hosts` turns it off, and the last line always counts
  what was left out.
- **Options that would make a finding meaningless are named before a proxy
  starts** — `-k`, `-x`, `--http3-only`, and a `~/.curlrc` that mentions any of
  them.
- **An option it does not recognize is passed through unchanged.** Everything
  after the tool name belongs to the tool; lint-http's own options go before it.

`lint-http use browser` is what `browse` used to be: a throwaway profile, a CA
trusted for one launch by public-key pin rather than added to any trust store,
and findings printed as the page loads. Nothing is installed, so closing the
browser is the end of it. Chromium-family only (`chromium`, `chrome`, `brave`,
`edge`, or a path); Firefox needs its CA in an NSS database, which has no
per-launch equivalent — see the header of `lint-http-proxy/src/browser.rs`.

Anything without a driver still goes through `run --`, and the error says so.

## Quick start — a proxy you point things at

For a session rather than a command, `proxy-start` runs the proxy and leaves it
listening:

```bash
lint-http proxy-start                          # built-in configuration
lint-http proxy-start --config config.toml     # or your own
```

```bash
# use the proxy (default configuration listens on 127.0.0.1:3000)
curl -x http://localhost:3000 http://example.com

# for HTTPS, trust the CA it generated
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt
curl -x http://localhost:3000 --cacert lint-http-ca.crt https://example.com
```

Watch traffic live (set `general.live_stream_enabled = true` in the config):

```bash
# Server-Sent Events feed of each transaction as it commits
curl -N http://localhost:3000/_lint_http/stream
```

Note: the proxy uses rustls; no system OpenSSL dependency is required for basic
operation.

## Configuration

Every command runs with a built-in configuration when you give it no `--config`
— the one in `config_example.toml`, compiled into the binary, with the whole rule
catalogue enabled. To change something, export it and edit:

```bash
lint-http config export > config.toml
lint-http proxy-start --config config.toml
```

`config export` emits exactly the bytes the binary would otherwise have run, so
an exported file you have not edited changes nothing.

Refer to `docs/configuration.md` for full options, including TLS settings and rule configuration.

## Browse the rule catalogue

List every rule and its metadata — no proxy or config needed:

```bash
lint-http rules list                 # human-readable: id, scope, title
lint-http rules list --format json   # full metadata (description, spec refs) for tooling
```

The per-rule pages under `docs/rules/` are generated from that same metadata, and
the per-defect pages under `docs/violations/` from the catalogue of defects those
rules report. Regenerating them is a repository task rather than something the
binary does — see `docs/development.md`.

## Lint recorded captures (CI)

Lint a JSONL capture file offline — no live proxy needed. It replays the
recorded transactions through the rules and exits non-zero when any violations
are found, so it drops straight into CI:

```bash
lint-http lint-captures captures.jsonl
lint-http lint-captures --config config.toml captures.jsonl
```

Example snippet:

```toml
[general]
listen = "127.0.0.1:3000"
captures = "captures.jsonl"
ttl_seconds = 300

[tls]
enabled = true
```

## Lint rules

Rules cover common client and server best practices (e.g., `User-Agent` presence, `Cache-Control`, `ETag`, connection reuse). Rules are documented in `docs/rules/` and listed in `docs/rules.md`.

A rule is the unit of analysis; a **violation** is the unit of report — one named defect a rule may find, and the name a finding carries after the rule's own (`rule/defect`). Each has a page under `docs/violations/`, listed in `docs/violations.md`, naming the sentences it enforces, the `[violations.<id>]` table that tunes it, and every rule that reports it.

## Capture format

Captures are written as JSON Lines; each line is an `HttpTransaction` JSON object containing:
- unique `id`, `timestamp`
- `client` metadata (ip, user-agent)
- `request` (method, uri, headers)
- `response` (status, headers)
- `timing` (duration)
- `violations` (rule id, severity, message)

Example (abbreviated):

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-11-30T10:30:00Z",
  "client": { "ip": "127.0.0.1", "user_agent": "test-client" },
  "request": {
    "method": "GET",
    "uri": "https://example.com/api/data",
    "headers": { ... }
  },
  "response": {
    "status": 200,
    "headers": { ... }
  },
  "timing": { "duration_ms": 145 },
  "violations": [
    {
      "rule": "cache_control_present",
      "severity": "warn",
      "message": "Response is missing Cache-Control header"
    }
  ]
}
```

## Development

The CI gates are mirrored locally with [`just`](https://just.systems). Run bare
`just` to list recipes:

```bash
just check          # everything CI rejects a PR for: fmt, citations, lint, test, quotes
just fmt            # format the whole tree, including the rule modules cargo fmt can't reach
just gendocs        # regenerate docs/rules/ and docs/violations/ with their indexes
just install-hooks  # enable the pre-commit guard (fmt + citations, once per clone)
```

`cargo fmt` does not reach the rule modules — they enter the crate through a
`build.rs`-generated `#[path]` include that rustfmt won't follow — so `just fmt`
formats them directly, and the pre-commit hook (in `.githooks/`) blocks a commit
that would fail the CI fmt or citation gate. Bypass it once with
`git commit --no-verify`.

`just quotes` is the one gate in `check` that opens the documents — it asks
whether every `// cite(…)` still says what the source says, which nothing else
can: a quote written from memory compiles, formats and passes the citation gate
like any other string. It is also the slowest and the only one that touches the
network, which is why the pre-commit hook does not run it.

Individual gates are also available directly: `cargo test`, `cargo lint`, and
`cargo coverage` (the last two are aliases in `.cargo/config.toml`).

## Security notice

lint-http is a debugging tool — do not use in production.
- The CA private key can decrypt intercepted HTTPS traffic; keep it private
- Only use on trusted networks and machines

## Contributing & license

Contributions are welcome — see `.github/CONTRIBUTING.md` for guidelines. The project is licensed under the ISC license (see `LICENSE`).
