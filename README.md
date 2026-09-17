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
  info  cache_control_present/cache_control_missing  Response 200 without Cache-Control header  [RFC 9111 §4.2.2 ...]
  info  charset_present/content_type_charset_missing  Text-based Content-Type header missing charset parameter.  [RFC 9110 §8.3.2 ...]

2 violation(s) in 1 transaction(s)
```

It is not curl-specific — the proxy lints whatever crosses it, so `run` works on
anything that reads the usual proxy and CA environment variables:

```bash
lint-http run -- npm install
lint-http run -- pytest tests/integration
lint-http run --fail-on error -- ./my-test-suite
```

The wrapped command keeps stdout and keeps its exit code, so `run` can sit in
front of a command without changing what that command's success means. The
report goes to stderr; `--fail-on <severity>` is what makes a finding fail the
run instead.

- `lint-http run --print-env` — the variables a wrapped command receives, and
  which client reads each one.
- `--captures <PATH>` keeps the capture file; by default the run leaves nothing
  on disk, including the CA, which is generated fresh per run and deleted with it.

Some clients cannot be reached this way — Go on macOS and Windows, Java, and any
binary with its trust anchors compiled in. The list, with reasons, is in the
module header of `lint-http-proxy/src/client_env.rs`.

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
