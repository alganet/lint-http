<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Usage

`lint-http` is one binary with six commands. Four of them put traffic through
the proxy or replay traffic that already did; two inspect the tool itself.

| Command | What it does |
|---|---|
| `run [OPTIONS] -- <COMMAND>...` | Runs a command with its HTTP traffic proxied and linted. The most common entry point; nothing needs configuring. |
| `use [OPTIONS] <TOOL> [ARGS]...` | Drives a tool lint-http knows how to configure (`curl`, or a Chromium-family browser), reading its own arguments and configuring it the way that tool documents. |
| `proxy-start` | Starts the intercepting proxy and leaves it listening. |
| `lint-captures [CAPTURES]` | Lints a recorded capture file offline and exits non-zero on findings. |
| `rules list` | Lists every rule and its metadata. No config or proxy needed. |
| `config export` | Prints the built-in configuration, ready to edit and pass back with `--config`. |

`-h`/`--help` works on the binary and on every command; `-V`/`--version` prints
the version.

## Global options

These mean the same thing wherever they appear and may be given before or after
the command: `lint-http --config c.toml run -- curl` and
`lint-http run --config c.toml -- curl` are the same command line.

| Option | Meaning |
|---|---|
| `--config <PATH>` | Config TOML. Omitted, the built-in configuration is used. See [Configuration](configuration.md). |
| `--format <text\|json>` | Report format. Default `text`. |
| `--min-severity <info\|warn\|error>` | Only report findings at or above this. Default `info`. |
| `--about <client\|server\|any>` | Only report findings the named peer is answerable for. Default `any`. A finding no rule has attributed yet is kept whichever peer is named, and counted on its own line. |
| `--captures <PATH>` | The JSONL capture file this command reads or writes. |
| `-q`, `--quiet` | One line per defect: its catalogue title and how often it happened. |
| `-v`, `--verbose` | Everything a finding knows: the rule, the specification reference in full, the docs page, and how to switch it off. |
| `--group` | One entry per defect, with a count and the targets it happened on, instead of one entry per transaction. |
| `--color <auto\|always\|never>` | Whether to colour the report. Default `auto`. |
| `--width <COLUMNS>` | Wrap the report at this column. |

### How a report is drawn

**A report going to a pipe is one line per finding**, no colour, the citation
spelled out in brackets with its URL. The only reader there is another program,
and nothing below changes that.

A report going to a *terminal* is drawn for a person:

- **Colour.** Severity is the only thing given a hue (`error` bold red, `warn`
  yellow, `info` blue) plus the response status, whose first digit already is
  one. Names are bold, counts and hints are dim, and the message itself is never
  coloured. `--color never`, `NO_COLOR` and `TERM=dumb` each switch it off;
  `--color always` and `CLICOLOR_FORCE` switch it on into a pipe.
- **Wrapping.** The defect takes its own line and the message is indented under
  it. There is no terminal width probe; the column is *stated*: `--width` if
  given, then `COLUMNS` if the shell exported it, then 100.
- **A compact citation.** `RFC 9110 §12.5.3` rather than that plus the URL,
  because under colour the label carries the URL as a terminal hyperlink (OSC 8)
  and is one click from the section. Where there is no hyperlink the URL is
  printed, so a report in a file never loses the address of the sentence it
  enforces. `-v` prints it either way.

Two labels appear on findings about the proxy's own presence. **`(this proxy's
own reply)`** marks a transaction lint-http answered itself, such as the `200` to
a `CONNECT`. **`(induced by this proxy)`** marks a finding that exists only
because the traffic went through a proxy, such as a `Proxy-Connection` header a
client sends to proxies alone. Both are still findings about what the client
did; the label says why a capture taken without a proxy would not show them.

`--group` collapses findings that read identically into one entry with a count
and the targets it happened on. Nothing is dropped and the total is unchanged;
the key is the whole rendered identity, so a parameterised message naming two
different values stays two entries.

### Diagnostics

Anything that is not the report goes to stderr as a log line, and `RUST_LOG`
selects how much of it you hear (`RUST_LOG=debug` shows HTTP/3 selection,
connection reuse and fallbacks per request). Unset, `run`, `use` and
`lint-captures` print warnings only, so the report is the first thing you read;
`proxy-start` also says where it is listening and where its CA lives.
`rules list` and `config export` print nothing but their output.

### The capture file is one flag

`--captures` is one file under one name across the surface: `run`, `use` and
`proxy-start` **write** it, `lint-captures` **reads** it. What a run keeps is
what a later lint replays:

```bash
lint-http run --captures run.jsonl -- pytest
lint-http lint-captures --captures run.jsonl      # same file, same flag
lint-http lint-captures run.jsonl                 # or as the positional
```

For `run` and `use`, `--captures` is also what makes the capture survive at all:
without it they discard theirs. For `proxy-start` it overrides the
`general.captures` path in the config.

`use` also turns on `general.captures_include_body` when the tool was asked to
send a body (`curl -d`, `-F`, `-T`, `--json`) *and* `--captures` named a file to
keep. That changes what the file records, not what the report says.

## Session options

`run` and `use` both stand a proxy up for a child process, and they take the
same four options for it.

| Option | Meaning |
|---|---|
| `--fail-on <info\|warn\|error>` | Exit non-zero when a finding **in the report** reaches this severity. Findings `--min-severity` filtered out cannot trip it. Without it, the exit code is the child's. |
| `--only-host <HOST>` | Report findings for this host and anything under it. Repeatable. |
| `--all-hosts` | Report every host, including third parties the target pulls in. |
| `--show-child-stderr` | Let the child's stderr through. Off by default, so the report has stderr to itself. |

Without either scoping flag, the report covers the hosts of whatever the session
was pointed at: every URL the driver could read off the tool's own command line.
`run --` is tool-blind and knows no target, so it reports every origin the child
reached.

`--min-severity` decides what the report contains; `--fail-on` decides what the
exit code means. With `--fail-on`, a clean child that produced findings at or
above that severity exits 1, and a child that failed keeps its own code.

## `run`: wrap a command

```bash
lint-http run -- curl https://example.com
lint-http run --min-severity warn -- npm install
lint-http run --fail-on error --captures run.jsonl -- pytest
lint-http run -- curl -sS https://example.com > body.html 2> report.txt
```

`run` binds a proxy on an ephemeral port, generates a CA into a temporary
directory, puts both into the child's environment, runs it, and reports what
crossed. When it ends the directory and the CA inside it are removed; only
`--captures` leaves anything behind.

- **The report goes to stderr, and the wrapped command's stderr is discarded.**
  Stdout is untouched, since it is the wrapped command's real output, so the two
  separate with a plain redirect as in the last example above. This does hide
  progress output from tools that write it to stderr (`npm`, `pytest`);
  `--show-child-stderr` is the way back.
- **The report is what the proxy found, not a second pass over the capture.**
  The rules ran on each transaction as it crossed, with its body in hand, and
  the report reads those findings back. A replay through `lint-captures` cannot
  see bodies, so the two reports can differ, and the live one is canonical.
- **`--about` narrows the report to one end of the exchange.** `--about server`
  drops the findings your client is answerable for; `--about client` drops the
  origin's. A finding no rule has attributed yet is kept under either and
  counted on an `unattributed:` line, because hiding it would turn an unread
  rule into a green build.
- **`--print-env`** lists the variables a wrapped command receives, and which
  client reads each one, without running anything.

The variables and the clients that read them are a table in
`lint-http/src/client_env.rs`, where each row quotes the documentation that
defines it. The same module header lists what no variable can reach: Go on macOS
and Windows, Java, any binary with its trust anchors compiled in, and anything
that pins a certificate. A pre-set `NO_PROXY` that already excludes the target
is left alone too, so a broad one set elsewhere in your environment can keep
traffic away from the proxy; `use curl` is the answer to that one.

## `use`: drive a tool it knows

```bash
lint-http use curl https://api.example.com/orders
lint-http use curl -d @order.json -H 'Content-Type: application/json' https://api/orders
lint-http use browser https://example.com
lint-http use --only-host example.com --only-host api.example.com browser https://example.com
lint-http use --all-hosts --format json browser https://example.com > findings.json
```

`run --` hands a command an environment and hopes it reads it. `use` reads the
tool's own arguments and configures it the way that tool's manual says to.
**lint-http's own options go before the tool.** Everything after the tool name
belongs to the tool and is passed through byte-identical, which is what makes an
unrecognized flag safe to type.

A driver answers five things about one tool:

- **Which executable.** A name on `PATH` or a path is taken as given; otherwise
  the driver searches. `use browser` finds whichever Chromium-family browser is
  installed.
- **What the invocation asked for.** A request body makes a kept capture record
  it.
- **Where it is aimed.** Every URL on the command line becomes the default host
  scope, so the report is about the site under test rather than about every
  origin it reached.
- **What would make the report a lie**, said *before* a proxy is stood up. A
  warning lets the session run and says which part of its report will not mean
  what it says; a refusal stops it.
- **How to say it.** `curl --proxy` and `--cacert`; a browser's `--proxy-server`
  and `--ignore-certificate-errors-spki-list`.

Anything without a driver still goes through `run --`, and the error says so.

### curl

| Detected | What it does |
|---|---|
| `-k`, `--insecure` | Warns: verification is off, so nothing the session says about TLS means anything. |
| `-x`, `--proxy` | Refuses: curl would go somewhere else and there would be nothing to report. |
| `--noproxy <list>` | Warns: the hosts it names are reached without a proxy and are not in the report. |
| `--preproxy` | Warns: a SOCKS hop in front of the session; a failure through it looks like a quiet session. |
| `--http3` | Warns: the session binds no QUIC listener, so the transfer falls back and the report is about the version it fell back to. |
| `--http3-only` | Refuses: no fallback, and nothing here to speak it to. |
| `--cacert` | Warns: replaces the session's trust bundle, so HTTPS through the proxy will not verify. |
| a default `~/.curlrc` naming any of the above | Warns, and names the file. |

The session passes `--noproxy ""` unless the invocation named its own list. An
exported `NO_PROXY` otherwise keeps curl away from the proxy, the session
records nothing, and the report says zero findings, indistinguishable from a
clean transfer. curl documents the empty list as the override for exactly that
variable.

It does not neutralize `~/.curlrc`: curl reads that file whatever is on the
command line, and its manual states no precedence between the two, so `use`
looks and says what it found. `curl -q` as the first argument is curl's own way
to ignore the file, and it is passed through where it was written.

### Browsers

`lint-http use browser [URL]`, or `chromium`, `chrome`, `brave`, `edge`, or a
path, launches a browser with a throwaway profile, pointed at an ephemeral
proxy, trusting the session CA by public-key pin.

- **Findings print as they happen**, because a browsing session lasts as long as
  someone keeps it open. `--format json` opts back into one report at the end.
- **Findings are scoped** to the URL's host and anything under it; everything
  else is counted on the last line. With the whole catalogue enabled, an
  unscoped session on a real page buries its own findings under a third-party
  CDN's.
- **Nothing is installed.** The CA is trusted through
  `--ignore-certificate-errors-spki-list`, which pins one public key for one
  launch. Verification stays on, so the session can still judge TLS. Passing
  `--ignore-certificate-errors` yourself is warned about; `--proxy-server` is
  refused.
- **Loopback is not bypassed.** Chromium skips the proxy for `localhost` by
  default, which would make a session on `http://localhost:3000` load perfectly
  and report nothing.
- **Chromium-family only.** Firefox verifies through its own NSS database and
  has no per-launch pin; the header of `lint-http/src/browser.rs` says
  what it would take.

## `proxy-start`: a proxy you point things at

```bash
lint-http proxy-start                          # built-in configuration
lint-http proxy-start --config config.toml     # or your own
```

The built-in configuration listens on `127.0.0.1:3000`, intercepts TLS, and
appends captures to `captures.jsonl` in the working directory. The CA it
generates lands beside it as `ca.crt` and `ca.key` unless the config says
otherwise.

```bash
# plain HTTP
curl -x http://localhost:3000 http://example.com

# HTTPS: trust the CA the proxy generated
curl http://localhost:3000/_lint_http/cert > lint-http-ca.crt
curl -x http://localhost:3000 --cacert lint-http-ca.crt https://example.com

# watch transactions live (needs general.live_stream_enabled = true)
curl -N http://localhost:3000/_lint_http/stream
```

The two `/_lint_http/` paths are answered by the proxy itself. The stream is a
Server-Sent Events feed of each transaction as it commits, in the same JSON
shape as a capture line; it is off by default because it shows every proxied
transaction to anyone who can reach the port.

Findings are written onto each capture record as it is linted. Read them back
with `lint-captures`, or watch them on the stream.

## `lint-captures`: lint a recording

```bash
lint-http lint-captures captures.jsonl
lint-http lint-captures --config config.toml --min-severity error captures.jsonl
```

Replays a capture file through the rule engine without running a proxy: the CI
story, for HTTP fixtures recorded earlier. Records are replayed in file order,
and each transaction is linted against the history of the ones before it, so
stateful rules work. WebSocket sessions are replayed per message through the
protocol rules. Protocol events are the exception and report the findings the
record already carries: a protocol rule reads a run of frames through the store
the live connection built, and a capture holds the frames without it.

**A replay is not a live pass.** Bodies are not written to a capture, so the
rules that read one cannot fire here; where the two disagree, the live pass
`run` and `use` report from is canonical.

The exit code is the signal for CI:

- **0**: no findings.
- **1**: findings, or an error (a missing file, a file no record could be read
  from, a malformed config).

The `--config` file is the same TOML `proxy-start` reads. `lint-captures` uses
the `[rules]` toggles, the `[violations]` overrides, and `general.ttl_seconds`
and `general.max_history` to size the replay's history window; `listen`,
`captures` and `[tls]` are ignored.

### What the report could not read

A capture line that does not parse as a record is skipped, and the report says
how many were, on a line of its own:

```
✔  no findings in 1 transaction
unread: 3 of 4 capture records could not be parsed
```

Read the share rather than the count: one line lost out of nine hundred is a
torn file; one out of one is a report of nothing. Why each line was skipped goes
to stderr, one `WARN` per record with the line number and the reason. The common
reason for a file this tool did not write is a control octet in a field value,
which no field-value grammar admits; such a record is refused whole rather than
read without the field.

**A file that yielded no records at all is an error**, not a report of nothing:
a capture written by a broken producer, or a path pointing at some other JSONL,
would otherwise pass a CI gate green. A file with no lines at all is still a
capture of nothing, and reported as one.

### JSON output

`--format json` emits one object, and `run` and `use` write the same document
under `--format json`, so one reader serves all three:

```json
{
  "records_read": 2,
  "records_unread": 0,
  "findings": [
    {
      "kind": "http_transaction",
      "method": "GET",
      "uri": "https://example.com/",
      "status": 200,
      "violations": [
        {
          "rule": "cache_control_present",
          "violation": "cache_control_missing",
          "severity": "info",
          "message": "Response 200 carries neither Cache-Control nor Expires, so every cache that stores it may assign a heuristic freshness lifetime of its own",
          "cite": {
            "spec": "RFC 9111",
            "section": "4.2.2",
            "url": "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2"
          },
          "party": "server"
        }
      ]
    }
  ]
}
```

`records_read` and `records_unread` are there because a reader cannot recover
them from the array: an unreadable line leaves nothing behind to count. Each
entry in `findings` is tagged by `kind`: an `http_transaction` carries `method`,
`uri`, `status` (`null` when the transaction got no response) and
`answered_by_this_proxy` when it did not reach an origin; a
`websocket_session` carries `session_id`, `transaction_id` and `close_code`; a
`protocol_event` carries `connection_id` and `event`, the frame's name. All
three carry `violations`, each with `rule`, `severity`, `message`, and, when
the rule named what it found, `violation` (the id `[violations.<id>]` tunes),
`cite`, `party`, `proxy_induced` and `strength`.

## `rules list` and `config export`

```bash
lint-http rules list                        # id, party, title
lint-http rules list --format json          # description, specifications, examples
lint-http rules list --config c.toml        # each rule annotated enabled/disabled under that config
lint-http config export > lint-http.toml    # the built-in configuration, byte for byte
```

The generated pages under `docs/rules/` and `docs/violations/` are rendered from
the same metadata `rules list --format json` prints.

## Capture file format

A capture is JSON Lines: one record per line, appended as each transaction
commits, each tagged with its `type` and a `schema_version`. Most records are
HTTP transactions; a WebSocket relay also writes a session record. A transaction
with its header lists shortened:

```json
{
  "type": "http_transaction",
  "schema_version": 1,
  "id": "915600b0-d273-4d70-97ab-ae4b40f9d3ec",
  "timestamp": "2026-09-20T23:14:12.057336821Z",
  "session": "309d9873-4b52-4c26-b354-cdf6a4ad44f9",
  "connection_id": "50b0ec3f-cec1-4bd5-8a6b-3ff4a7d78cfa",
  "sequence_number": 1,
  "client": { "ip": "127.0.0.1", "user_agent": "curl/8.5.0" },
  "request": {
    "method": "GET",
    "uri": "https://example.com/",
    "version": "HTTP/2.0",
    "headers": [["user-agent", "curl/8.5.0"], ["accept", "*/*"]],
    "body_length": 0,
    "body_interrupted": false
  },
  "response": {
    "status": 200,
    "version": "HTTP/2.0",
    "headers": [["date", "Sun, 20 Sep 2026 23:14:12 GMT"], ["content-type", "text/html"]],
    "body_length": 559,
    "body_interrupted": false
  },
  "timing": { "duration_ms": 517 },
  "upstream_never_answered": false,
  "request_body_over_limit": false,
  "response_body_over_limit": false,
  "was_upgraded": false,
  "violations": [
    {
      "rule": "accept_encoding_present",
      "violation": "accept_encoding_missing",
      "severity": "info",
      "message": "Request expresses no content-coding preference (no Accept-Encoding header); any coding is acceptable, but most servers will not compress without an explicit signal",
      "cite": {
        "spec": "RFC 9110",
        "section": "12.5.3",
        "url": "https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3"
      },
      "party": "client"
    }
  ]
}
```

Headers are a list of `[name, value]` pairs in wire order, names lowercased, so
a repeated field keeps every line. The fields worth knowing:

- `response` is `null` when the upstream never answered, and
  `upstream_never_answered` is then `true`.
- `request_body` and `response_body` appear, base64-encoded, only when
  `general.captures_include_body` is set. `body_length` is the real size either
  way, and `request_body_over_limit` / `response_body_over_limit` say when the
  captured copy is a truncated prefix.
- `body_interrupted` says the sender stopped short of the length it framed.
- `was_upgraded` and `upgrade_protocol` mark a transaction that became a
  WebSocket session; `trailers` appears on a message that carried any.
- `violations` is what the rules found at capture time, under the configuration
  the proxy ran with. `lint-captures` re-lints under its own. A finding's
  `violation`, `cite`, `party`, `proxy_induced` and `strength` are written only
  when they carry something.
