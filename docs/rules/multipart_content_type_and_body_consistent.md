<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Multipart Content-Type and Body Consistency

## Description

When a `Content-Type` declares a `multipart/*` media type, the body it describes has to be delimited by the `boundary` the header names. This rule reads a captured body and checks that it carries at least one **boundary delimiter line** opening a part, and the terminating one — `--<boundary>--` — that says no further parts follow.

**A delimiter is a line, not text.** RFC 2046 §5.1.1 requires the delimiter to occur at the beginning of a line, so a body carrying the boundary text mid-line delimits nothing: `hello --abc-- world` is reported, and the finding says the text occurs but never at a line start rather than claiming the boundary is absent. Matching is a *prefix* match against the start of each candidate line, which §5.1.1 instructs implementors to do — the rest of the line may be `transport-padding`.

**A body whose only delimiter line is the closing one is reported.** The closing line is defined as the one following the last body part, so with no part to follow it the body encapsulates nothing. A single part is the documented minimum, and it passes.

**RFC 9110 §8.3.3 is why a MIME grammar governs an HTTP body**, and it is also careful about what this rule is not: HTTP framing does not use the boundary as a length indicator, so nothing here says anything about where the message ends.

**Known leniency: line endings.** §8.3.3 requires senders to generate only CRLF between body parts, and this rule locates line starts on LF, so a body using bare LF has its delimiters recognised rather than reported as missing. The wrong line ending is a real defect and a different one; blaming the boundary for it would name the wrong thing. No rule currently reports it.

**The epilogue is not read.** A delimiter line written after the closing one is `discard-text` that implementations must ignore, so it opens no part — a body consisting of a closing line followed by something that looks like a delimiter still encapsulates nothing and is reported.

**Cost:** a conforming body settles the question in its first two lines and the scan stops there. A body that never carries the delimiter is walked in full, which is inherent — the answer is only known at the end — and is bounded by `max_body_bytes`.

**Scope:** every `Content-Type` field line in each message is read, since recipients differ over which one they act on; that there is more than one is `content_type_valid`'s finding. Whether the boundary *value* is syntactically legal is `multipart_boundary_syntax`'s. A body captured only as a prefix is skipped entirely — the terminating delimiter sits at a body's end, so a truncated capture would always look like it is missing one. Nothing before the first delimiter line or after the last is examined, which §5.1.1 requires: the preamble and epilogue are to be ignored.

## Specifications

- [RFC 2046 §5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1): Multipart common syntax: `dash-boundary`, `delimiter` and `close-delimiter`, the requirement that a delimiter begin a line, the instruction to compare against the beginning of a candidate line rather than the whole of it, and the ignoring of preamble and epilogue
- [RFC 9110 §8.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.3): Multipart Types: where HTTP adopts RFC 2046 §5.1.1, and the CRLF-between-parts requirement this rule tolerates rather than enforces. It also says HTTP framing does not use the boundary as a length indicator, so nothing here is a framing check
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type: the field describes a representation in either direction, which is what puts request and response bodies both in scope

## Configuration

```toml
[rules.multipart_content_type_and_body_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

--abc
Content-Type: text/plain

hello
--abc--
```

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary="a b"

--a b
Content-Type: text/plain

hello
--a b--
```

### ❌ Bad (missing boundary)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

no boundaries here
```

### ❌ Bad (missing final boundary)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

--abc
Content-Type: text/plain

hello
--abc
```

### ❌ Bad (the boundary text never begins a line, so it delimits nothing)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

hello --abc-- world
```

### ❌ Bad (the closing delimiter has no part to follow)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

--abc--
```
