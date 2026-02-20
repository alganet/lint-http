<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Stateful 103 Early Hints Before Final

## Description

`103 Early Hints` responses are intended to be sent before the final
response for the same request so that user agents can begin speculative
work (for example, resource preloads). This rule flags `103` responses that
are observed *after* a final response for the same client + request-target,
using a stateful heuristic based on the previous transaction for that
client and request-target. Because the implementation cannot reliably
distinguish separate requests to the same URI, this detection may produce
false positives when multiple requests to the same target are made in
quick succession, but it is still useful for catching likely violations of
the intent of RFC 8297.

## Specifications

- [RFC 8297](https://www.rfc-editor.org/rfc/rfc8297.html) — Early Hints

## Configuration

```toml
[rules.stateful_103_early_hints_before_final]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — Early Hint precedes final response

```http
> GET /resource HTTP/1.1

< 103 Early Hints
< Link: </static/style.css>; rel=preload; as=style

< 200 OK
< Content-Type: text/html; charset=utf-8
```

### ❌ Bad — 103 appears after final response (violation)

```http
> GET /resource HTTP/1.1

< 200 OK
< Content-Type: text/html; charset=utf-8

< 103 Early Hints
< Link: </static/style.css>; rel=preload; as=style
```