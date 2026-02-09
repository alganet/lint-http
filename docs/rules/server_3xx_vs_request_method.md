<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_3xx_vs_request_method

## Description

Servers should use redirect status codes that unambiguously express whether the
client should change the request method when following the Location. Responding
with 301 or 302 to unsafe methods (e.g., POST) is historically ambiguous: use
303 to explicitly instruct the client to perform a GET on the target, or use
307/308 to indicate the client must preserve the original method and body.

## Specifications

- [RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4) — Redirection status codes and method-preserving semantics.

## Configuration

This rule has no custom configuration; enable it in your `config.toml` like other rules. Example:

```toml
[rules.server_3xx_vs_request_method]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 307 Temporary Redirect
Location: /submit-new
```

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 303 See Other
Location: /status
```

### ❌ Bad

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: /submit-new
```