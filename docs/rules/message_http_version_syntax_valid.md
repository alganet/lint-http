<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_http_version_syntax_valid

## Description

Validate that the HTTP start-line version token matches the ABNF syntax defined for HTTP-version: `HTTP"/"DIGIT"."DIGIT` (e.g., `HTTP/1.1`). This rule checks both request start-lines and response status-lines when the version token is available.

## Specifications

- RFC 9112 §2.3: `HTTP-version = HTTP-name "/" DIGIT "." DIGIT` (case-sensitive `HTTP`)

## Configuration

Enable the rule in `config.toml`:

```toml
[rules.message_http_version_syntax_valid]
enabled = true
severity = "error"
```

## Examples

✅ Good

```http
GET /path HTTP/1.1
Host: example

HTTP/1.1 200 OK
Content-Type: text/plain

Hello
```

❌ Bad

```http
GET /path http/1.1
Host: example

HTTP/1.10 200 OK
Content-Type: text/plain

Hello
```