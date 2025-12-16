<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_connection_header_tokens_valid

**Goal:** Ensure tokens in the `Connection` header are syntactically valid header field-name tokens.

## Why

The `Connection` header nominates header field names that are hop-by-hop for the connection (RFC 7230 §6.1). Each token in a `Connection` field must be a valid token that can appear as a header field name (i.e., match the tchar grammar). Rejecting malformed tokens helps catch header-injection or malformed requests.

## What this rule checks

- For each `Connection` header field and each comma-separated token:
  - The token must be non-empty.
  - The token must match header field-name syntax (as parsed by `hyper::header::HeaderName`).

The rule treats token syntax only; it does not currently require that the named header field actually be present in the message (some tokens are connection options, e.g., `close`).

## Examples

- OK: `Connection: upgrade, keep-alive`
- Violation: `Connection: a/b` ("/" not allowed in header name)
- Violation: `Connection: ""` (empty token)

## Configuration

This rule has no configuration; enable it by adding the following to your configuration:

```toml
[rules.message_connection_header_tokens_valid]
enabled = true
severity = "warn"
```
