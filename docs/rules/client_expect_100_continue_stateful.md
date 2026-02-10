<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_expect_100_continue_stateful

## Description

When a client sends `Expect: 100-continue` it SHOULD wait for a `100 (Continue)` interim
response before sending the request body. This rule detects requests that include the
`100-continue` expectation and appear to have sent a body (non-zero `Content-Length`,
`Transfer-Encoding` present, or captured request body bytes) but where the previous
transaction for the same client+resource did not include a `100` interim response.

## Specifications

- [RFC 9110 §10.1.1 Expect / 100 (Continue)](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1)
- [RFC 9110 §15.2.1 100 (Continue) status code](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2.1)

## Configuration

```toml
[rules.client_expect_100_continue_stateful]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
PUT /upload HTTP/1.1
Host: example.com
Expect: 100-continue

# Server (interim):
HTTP/1.1 100 Continue

# Client: after receiving 100, sends request body (not shown)
```

### ❌ Bad

```http
PUT /upload HTTP/1.1
Host: example.com
Content-Length: 12345
Expect: 100-continue

# The client sent a body despite no prior 100 (Continue) interim response being observed
```
