<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_max_forwards_numeric

## Description

Validate that the `Max-Forwards` request header value is a decimal integer consisting of one or more digits (ABNF: `Max-Forwards = 1*DIGIT`). This header is used by `TRACE` and `OPTIONS` to limit forwarding by intermediaries; invalid values can break proxy forwarding semantics.

## Specifications

- [RFC 9110 §7.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2) — Max-Forwards header.

## Configuration

Enable the rule in your TOML config (example):

```toml
[rules.message_max_forwards_numeric]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: 0

```

❌ Bad

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: -1

``` 

```http
OPTIONS * HTTP/1.1
Host: example.com
Max-Forwards: 1.0

```

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: 120, 240

```
