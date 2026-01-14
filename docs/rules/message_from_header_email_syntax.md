<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message From Header Email Syntax

## Description

This rule validates the `From` request header's mailbox-list syntax. It accepts common mailbox forms such as a bare `addr-spec` (e.g., `alice@example.com`) or a `display-name <addr-spec>` entry. The validator is conservative: it rejects obvious errors such as missing `@`, empty local-part or domain, unbalanced angle brackets, control characters, or malformed quoted local-parts.

## Specifications

- [RFC 9110 §7.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-from) — Header field definition and reference
- [RFC 5322 §3.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4) — Mailbox and mailbox-list syntax (note: full RFC 5322 parsing is complex; this rule uses a conservative subset to catch common errors)

## Configuration

```toml
[rules.message_from_header_email_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (single addr-spec)

```http
GET / HTTP/1.1
From: alice@example.com
```

### ✅ Good (display name)

```http
GET / HTTP/1.1
From: Alice <alice@example.com>
```

### ✅ Good (multiple addresses)

```http
GET / HTTP/1.1
From: Alice <alice@example.com>, bob@example.org
```

### ❌ Bad (missing @)

```http
GET / HTTP/1.1
From: not-an-email
```

### ❌ Bad (empty domain)

```http
GET / HTTP/1.1
From: alice@
```

### ❌ Bad (unbalanced angle-brackets)

```http
GET / HTTP/1.1
From: Alice <alice@example.com
```
