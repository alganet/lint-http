<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Digest Auth Valid

## Description

Digest `Authorization` credentials must include the required auth-params and use syntactically valid tokens or quoted-strings. This rule checks `Authorization: Digest ...` request headers for presence of required fields and basic syntactic validity (e.g., `username`, `realm`, `nonce`, `uri`, `response`).

**`cnonce` and `nc` are demanded exactly where the credential's own `qop` makes the demand observable.** RFC 7616 §3.4 marks each *"MUST be used by all implementations"*; RFC 2617 computes a qop-less response without either and makes both conditional on a qop directive. A credential that carries `qop` is inside both documents' requirements at once — and both compute the `response` value over `cnonce` and `nc`, so their absence leaves the credential unverifiable by the recipient it was written for. A credential with no `qop` is RFC 2617's older shape and neither is demanded of it: RFC 7616 alone would ask for them, but rejecting the qop-less form outright would reject credentials the obsolete document defines and deployed servers still verify, and no observable line short of `qop` separates the two vintages.

**§3.4's two per-parameter quoting MUSTs are enforced in both directions.** A sender *"MUST only generate the quoted string syntax"* for `username`, `realm`, `nonce`, `uri`, `response`, `cnonce` and `opaque`, and *"MUST NOT"* for `algorithm`, `qop` and `nc` — for historical reasons, which is the point: recipients of each parameter were deployed against one spelling, so the wrong spelling is a credential some verifiers will not read. An unquoted `uri` was deliberately accepted here for a long time and no longer is. `username*`, `userhash` and unknown extension parameters are in neither list, so only the spelling they arrived in is judged.

Servers and clients relying on Digest authentication may behave incorrectly when required parameters are missing or malformed.

## Specifications

- [RFC 7616 §3.4](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.4): The Authorization Header Field — the Digest credentials, their parameters, the 4xx consequence for missing or improper ones, the "MUST be used by all implementations" on cnonce and nc, and the two historical-reasons quoting MUSTs enforced here in both directions
- [RFC 2617 §3.2.2](https://www.rfc-editor.org/rfc/rfc2617.html#section-3.2.2): The obsolete document whose qop-less credential shape is why cnonce and nc are demanded only beside a qop: its own conditional ("MUST be specified if a qop directive is sent") is the observable line, and deployed servers still verify the older shape

## Configuration

```toml
[rules.digest_auth_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /protected HTTP/1.1
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/protected", response="d41d8cd98f00b204e9800998ecf8427e"
```

### ❌ Bad (missing response)

```http
GET /protected HTTP/1.1
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/protected"
```

### ❌ Bad (username unquoted — §3.4 admits only the quoted string syntax for it)

```http
GET /protected HTTP/1.1
Authorization: Digest username=Mu!fasa, realm="test", nonce="abc", uri="/protected", response="d41d8c"
```

### ❌ Bad (qop sent with no cnonce or nc — the response value is computed over both)

```http
GET /protected HTTP/1.1
Authorization: Digest username="Mufasa", realm="test", nonce="abc", uri="/protected", response="d41d8c", qop=auth
```
