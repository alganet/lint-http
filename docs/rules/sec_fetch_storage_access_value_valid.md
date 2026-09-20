<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Sec Fetch Storage Access Value Valid

## Description

Validate the `Sec-Fetch-Storage-Access` request header, the fifth member of the `Sec-Fetch-*` family and the one its four siblings' document does not define. Storage Access Headers § 4.1 makes it a Structured Field item whose value is a token, and names three valid values — `none`, `inactive` and `active`, the user agent's answer to whether this request can reach unpartitioned cookies. The match is exact: the statuses are lowercase tokens and structured-field tokens carry no case folding, so `Active` is not a valid value. Token syntax is enforced. Multiple header fields are treated as a violation.

**The value is computed by the user agent, not chosen by the page**, which is why an unrecognised one is worth reporting against the sender: the field exists so a server can decide whether to answer with `Activate-Storage-Access`, and a value outside the three leaves that decision with nothing to read. § 4.1 tells servers to ignore an invalid value for forward-compatibility, in the same words its four siblings use; this rule lints the sender, where an unrecognised status means the header came from something that is not implementing the document.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [sec_fetch_storage_access_value_invalid](../violations/sec_fetch_storage_access_value_invalid.md) — Sec-Fetch-Storage-Access names no storage access status the document defines
- [sec_fetch_value_empty](../violations/sec_fetch_value_empty.md) — A Sec-Fetch-* field is written with no value on it
- [sec_fetch_value_malformed](../violations/sec_fetch_value_malformed.md) — A Sec-Fetch-* value holds a character no token admits

## Specifications

- [Storage Access Headers §4.1](https://privacycg.github.io/storage-access-headers/#sec-fetch-storage-access-header): Storage Access Headers (Privacy CG) — `Sec-Fetch-Storage-Access`: an sf-token whose valid values are the three storage access statuses
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.sec_fetch_storage_access_value_valid]
enabled = true
```

## Examples

### ✅ Good the request already carries unpartitioned cookies

```http
GET /embed HTTP/1.1
Host: example.com
Sec-Fetch-Storage-Access: active
```

### ✅ Good permission granted, but this request did not use it

```http
GET /embed HTTP/1.1
Host: example.com
Sec-Fetch-Storage-Access: inactive
```

### ❌ Bad the statuses are lowercase; the match is exact

```http
GET /embed HTTP/1.1
Host: example.com
Sec-Fetch-Storage-Access: Active
```

### ❌ Bad a status the document does not define

```http
GET /embed HTTP/1.1
Host: example.com
Sec-Fetch-Storage-Access: granted
```
