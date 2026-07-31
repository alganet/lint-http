<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Sec Fetch Site Value Valid

## Description

Requests that include the `Sec-Fetch-Site` request header must use one of the canonical values defined by the Fetch Metadata specification: `cross-site`, `same-origin`, `same-site`, or `none`. This rule validates the header token syntax and that the value is exactly one of the accepted identifiers — the values are lowercase tokens and structured-field tokens carry no case folding, so `Same-Origin` is not a valid value. Multiple header fields (repeated `Sec-Fetch-Site`) are treated as a violation (possible header injection) and will be flagged.

## Specifications

- [Fetch Metadata](https://www.w3.org/TR/fetch-metadata/#sec-fetch-site): Fetch Metadata (W3C) — `Sec-Fetch-Site` header values

## Configuration

```toml
[rules.message_sec_fetch_site_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Sec-Fetch-Site: same-origin
```

```http
Sec-Fetch-Site: cross-site
```

### ❌ Bad

```http
Sec-Fetch-Site: invalid
```

```http
Sec-Fetch-Site:
```
