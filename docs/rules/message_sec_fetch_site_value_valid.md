<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_sec_fetch_site_value_valid

## Description

Requests that include the `Sec-Fetch-Site` request header must use one of the canonical values defined by the Fetch Metadata specification: `cross-site`, `same-origin`, `same-site`, or `none`. This rule validates the header token syntax and that the value is one of the accepted identifiers (comparison is case-insensitive). Multiple header fields (repeated `Sec-Fetch-Site`) are treated as a violation (possible header injection) and will be flagged.

## Specifications

- Fetch Metadata (W3C) — `Sec-Fetch-Site` header values: https://www.w3.org/TR/fetch-metadata/#sec-fetch-site

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