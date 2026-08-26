<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Sec Fetch Mode Value Valid

## Description

Requests that include the `Sec-Fetch-Mode` request header must use one of the canonical values defined by the Fetch Metadata specification: `cors`, `no-cors`, `same-origin`, `navigate`, or `websocket`. This rule validates the header token syntax and that the value is exactly one of the accepted identifiers — modes are lowercase tokens and structured-field tokens carry no case folding, so `CORS` is not a valid value. Multiple header fields (repeated `Sec-Fetch-Mode`) are treated as a violation (possible header injection) and will be flagged.

## Specifications

- [Fetch Metadata §2.2](https://www.w3.org/TR/fetch-metadata/#sec-fetch-mode-header): Fetch Metadata (W3C) — `Sec-Fetch-Mode`: an sf-token whose valid values are the five request modes

## Configuration

```toml
[rules.sec_fetch_mode_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Sec-Fetch-Mode: cors
```

```http
Sec-Fetch-Mode: navigate
```

### ❌ Bad

```http
Sec-Fetch-Mode: invalid
```

```http
Sec-Fetch-Mode:
```
