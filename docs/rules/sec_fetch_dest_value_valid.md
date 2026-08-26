<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Sec Fetch Dest Value Valid

## Description

Validate the `Sec-Fetch-Dest` request header follows the Fetch Metadata specification: the header value must be a token matching one of the recognized request destinations (e.g., `image`, `document`, `script`, `worker`, `empty`, etc.). The match is exact — destinations are lowercase tokens and structured-field tokens carry no case folding, so `Image` is not a valid value. Token syntax is enforced. Multiple header fields are treated as a violation.

## Specifications

- [Fetch Metadata §2.1](https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest-header): Fetch Metadata (W3C) — `Sec-Fetch-Dest`: an sf-token whose valid values are Fetch's request destinations

## Configuration

```toml
[rules.sec_fetch_dest_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /image.png HTTP/1.1
Host: example.com
Sec-Fetch-Dest: image
```

```http
GET /script.js HTTP/1.1
Host: example.com
Sec-Fetch-Dest: script
```

### ❌ Bad destination tokens are lowercase; the match is exact

```http
GET /script.js HTTP/1.1
Host: example.com
Sec-Fetch-Dest: Script
```

### ❌ Bad

```http
GET /something HTTP/1.1
Host: example.com
Sec-Fetch-Dest: invalid-dest
```

```http
GET /img HTTP/1.1
Host: example.com
Sec-Fetch-Dest: image
Sec-Fetch-Dest: script
```
