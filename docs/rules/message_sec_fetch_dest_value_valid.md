<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Sec Fetch Dest Value Valid

## Description

Validate the `Sec-Fetch-Dest` request header follows the Fetch Metadata specification: the header value must be a token matching one of the recognized request destinations (e.g., `image`, `document`, `script`, `worker`, `empty`, etc.). Values are compared case-insensitively and token syntax is enforced. Multiple header fields are treated as a violation.

## Specifications

- [Fetch Metadata](https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest): Fetch Metadata (W3C) — `Sec-Fetch-Dest` header values

## Configuration

```toml
[rules.message_sec_fetch_dest_value_valid]
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
