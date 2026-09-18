<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server X-Content-Type-Options

## Description

This rule checks if responses include the `X-Content-Type-Options: nosniff` header.

This security header prevents browsers from "MIME-sniffing" a response away from the declared `Content-Type`. This reduces exposure to drive-by download attacks and cross-site scripting (XSS) vulnerabilities where a browser might execute a file as HTML/JavaScript even if the server served it as an image or text.

A header that is present but whose first value is not `nosniff` (matched case-insensitively, per the Fetch standard's determine-nosniff algorithm) is also flagged: it does not enable the protection.

## Violations

- [x_content_type_options_invalid](../violations/x_content_type_options_invalid.md) — X-Content-Type-Options carries a value that is not nosniff
- [x_content_type_options_missing](../violations/x_content_type_options_missing.md) — A response does not ask for its content type to be respected

## Specifications

- [Fetch §3.6](https://fetch.spec.whatwg.org/#x-content-type-options-header): `X-Content-Type-Options`: the conformance value ABNF (`"nosniff" ; case-insensitive`) and the determine-nosniff algorithm
- [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options): Web Docs: X-Content-Type-Options

## Configuration

```toml
[rules.x_content_type_options_present]
enabled = true
content_types = ["text/html", "text/javascript", "application/javascript", "application/json"]
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: text/javascript
X-Content-Type-Options: nosniff
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: text/javascript
# Missing X-Content-Type-Options header
```
