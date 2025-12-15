<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server X-Content-Type-Options

## Description
This rule checks if responses include the `X-Content-Type-Options: nosniff` header.

This security header prevents browsers from "MIME-sniffing" a response away from the declared `Content-Type`. This reduces exposure to drive-by download attacks and cross-site scripting (XSS) vulnerabilities where a browser might execute a file as HTML/JavaScript even if the server served it as an image or text.

## Specifications

- [MDN Web Docs: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

## Configuration

```toml
[rules.server_x_content_type_options]
enabled = true
severity = "warn"
content_types = ["text/html", "application/javascript", "application/json"]
```

This rule requires a non-empty `content_types` array of media types which the rule will check against the response `Content-Type` header. Only responses whose `Content-Type` header (ignoring any parameters like `; charset=UTF-8`) matches one of the configured values will be checked.

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
