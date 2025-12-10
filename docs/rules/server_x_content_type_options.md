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

## Configuration

This rule should only be applied to responses with specific `Content-Type` values. Configure which content types should be checked under `[rules.server_x_content_type_options]` with a `content_types` array of MIME types:

```toml
[rules.server_x_content_type_options]
enabled = true
content_types = ["text/html", "application/javascript", "application/json"]
```

Only responses whose `Content-Type` header (ignoring any media type parameters like `; charset=UTF-8`) matches one of the configured values will be checked. If `content_types` is omitted or invalid, the rule's `validate_config` will fail at startup.
