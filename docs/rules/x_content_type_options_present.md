<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server X-Content-Type-Options

## Description

This rule checks if responses include the `X-Content-Type-Options: nosniff` header.

This security header prevents browsers from "MIME-sniffing" a response away from the declared `Content-Type`. This reduces exposure to drive-by download attacks and cross-site scripting (XSS) vulnerabilities where a browser might execute a file as HTML/JavaScript even if the server served it as an image or text.

A header that is present but whose first value is not `nosniff` (matched case-insensitively, per the Fetch standard's determine-nosniff algorithm) is also flagged: it does not enable the protection.

A response writing the field on more than one line is flagged too, whether or not the lines agree. Fetch §3.6 defines the value as the single literal `nosniff` and gives it no comma-separated-list alternative, so RFC 9110 §5.3's exception does not reach it; the splitting in *determine-nosniff* is a recipient recovering a first member from a value it should not have been sent, which is a recipient's rule and not a sender's licence. The repetition is reported in place of the value verdict, as it is for every other singleton field in this catalogue.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [x_content_type_options_invalid](../violations/x_content_type_options_invalid.md) — X-Content-Type-Options carries a value that is not nosniff
- [x_content_type_options_missing](../violations/x_content_type_options_missing.md) — A response does not ask for its content type to be respected

## Specifications

- [Fetch §3.6](https://fetch.spec.whatwg.org/#x-content-type-options-header): `X-Content-Type-Options`: the conformance value ABNF (`"nosniff" ; case-insensitive`) and the determine-nosniff algorithm
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options): Web Docs: X-Content-Type-Options

## Configuration

```toml
[rules.x_content_type_options_present]
enabled = true
content_types = ["text/html", "text/javascript", "application/javascript", "application/json", "text/css"]
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

```http
HTTP/1.1 200 OK
Content-Type: text/css
# Missing X-Content-Type-Options header
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Content-Type-Options: sniff
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
X-Content-Type-Options: nosniff
X-Content-Type-Options: nosniff
```
