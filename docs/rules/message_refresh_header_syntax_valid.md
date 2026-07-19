<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Refresh header syntax

## Description

Validate syntax of the `Refresh` response header. Long treated as non-standard, it is now specified by the HTML Standard as the HTTP equivalent of a `meta` element in the Refresh state, and takes the same value: a `delta-seconds` value optionally followed by a `url=<URI>` parameter (e.g., `5; url=/new`). This rule flags malformed values such as non-numeric delays, missing `url` values, unrecognized parameters, and invalid URI syntax in the `url` parameter.

Note: this rule rejects comma-separated field-values (i.e., the header must be a single value). As a consequence, URLs containing commas will be flagged because commas are treated as list separators by this check.

## Specifications

- [HTML Speculative Loading](https://html.spec.whatwg.org/multipage/speculative-loading.html): The `Refresh` header — the HTTP equivalent of a `meta` element in the Refresh state. The standard caught up with the header; this reference had not
- [MDN Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh): `Refresh` header, with browser support notes

## Configuration

```toml
[rules.message_refresh_header_syntax_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Refresh: 5

HTTP/1.1 200 OK
Refresh: 10; url=/new
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Refresh: bad

HTTP/1.1 200 OK
Refresh: 5; url=

HTTP/1.1 200 OK
Refresh: 5; foo=bar

HTTP/1.1 200 OK
Refresh: 5, 10  # comma-separated values are not valid
```
