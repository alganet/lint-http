<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Refresh header syntax

## Description

Validate syntax of the non-standard `Refresh` response header. The header is commonly used to perform a delayed redirect or refresh using a `delta-seconds` value optionally followed by a `url=<URI>` parameter (e.g., `5; url=/new`). This rule flags malformed values such as non-numeric delays, missing `url` values, unrecognized parameters, and invalid URI syntax in the `url` parameter.

## Specifications

- MDN: [Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Refresh) — non-standard header commonly used for delayed redirects.
- Note: this rule rejects comma-separated field-values (i.e., the header must be a single value). As a consequence, URLs containing commas will be flagged because commas are treated as list separators by this check.

## Configuration

TOML example (enable the rule and set severity):

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
