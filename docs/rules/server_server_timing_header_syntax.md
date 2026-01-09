<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Server-Timing Header Syntax

## Description

The `Server-Timing` response header communicates server-side performance metrics. Each metric must be a `metric-name` followed by optional `;`-separated parameters such as `dur` (duration, numeric) and `desc` (description, token or quoted-string). This rule validates that each metric name and parameter-name is a `token`, parameter values are either `token` or a well-formed `quoted-string`, and that `dur` parses as a number when present.

## Specifications

- W3C Server-Timing Header Field — Section "The `Server-Timing` Header Field" (syntax and examples): https://w3c.github.io/server-timing/#the-server-timing-header-field

## Configuration

```toml
[rules.server_server_timing_header_syntax]
# enabled = true
# severity = "warn" # info|warn|error
```

## Examples

✅ Good

```http
Server-Timing: miss, db;dur=53, app;dur=47.2
Server-Timing: cache;desc="Cache Read";dur=23.2
Server-Timing: customView, dc;desc=atl
```

❌ Bad

```http
Server-Timing: ,miss
Server-Timing: b@d;dur=5
Server-Timing: db;dur=abc
Server-Timing: db;desc=Cache Read
Server-Timing: db;desc="unfinished
```
