<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_301_ambiguous

A 301 answers a POST, leaving the redirected method undetermined

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §15.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2): 301 Moved Permanently: a user agent MAY change the method from POST to GET, and 308 is the status named for a server that does not want that

## Configuration

```toml
[violations.status_301_ambiguous]
# A 301 answers a POST, leaving the redirected method undetermined
severity = "warn"
```

## Reported By

- [status_3xx_vs_request_method](../rules/status_3xx_vs_request_method.md)
