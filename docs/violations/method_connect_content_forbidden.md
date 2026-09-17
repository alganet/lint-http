<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_connect_content_forbidden

A CONNECT request declares content its definition has no room for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the request message does not have content, and the interpretation of anything after its header section is specific to the version of HTTP in use

## Configuration

```toml
[violations.method_connect_content_forbidden]
# A CONNECT request declares content its definition has no room for
severity = "warn"
```

## Reported By

- [request_version_method_valid](../rules/request_version_method_valid.md)
