<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_head_conflicting

A HEAD response disagrees with the GET it stands in for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — the SHOULD to send the same header fields a GET would have carried, the MAY that excuses fields whose value is determined only while generating the content, and GET's content paragraph repeated word for word

## Configuration

```toml
[violations.method_head_conflicting]
# A HEAD response disagrees with the GET it stands in for
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [head_response_headers_match_get](../rules/head_response_headers_match_get.md)
