<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# via_received_by_obsolete

Via received-by is spelled as a uri-host

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §B.2](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2): Why a `received-by` is a token: RFC 9110 removed `uri-host` from the production, which is what makes a bracketed IPv6 literal a finding here and not under RFC 7230

## Configuration

```toml
[violations.via_received_by_obsolete]
# Via received-by is spelled as a uri-host
severity = "warn"
```

## Reported By

- [via_header_syntax](../rules/via_header_syntax.md)
