<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http3_goaway_ignored

A request stream opens past the limit a server's GOAWAY set

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9114 §5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2): Connection Shutdown — the GOAWAY identifier and whose id space it is drawn from, the connection error a larger one draws, and the prohibition on starting anything new past it

## Configuration

```toml
[violations.http3_goaway_ignored]
# A request stream opens past the limit a server's GOAWAY set
severity = "warn"
```

## Reported By

- [http3_goaway_semantics](../rules/http3_goaway_semantics.md)
