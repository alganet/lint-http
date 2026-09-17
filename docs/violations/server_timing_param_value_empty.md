<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_timing_param_value_empty

Server-Timing parameter is written with no value after its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Server Timing §2](https://www.w3.org/TR/server-timing/#the-server-timing-header-field): The `Server-Timing` Header Field: the ABNF the entries here are written against, the two parameter names the specification establishes, and the user-agent parsing algorithm. Eight BCP 14 keywords: six addressed to the user agent, a MAY permitting a response to repeat a metric name, and a SHOULD NOT on a parameter name appearing twice in one metric — that last one is the only sentence in the whole document that measures what a server wrote. The section takes `#`, `*`, `OWS`, `token` and `quoted-string` from `[RFC7230]`, which is obsolete; the current productions are RFC 9110 § 5.6.1, § 5.6.3, § 5.6.2 and § 5.6.4 and are carried forward unchanged, so nothing decided here turns on which document is read. The document is a W3C Working Draft (7 April 2026) whose own Status section says "It is inappropriate to cite this document as other than a work in progress" — and it is nonetheless the field's only specification: the IANA HTTP Field Name Registry lists `Server-Timing` as **permanent** with this document as its sole reference, the same way it lists `Keep-Alive` against an obsoleted RFC. A work in progress is what there is to read

## Configuration

```toml
[violations.server_timing_param_value_empty]
# Server-Timing parameter is written with no value after its '='
severity = "warn"
```

## Reported By

- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
