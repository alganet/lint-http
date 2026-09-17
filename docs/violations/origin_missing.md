<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_missing

A request that must say where it came from carries no Origin

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch §3.2](https://fetch.spec.whatwg.org/#origin-header): The `Origin` request header — where a fetch originates from, sent for CORS fetches and for any request whose method is neither GET nor HEAD

## Configuration

```toml
[violations.origin_missing]
# A request that must say where it came from carries no Origin
severity = "warn"
```

## Reported By

- [request_origin_header_present_for_cors](../rules/request_origin_header_present_for_cors.md)
