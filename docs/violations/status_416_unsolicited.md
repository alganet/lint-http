<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_416_unsolicited

416 Range Not Satisfiable answers a request that named no range

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.5.17](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17): 416 Range Not Satisfiable: the status code is the rejection of the ranges in the request's `Range` field; a server answering a *byte*-range request SHOULD include `Content-Range: bytes */<complete-length>`
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): `Range`: an origin server MUST ignore a `Range` field in a unit it does not understand, which is what a request outside the advertised set is likely to cost — the whole representation instead of the part asked for

## Configuration

```toml
[violations.status_416_unsolicited]
# 416 Range Not Satisfiable answers a request that named no range
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
