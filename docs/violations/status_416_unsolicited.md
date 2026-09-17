<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_416_unsolicited

416 Range Not Satisfiable answers a request that named no range

## Message

416 Range Not Satisfiable response sent to a request with no Range header

## Specifications

- [RFC 9110 §15.5.17](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.17): 416 Range Not Satisfiable: the status code is the rejection of the ranges in the request's `Range` field; a server answering a *byte*-range request SHOULD include `Content-Range: bytes */<complete-length>`

## Configuration

```toml
[violations.status_416_unsolicited]
# 416 Range Not Satisfiable answers a request that named no range
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
