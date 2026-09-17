<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_206_unsolicited

206 Partial Content answers a request that asked for no range

## Message

206 Partial Content response received but request did not include a Range header

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content: the status code is a range request being fulfilled, and a single-part 206 MUST carry a `Content-Range` describing the enclosed range

## Configuration

```toml
[violations.status_206_unsolicited]
# 206 Partial Content answers a request that asked for no range
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
