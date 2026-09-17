<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_206_multipart_forbidden

A multipart 206 answers a request that asked for a single range

## Message

multipart/byteranges 206 response sent to a request for a single range

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.3.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2): 206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response

## Configuration

```toml
[violations.status_206_multipart_forbidden]
# A multipart 206 answers a request that asked for a single range
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
