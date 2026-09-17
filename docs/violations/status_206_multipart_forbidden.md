<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_206_multipart_forbidden

A multipart 206 answers a request that asked for a single range

## Message

multipart/byteranges 206 response sent to a request for a single range

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.3.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2): 206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response

## Configuration

```toml
[violations.status_206_multipart_forbidden]
# A multipart 206 answers a request that asked for a single range
severity = "warn"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
