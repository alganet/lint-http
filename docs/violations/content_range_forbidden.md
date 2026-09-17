<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_range_forbidden

Content-Range is written in the header section of a multipart 206

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.3.7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7.2): 206 Partial Content, multiple parts: the parts carry the `Content-Range` fields and the header section MUST NOT carry one; a request for a single range MUST NOT be answered with a multipart response

## Configuration

```toml
[violations.content_range_forbidden]
# Content-Range is written in the header section of a multipart 206
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_and_content_range_consistent](../rules/range_and_content_range_consistent.md)
