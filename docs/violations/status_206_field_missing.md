<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_206_field_missing

A 206 omits a header field the 200 it is a part of carried

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content: the status code is a range request being fulfilled, and a single-part 206 MUST carry a `Content-Range` describing the enclosed range

## Configuration

```toml
[violations.status_206_field_missing]
# A 206 omits a header field the 200 it is a part of carried
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [status_206_required_fields](../rules/status_206_required_fields.md)
