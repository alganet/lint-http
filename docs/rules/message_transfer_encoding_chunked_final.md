<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_transfer_encoding_chunked_final

**Goal:** Ensure that when `Transfer-Encoding` includes the `chunked` transfer coding it appears as the final transfer coding.

## Why

Per RFC 7230 §4.1, the `chunked` transfer-coding must always be the final transfer-coding applied to a message. Intermediate codecs cannot follow `chunked`, because chunked encoding is the format used to delimit the message body.

## What this rule checks

- If a message includes `Transfer-Encoding: ...` values and any of them is `chunked`, then `chunked` must be the final coding in the sequence. The rule checks all `Transfer-Encoding` header fields and the order of comma-separated codings.

## Examples

- OK: `Transfer-Encoding: gzip, chunked`
- OK: `Transfer-Encoding: chunked`
- Violation: `Transfer-Encoding: chunked, gzip`
- Violation: multiple header fields where an earlier field contains `chunked` and later fields contain other codings

## Configuration

This rule has no configuration; enable it by adding the following to your configuration:

```toml
[rules.message_transfer_encoding_chunked_final]
enabled = true
severity = "warn"
```
