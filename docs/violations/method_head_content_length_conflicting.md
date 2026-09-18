<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_head_content_length_conflicting

A HEAD response states a length the GET would not have sent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length is the one requirement about a HEAD response that is not a SHOULD: "a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method". The same sentence opens with the MAY that lets a HEAD response omit it

## Configuration

```toml
[violations.method_head_content_length_conflicting]
# A HEAD response states a length the GET would not have sent
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [head_response_headers_match_get](../rules/head_response_headers_match_get.md)
