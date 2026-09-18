<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_head_content_length_ambiguous

A HEAD and a GET report different lengths for a resource nothing pins

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length is the one requirement about a HEAD response that is not a SHOULD: "a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method". The same sentence opens with the MAY that lets a HEAD response omit it

## Configuration

```toml
[violations.method_head_content_length_ambiguous]
# A HEAD and a GET report different lengths for a resource nothing pins
severity = "warn"
```

## Reported By

- [head_response_headers_match_get](../rules/head_response_headers_match_get.md)
