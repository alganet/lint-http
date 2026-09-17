<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_head_content_forbidden

A response to HEAD carries content octets

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — the SHOULD to send the same header fields a GET would have carried, the MAY that excuses fields whose value is determined only while generating the content, and GET's content paragraph repeated word for word

## Configuration

```toml
[violations.method_head_content_forbidden]
# A response to HEAD carries content octets
severity = "error"
```

## Reported By

- [response_body_length_accuracy](../rules/response_body_length_accuracy.md)
