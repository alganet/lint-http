<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_length_conflicting

Content-Length disagrees with the octets received

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9112 §6.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2): Content-Length as framing — the declared length is how a recipient determines where the data and the message end, and the sender-side prohibition on sending it in a message that carries a Transfer-Encoding

## Configuration

```toml
[violations.content_length_conflicting]
# Content-Length disagrees with the octets received
severity = "error"
```

## Reported By

- [request_body_length_accuracy](../rules/request_body_length_accuracy.md)
- [response_body_length_accuracy](../rules/response_body_length_accuracy.md)
