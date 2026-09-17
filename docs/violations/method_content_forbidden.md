<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_content_forbidden

A GET, HEAD or DELETE request carries content

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §9.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.1): GET — the client `SHOULD NOT` on content, its `unless` clause, the sentence declining to rely on the private agreement that clause describes, and the statement that framing is independent of the method
- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — the SHOULD to send the same header fields a GET would have carried, the MAY that excuses fields whose value is determined only while generating the content, and GET's content paragraph repeated word for word
- [RFC 9110 §9.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.5): DELETE — the same content paragraph as GET and HEAD, word for word again

## Configuration

```toml
[violations.method_content_forbidden]
# A GET, HEAD or DELETE request carries content
severity = "warn"
```

## Reported By

- [request_version_method_valid](../rules/request_version_method_valid.md)
