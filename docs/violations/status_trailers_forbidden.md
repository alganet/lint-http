<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_trailers_forbidden

A status that ends at its header section carries a trailer section

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): Informational 1xx — the class is interim, such a response is terminated by the end of the header section and cannot contain content or trailers, and a server must not send one to an HTTP/1.0 client, which defined no 1xx status codes
- [RFC 9110 §15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5): 204 (No Content) — the same sentence, written again for this status
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section

## Configuration

```toml
[violations.status_trailers_forbidden]
# A status that ends at its header section carries a trailer section
severity = "error"
```

## Reported By

- [no_body_for_1xx_204_304](../rules/no_body_for_1xx_204_304.md)
