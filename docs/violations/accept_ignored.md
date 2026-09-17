<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_ignored

Response sends a media type the request did not accept

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §12.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.1): Absence: what a missing negotiation field means, and the origin server's explicit choice between sending a 406 and disregarding the field — which is why a finding about an unhonoured preference is advice and never a violation

## Configuration

```toml
[violations.accept_ignored]
# Response sends a media type the request did not accept
severity = "info"
```

## Reported By

- [accept_and_content_type_negotiation](../rules/accept_and_content_type_negotiation.md)
