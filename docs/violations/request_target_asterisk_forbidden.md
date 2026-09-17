<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_asterisk_forbidden

The asterisk target is sent with a method other than OPTIONS

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource — the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version

## Configuration

```toml
[violations.request_target_asterisk_forbidden]
# The asterisk target is sent with a method other than OPTIONS
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
- [request_target_form_valid](../rules/request_target_form_valid.md)
