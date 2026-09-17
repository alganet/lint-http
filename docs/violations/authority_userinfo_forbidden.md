<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_userinfo_forbidden

An :authority carries the deprecated userinfo subcomponent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): Request Pseudo-Header Fields — what each of `:method`, `:scheme`, `:authority` and `:path` conveys, the `'*'` value for asterisk-form OPTIONS, the `:path`-must-not-be-empty MUST, and the userinfo MUST NOT written for `http` and `https` targets
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): Request Pseudo-Header Fields — the exactly-one MUST for `:method`, `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes with a mandatory authority component, and the MUST NOT on the deprecated userinfo subcomponent for http and https URIs

## Configuration

```toml
[violations.authority_userinfo_forbidden]
# An :authority carries the deprecated userinfo subcomponent
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
