<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_whitespace_forbidden

A request-target carries whitespace

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — `request-target = origin-form / absolute-form / authority-form / asterisk-form`, no whitespace allowed in any of them, the recipient's SHOULD to answer 400 rather than autocorrect, and why: a request-line like that might be crafted to bypass a filter along the chain

## Configuration

```toml
[violations.request_target_whitespace_forbidden]
# A request-target carries whitespace
severity = "error"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
