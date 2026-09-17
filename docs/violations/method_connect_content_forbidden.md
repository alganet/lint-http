<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_connect_content_forbidden

A CONNECT request declares content its definition has no room for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the request message does not have content, and the interpretation of anything after its header section is specific to the version of HTTP in use

## Configuration

```toml
[violations.method_connect_content_forbidden]
# A CONNECT request declares content its definition has no room for
severity = "warn"
```

## Reported By

- [request_version_method_valid](../rules/request_version_method_valid.md)
