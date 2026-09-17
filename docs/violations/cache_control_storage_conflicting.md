<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_storage_conflicting

Two Cache-Control directives disagree about storing the response

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.2.2.9](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.9): `public` — a cache MAY store the response even where it would otherwise be prohibited
- [RFC 9111 §5.2.2.7](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7): private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private
- [RFC 9111 §5.2.2.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.5): `no-store` — a cache MUST NOT store any part of the request or the response, and MUST NOT use the response to satisfy another request

## Configuration

```toml
[violations.cache_control_storage_conflicting]
# Two Cache-Control directives disagree about storing the response
severity = "warn"
```

## Reported By

- [caching_directive_interaction](../rules/caching_directive_interaction.md)
