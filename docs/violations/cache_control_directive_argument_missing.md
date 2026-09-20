<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_directive_argument_missing

A Cache-Control directive that requires an argument carries none

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.3): Extension Directives — a cache MUST ignore what it does not recognise, and a new directive states whether it requires an argument, what a missing one means, and what a present one means where none is defined
- [RFC 9111 §5.2.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.1): `max-age` response directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.1): `max-age` request directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.3): `min-fresh` — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10): `s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache

## Configuration

```toml
[violations.cache_control_directive_argument_missing]
# A Cache-Control directive that requires an argument carries none
severity = "error"
```

## Reported By

- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
