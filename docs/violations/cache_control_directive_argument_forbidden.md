<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_directive_argument_forbidden

A Cache-Control directive that defines no argument is written with one

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control directives and general directive syntax — `cache-directive = token [ "=" ( token / quoted-string ) ]`, the production an argument's presence and form derive from
- [RFC 9111 §5.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.3): Extension Directives — a cache MUST ignore what it does not recognise, and a new directive states whether it requires an argument, what a missing one means, and what a present one means where none is defined
- [RFC 9111 §5.2.1.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.4): `no-cache` request directive — a client's preference that a stored response not be used without validation, stated by the directive alone and taking no argument

## Configuration

```toml
[violations.cache_control_directive_argument_forbidden]
# A Cache-Control directive that defines no argument is written with one
severity = "warn"
```

## Reported By

- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
