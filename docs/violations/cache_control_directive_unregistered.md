<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_directive_unregistered

A Cache-Control directive names nothing any cache implements

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9111 §5.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.3): Extension Directives — a cache MUST ignore what it does not recognise, and a new directive states whether it requires an argument, what a missing one means, and what a present one means where none is defined
- [RFC 9111 §5.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.4): Cache Directive Registry — the "Hypertext Transfer Protocol (HTTP) Cache Directive Registry" defines the namespace for the cache directives, and a name enters it under IETF Review rather than by being sent

## Configuration

```toml
[violations.cache_control_directive_unregistered]
# A Cache-Control directive names nothing any cache implements
severity = "warn"
```

## Reported By

- [cache_control_directive_registered](../rules/cache_control_directive_registered.md)
