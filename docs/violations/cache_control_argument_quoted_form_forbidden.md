<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_argument_quoted_form_forbidden

A Cache-Control delta-seconds argument is written in the quoted-string form

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9111 §5.2.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.1): `max-age` response directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.1): `max-age` request directive — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.2): `max-stale` — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.1.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.3): `min-fresh` — the argument uses the token form, and a sender MUST NOT generate the quoted-string form
- [RFC 9111 §5.2.2.10](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.10): `s-maxage` — the directive is defined for a shared cache, where it overrides the maximum age given by `max-age` or `Expires`; it says nothing to any other kind of cache

## Configuration

```toml
[violations.cache_control_argument_quoted_form_forbidden]
# A Cache-Control delta-seconds argument is written in the quoted-string form
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
