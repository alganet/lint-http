<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# challenge_member_empty

Authentication challenge list has an empty member

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate = #challenge` — the list whose members are grouped into challenges before any of them is read

## Configuration

```toml
[violations.challenge_member_empty]
# Authentication challenge list has an empty member
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [proxy_authenticate_challenge_syntax](../rules/proxy_authenticate_challenge_syntax.md)
- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
