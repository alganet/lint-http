<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# credentials_control_character_forbidden

Credentials hold a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §11.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.4): Credentials — `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, the request-side mirror of `challenge`

## Configuration

```toml
[violations.credentials_control_character_forbidden]
# Credentials hold a control character
# GRAMMAR obliges the sender, so this defaults to error.
# No input this tool accepts reaches this defect: the octet this names is a control octet, and no route carries one to the rules: on the wire the parser refuses the message before there is a transaction, and from a capture file `HeaderValue` refuses the record -- 0x7f with the rest of the class
severity = "error"
```

## Reported By

- [authorization_credentials_valid](../rules/authorization_credentials_valid.md)
