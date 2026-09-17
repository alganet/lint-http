<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# oauth2_request_state_missing

An authorization request carries no state to bind against

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6749 §10.12](https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12): Cross-Site Request Forgery — the client MUST implement CSRF protection for its redirection URI and SHOULD use the state parameter for it (the basis for every entry in this subject)

## Configuration

```toml
[violations.oauth2_request_state_missing]
# An authorization request carries no state to bind against
severity = "warn"
```

## Reported By

- [oauth2_code_flow](../rules/oauth2_code_flow.md)
