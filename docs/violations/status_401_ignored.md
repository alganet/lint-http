<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_401_ignored

A client replays credentials a 401 keeps refusing

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2): 401 (Unauthorized) — the server generating one MUST send a `WWW-Authenticate` containing at least one challenge applicable to the target resource, and a user agent that has already attempted authentication and gets the same challenge back SHOULD show the representation to the user

## Configuration

```toml
[violations.status_401_ignored]
# A client replays credentials a 401 keeps refusing
severity = "warn"
```

## Reported By

- [authentication_failure_loop](../rules/authentication_failure_loop.md)
