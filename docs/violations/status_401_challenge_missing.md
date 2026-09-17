<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_401_challenge_missing

A 401 presents no challenge to authenticate against

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2): 401 (Unauthorized) — the server generating one MUST send a `WWW-Authenticate` containing at least one challenge applicable to the target resource, and a user agent that has already attempted authentication and gets the same challenge back SHOULD show the representation to the user

## Configuration

```toml
[violations.status_401_challenge_missing]
# A 401 presents no challenge to authenticate against
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [status_code_semantics](../rules/status_code_semantics.md)
