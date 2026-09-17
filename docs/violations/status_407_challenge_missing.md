<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# status_407_challenge_missing

A 407 presents no challenge to authenticate against

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §15.5.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.8): 407 (Proxy Authentication Required) — the proxy generating one MUST send a `Proxy-Authenticate` containing a challenge applicable to that proxy for the request

## Configuration

```toml
[violations.status_407_challenge_missing]
# A 407 presents no challenge to authenticate against
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [status_code_semantics](../rules/status_code_semantics.md)
