<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# digest_challenge_quoting_invalid

A Digest challenge parameter is written in the syntax its definition refuses

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 7616 §3.3](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3): The WWW-Authenticate Response Header Field — the parameters a Digest challenge may carry, and the two lists saying which of them must and must not be written as a quoted-string

## Configuration

```toml
[violations.digest_challenge_quoting_invalid]
# A Digest challenge parameter is written in the syntax its definition refuses
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [digest_challenge_valid](../rules/digest_challenge_valid.md)
