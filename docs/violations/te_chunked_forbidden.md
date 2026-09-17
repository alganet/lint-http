<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# te_chunked_forbidden

TE names the chunked coding, which cannot be declined

## Message

A client must not send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §7.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4): TE — the codings a client will accept, the `q` pseudo-parameter that ranks them, and the MUST NOT on naming `chunked`

## Configuration

```toml
[violations.te_chunked_forbidden]
# TE names the chunked coding, which cannot be declined
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [transfer_coding_registered](../rules/transfer_coding_registered.md)
