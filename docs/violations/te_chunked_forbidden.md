<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# te_chunked_forbidden

TE names the chunked coding, which cannot be declined

## Message

A client must not send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients

## Specifications

- [RFC 9112 §7.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4): TE — the codings a client will accept, the `q` pseudo-parameter that ranks them, and the MUST NOT on naming `chunked`

## Configuration

```toml
[violations.te_chunked_forbidden]
# TE names the chunked coding, which cannot be declined
severity = "warn"
```

## Reported By

- [transfer_coding_registered](../rules/transfer_coding_registered.md)
