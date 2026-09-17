<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# te_chunked_forbidden

TE names the chunked coding, which cannot be declined

## Message

A client must not send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

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
