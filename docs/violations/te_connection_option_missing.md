<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# te_connection_option_missing

TE is sent without a TE connection option beside it

## Message

Request carries a TE header field without a 'TE' connection option in Connection; TE applies to the immediate connection only, and the option is what stops an intermediary from forwarding it

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE — what a member states, the grammar of its parameters, and the `TE` connection option a sender of the field MUST also send

## Configuration

```toml
[violations.te_connection_option_missing]
# TE is sent without a TE connection option beside it
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [te_header_valid](../rules/te_header_valid.md)
