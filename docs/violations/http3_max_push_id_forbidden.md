<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http3_max_push_id_forbidden

A server sent a MAX_PUSH_ID frame

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9114 §7.2.7](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7): MAX_PUSH_ID — a client-only frame that raises the push limit, the prohibition on a server sending one, and the rule that a later frame cannot reduce the maximum

## Configuration

```toml
[violations.http3_max_push_id_forbidden]
# A server sent a MAX_PUSH_ID frame
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [http3_max_push_id](../rules/http3_max_push_id.md)
