<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_type_missing

A message carries content and does not say what it is

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type — the SHOULD, the exception that excuses a sender who does not know the type, the recipient's two fallbacks, and what sniffing costs

## Configuration

```toml
[violations.content_type_missing]
# A message carries content and does not say what it is
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [content_type_present](../rules/content_type_present.md)
