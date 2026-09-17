<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_patch_content_type_missing

A PATCH request does not name its patch document format

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 5789 §2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2): PATCH — the set of changes is represented in a format identified by a media type, and no single default patch document format exists for a recipient to assume

## Configuration

```toml
[violations.method_patch_content_type_missing]
# A PATCH request does not name its patch document format
severity = "warn"
```

## Reported By

- [patch_partial_update](../rules/patch_partial_update.md)
