<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# link_attribute_duplicated

Link member writes one of the bounded attributes more than once

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 8288 §3.4.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.4.1): The four serialisation-defined attributes this document bounds to one occurrence — `media`, `title`, `title*`, `type` — each in its own MUST NOT. `hreflang` is the one it deliberately leaves unbounded, saying that repeating it means several languages are available. Also the per-attribute value ABNFs: `Language-Tag` for `hreflang`, `type-name "/" subtype-name` for `type`, and `media-query-list` for `media` — the first two measured here, the third declined for the reasons the description gives

## Configuration

```toml
[violations.link_attribute_duplicated]
# Link member writes one of the bounded attributes more than once
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [link_header_valid](../rules/link_header_valid.md)
