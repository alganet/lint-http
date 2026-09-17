<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# conditional_entity_tag_missing

A revalidating request omits the entity tags it holds

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9111 §4.3.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1): Sending a Validation Request — a cache MUST send the entity tags of the stored responses it is validating, in `If-Match`, `If-None-Match` or `If-Range`, and SHOULD send the `Last-Modified` value where the conditions for it hold

## Configuration

```toml
[violations.conditional_entity_tag_missing]
# A revalidating request omits the entity tags it holds
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [range_request_and_caching](../rules/range_request_and_caching.md)
