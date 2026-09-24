<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# vary_accept_encoding_missing

A response coded from Accept-Encoding does not name it in Vary

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5): Vary — an origin SHOULD send it on a cacheable response whose content was tailored to the request's preferences, and might elide it where reuse is already limited by cache directives

## Configuration

```toml
[violations.vary_accept_encoding_missing]
# A response coded from Accept-Encoding does not name it in Vary
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [vary_and_content_encoding_consistent](../rules/vary_and_content_encoding_consistent.md)
