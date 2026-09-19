<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_pair_missing

Set-Cookie carries no cookie-pair

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

**It departs from that level.** RFC 6265 writes its whole grammar as a SHOULD NOT, so every defect in a `Set-Cookie` inherits `warn` from one sentence. What is lost here is not an attribute but the cookie: a server that wrote this believes it stored state and stored none, and no reading of the line recovers what the pair would have said.

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`

## Configuration

```toml
[violations.cookie_pair_missing]
# Set-Cookie carries no cookie-pair
# SHOULD obliges the sender, so this defaults to warn.
# Departs from that: RFC 6265 writes its whole grammar as a SHOULD NOT, so every defect in a `Set-Cookie` inherits `warn` from one sentence. What is lost here is not an attribute but the cookie: a server that wrote this believes it stored state and stored none, and no reading of the line recovers what the pair would have said.
severity = "error"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
