<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_post_location_missing

A 201 answering a POST does not say what it created

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §9.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3): POST — the SHOULD asking an origin server that created a resource to answer 201 with a Location naming it, which is the sentence that makes a 201 without one a finding

## Configuration

```toml
[violations.method_post_location_missing]
# A 201 answering a POST does not say what it created
severity = "warn"
```

## Reported By

- [post_creates_resource](../rules/post_creates_resource.md)
