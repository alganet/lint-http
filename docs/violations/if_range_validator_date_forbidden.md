<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# if_range_validator_date_forbidden

If-Range carries a date for a representation with an entity tag

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5): `If-Range`: `entity-tag / HTTP-date`, the first-three-characters DQUOTE test that tells them apart, the MUST NOT on a request with no `Range`, the MUST NOT on a weak entity-tag, and the strong comparison a recipient evaluates the condition with

## Configuration

```toml
[violations.if_range_validator_date_forbidden]
# If-Range carries a date for a representation with an entity tag
severity = "warn"
```

## Reported By

- [range_request_and_caching](../rules/range_request_and_caching.md)
