<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_malformed

An Origin derives from neither null nor a serialized origin

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Origin header field syntax — `origin-list-or-null` is the literal `null` or a list of `serialized-origin`, and a `serialized-origin` is a scheme, `://`, a host and an optional port, with no path component

## Configuration

```toml
[violations.origin_malformed]
# An Origin derives from neither null nor a serialized origin
severity = "warn"
```

## Reported By

- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
- [request_origin_header_present_for_cors](../rules/request_origin_header_present_for_cors.md)
- [timing_allow_origin_valid](../rules/timing_allow_origin_valid.md)
