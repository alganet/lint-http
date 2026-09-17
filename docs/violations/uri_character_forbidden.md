<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_character_forbidden

Value holds a character no URI is written with

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters — the limited set a URI is composed from, every other octet being percent-encoded before the reference is formed

## Configuration

```toml
[violations.uri_character_forbidden]
# Value holds a character no URI is written with
severity = "warn"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [link_header_valid](../rules/link_header_valid.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [request_origin_header_present_for_cors](../rules/request_origin_header_present_for_cors.md)
- [request_uri_percent_encoding_valid](../rules/request_uri_percent_encoding_valid.md)
- [timing_allow_origin_valid](../rules/timing_allow_origin_valid.md)
