<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_scheme_character_forbidden

URI scheme holds a character outside letters, digits, '+', '-' and '.'

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon

## Configuration

```toml
[violations.uri_scheme_character_forbidden]
# URI scheme holds a character outside letters, digits, '+', '-' and '.'
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
- [link_header_valid](../rules/link_header_valid.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [request_origin_header_present_for_cors](../rules/request_origin_header_present_for_cors.md)
- [timing_allow_origin_valid](../rules/timing_allow_origin_valid.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
