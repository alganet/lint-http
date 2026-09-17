<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# percent_encoding_malformed

Percent-encoding is not two hexadecimal digits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits every `%` still owes

## Configuration

```toml
[violations.percent_encoding_malformed]
# Percent-encoding is not two hexadecimal digits
severity = "warn"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [cookie_path_valid](../rules/cookie_path_valid.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [host_header](../rules/host_header.md)
- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [request_uri_percent_encoding_valid](../rules/request_uri_percent_encoding_valid.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
