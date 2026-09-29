<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_host_ip_literal_delimiter_missing

An IPv6 address is written without the brackets that mark it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere

## Configuration

```toml
[violations.uri_host_ip_literal_delimiter_missing]
# An IPv6 address is written without the brackets that mark it
severity = "warn"
```

## Reported By

- [alt_used_valid](../rules/alt_used_valid.md)
- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [host_header](../rules/host_header.md)
- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
- [link_header_valid](../rules/link_header_valid.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
