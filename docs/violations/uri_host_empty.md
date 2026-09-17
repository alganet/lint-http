<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_host_empty

An http or https reference names no host

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §4.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1): http URI Scheme — a TCP connection and no more, `http-URI = "http" "://" authority path-abempty [ "?" query ]`, the default port, and the MUST NOT against an empty host identifier with the recipient's MUST to reject one
- [RFC 9110 §4.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2): https URI Scheme — what "secured" means for a resource named by one and the client's MUST to secure its requests for it, the same shape as the http scheme with TLS and port 443, and the MUST NOT against an empty host identifier

## Configuration

```toml
[violations.uri_host_empty]
# An http or https reference names no host
severity = "error"
```

## Reported By

- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
