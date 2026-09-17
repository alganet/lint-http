<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_host_ip_literal_malformed

Host brackets something that is not an IP literal

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere

## Configuration

```toml
[violations.uri_host_ip_literal_malformed]
# Host brackets something that is not an IP literal
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [host_header](../rules/host_header.md)
- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
- [x_forwarded_consistent](../rules/x_forwarded_consistent.md)
