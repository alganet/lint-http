<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_domain_ipv6_literal_forbidden

Set-Cookie Domain attribute is an IPv6 literal

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3): Domain matching — a cookie-domain that is not a host name matches only the identical string, so an IP address scopes the cookie to nothing it can be sent for

## Configuration

```toml
[violations.cookie_domain_ipv6_literal_forbidden]
# Set-Cookie Domain attribute is an IPv6 literal
severity = "warn"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
