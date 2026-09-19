<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_domain_missing

Set-Cookie Domain attribute carries no value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.2.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3): `Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035

## Configuration

```toml
[violations.cookie_domain_missing]
# Set-Cookie Domain attribute carries no value
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
- [cookie_domain_valid](../rules/cookie_domain_valid.md)
