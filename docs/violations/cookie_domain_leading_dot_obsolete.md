<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_domain_leading_dot_obsolete

Set-Cookie Domain attribute keeps the obsolete leading dot

## Message

Set-Cookie 'Domain' attribute uses a leading '.' which is deprecated; prefer the registry form without leading dot

## Specifications

- [RFC 6265 §5.2.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3): `Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035

## Configuration

```toml
[violations.cookie_domain_leading_dot_obsolete]
# Set-Cookie Domain attribute keeps the obsolete leading dot
severity = "info"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
