<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_domain_leading_dot_obsolete

Set-Cookie Domain attribute keeps the obsolete leading dot

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

**It departs from that level.** The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.2.3 is a MUST on the recipient, and its first step strips the leading dot, so the cookie-domain is the one the server would have written without it and nothing any conforming user agent does changes. The same bracket as `cookie_attribute_separator_space_missing` and `cookie_expires_malformed`.

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 6265 §5.2.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.3): `Domain` attribute processing — an empty value is undefined (the user agent ignores it) and a leading dot is stripped; the value's *format* is § 4.1.1 and RFC 1035

## Configuration

```toml
[violations.cookie_domain_leading_dot_obsolete]
# Set-Cookie Domain attribute keeps the obsolete leading dot
# SHOULD obliges the sender, so this defaults to warn.
# Departs from that: The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.2.3 is a MUST on the recipient, and its first step strips the leading dot, so the cookie-domain is the one the server would have written without it and nothing any conforming user agent does changes. The same bracket as `cookie_attribute_separator_space_missing` and `cookie_expires_malformed`.
severity = "info"
```

## Reported By

- [cookie_domain_valid](../rules/cookie_domain_valid.md)
