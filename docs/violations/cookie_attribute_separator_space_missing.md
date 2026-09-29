<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_attribute_separator_space_missing

Set-Cookie separates an attribute with ';' and no space

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

**It departs from that level.** The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.2 is a MUST on the recipient, and it discards the `;` and strips whitespace from what follows, so the missing space changes nothing any conforming user agent does. The same bracket as `cookie_expires_malformed`: the sender departed from the grammar, and no reader can be affected by it.

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 6265 §5.2](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2): The Set-Cookie Header — the algorithm a user agent MUST use to parse a set-cookie-string: it discards each attribute's leading `;` and removes leading and trailing WSP from the name and value

## Configuration

```toml
[violations.cookie_attribute_separator_space_missing]
# Set-Cookie separates an attribute with ';' and no space
# SHOULD obliges the sender, so this defaults to warn.
# Departs from that: The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.2 is a MUST on the recipient, and it discards the `;` and strips whitespace from what follows, so the missing space changes nothing any conforming user agent does. The same bracket as `cookie_expires_malformed`: the sender departed from the grammar, and no reader can be affected by it.
severity = "info"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
