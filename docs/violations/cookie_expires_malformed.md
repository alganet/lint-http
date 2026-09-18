<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_expires_malformed

Set-Cookie Expires is readable but derives from no HTTP-date

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

**It departs from that level.** The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.1.1 is a MUST on the recipient, and it reads every value this entry names. So the two sentences bracket the defect from both sides — the sender did depart from the grammar, and no conforming reader can be affected by it. There is no interoperability failure here to warn anybody about, and `warn` on traffic from most of the web's largest origins is how an operator learns to turn a whole id off.

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 6265 §5.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.1): Dates — the algorithm a user agent MUST use to parse a cookie-date: delimiter-separated tokens, `-` among the delimiters, a two-to-four-digit year, and no zone read at all

## Configuration

```toml
[violations.cookie_expires_malformed]
# Set-Cookie Expires is readable but derives from no HTTP-date
# SHOULD obliges the sender, so this defaults to warn.
# Departs from that: The SHOULD NOT is § 4.1.1's, and the sibling entries that quote it report at `warn` on the strength of it. This one cannot: § 5.1.1 is a MUST on the recipient, and it reads every value this entry names. So the two sentences bracket the defect from both sides — the sender did depart from the grammar, and no conforming reader can be affected by it. There is no interoperability failure here to warn anybody about, and `warn` on traffic from most of the web's largest origins is how an operator learns to turn a whole id off.
severity = "info"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
