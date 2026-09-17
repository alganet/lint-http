<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_secure_ignored

A Secure cookie is sent over a scheme that is not secure

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4): The Cookie Header — the algorithm a user agent MUST use to compute the cookie-string, whose first step excludes a cookie whose path does not path-match and one whose secure-only-flag is set on a scheme that is not secure

## Configuration

```toml
[violations.cookie_secure_ignored]
# A Secure cookie is sent over a scheme that is not secure
severity = "warn"
```

## Reported By

- [cookie_lifecycle](../rules/cookie_lifecycle.md)
