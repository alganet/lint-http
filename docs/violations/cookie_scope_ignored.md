<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_scope_ignored

A cookie is sent where the store's own rules exclude it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.3): Storage Model — what a user agent stores about each cookie, and the MUST to evict every expired cookie from the store as soon as one exists in it
- [RFC 6265 §5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4): The Cookie Header — the algorithm a user agent MUST use to compute the cookie-string, whose first step excludes a cookie whose path does not path-match and one whose secure-only-flag is set on a scheme that is not secure

## Configuration

```toml
[violations.cookie_scope_ignored]
# A cookie is sent where the store's own rules exclude it
severity = "info"
```

## Reported By

- [cookie_domain_matching](../rules/cookie_domain_matching.md)
- [cookie_lifecycle](../rules/cookie_lifecycle.md)
