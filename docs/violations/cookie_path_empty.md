<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_path_empty

Set-Cookie Path attribute is empty

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)

## Configuration

```toml
[violations.cookie_path_empty]
# Set-Cookie Path attribute is empty
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
- [cookie_path_valid](../rules/cookie_path_valid.md)
