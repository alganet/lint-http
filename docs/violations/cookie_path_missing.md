<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_path_missing

Set-Cookie Path attribute carries no value

## Message

Set-Cookie attribute 'Path' requires a value

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 6265 §5.2.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.2.4): Path attribute — the user agent replaces an empty or non-`/` Path with the default-path (why those forms are flagged)

## Configuration

```toml
[violations.cookie_path_missing]
# Set-Cookie Path attribute carries no value
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
- [cookie_path_valid](../rules/cookie_path_valid.md)
