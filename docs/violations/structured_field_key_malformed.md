<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# structured_field_key_malformed

Structured field key is not a key production

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails

## Configuration

```toml
[violations.structured_field_key_malformed]
# Structured field key is not a key production
severity = "warn"
```

## Reported By

- [deprecation_header_syntax](../rules/deprecation_header_syntax.md)
- [digest_header_syntax](../rules/digest_header_syntax.md)
- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
- [priority_header_syntax](../rules/priority_header_syntax.md)
- [sec_fetch_dest_value_valid](../rules/sec_fetch_dest_value_valid.md)
- [sec_fetch_mode_value_valid](../rules/sec_fetch_mode_value_valid.md)
- [sec_fetch_site_value_valid](../rules/sec_fetch_site_value_valid.md)
- [sec_fetch_storage_access_value_valid](../rules/sec_fetch_storage_access_value_valid.md)
- [sec_fetch_user_value_valid](../rules/sec_fetch_user_value_valid.md)
- [structured_headers_valid](../rules/structured_headers_valid.md)
