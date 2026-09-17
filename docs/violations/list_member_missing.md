<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# list_member_missing

List with a one-element floor holds no element

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements

## Configuration

```toml
[violations.list_member_missing]
# List with a one-element floor holds no element
severity = "warn"
```

## Reported By

- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [accept_ranges_values_valid](../rules/accept_ranges_values_valid.md)
- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [prefer_header_valid](../rules/prefer_header_valid.md)
- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
- [range_header_syntax](../rules/range_header_syntax.md)
- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
- [timing_allow_origin_valid](../rules/timing_allow_origin_valid.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
