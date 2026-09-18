<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# list_member_empty

List holds an empty element

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element

## Configuration

```toml
[violations.list_member_empty]
# List holds an empty element
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [accept_encoding_parameter_valid](../rules/accept_encoding_parameter_valid.md)
- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [accept_ranges_values_valid](../rules/accept_ranges_values_valid.md)
- [allow_header_method_tokens_valid](../rules/allow_header_method_tokens_valid.md)
- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
- [cache_control_token_valid](../rules/cache_control_token_valid.md)
- [caching_directive_interaction](../rules/caching_directive_interaction.md)
- [conditional_etag_syntax](../rules/conditional_etag_syntax.md)
- [connection_header_tokens_valid](../rules/connection_header_tokens_valid.md)
- [content_encoding_and_type_consistent](../rules/content_encoding_and_type_consistent.md)
- [digest_auth_valid](../rules/digest_auth_valid.md)
- [expect_header_valid](../rules/expect_header_valid.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [language_tag_syntax](../rules/language_tag_syntax.md)
- [link_header_valid](../rules/link_header_valid.md)
- [pragma_token_valid](../rules/pragma_token_valid.md)
- [prefer_header_valid](../rules/prefer_header_valid.md)
- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
- [range_header_syntax](../rules/range_header_syntax.md)
- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
- [te_header_valid](../rules/te_header_valid.md)
- [timing_allow_origin_valid](../rules/timing_allow_origin_valid.md)
- [trailer_header_valid](../rules/trailer_header_valid.md)
- [upgrade_header_syntax](../rules/upgrade_header_syntax.md)
- [vary_header_valid](../rules/vary_header_valid.md)
- [via_header_syntax](../rules/via_header_syntax.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
