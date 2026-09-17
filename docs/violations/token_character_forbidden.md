<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# token_character_forbidden

Token holds a character outside tchar

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits

## Configuration

```toml
[violations.token_character_forbidden]
# Token holds a character outside tchar
severity = "warn"
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
- [charset_registered](../rules/charset_registered.md)
- [connection_header_tokens_valid](../rules/connection_header_tokens_valid.md)
- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
- [content_disposition_token_valid](../rules/content_disposition_token_valid.md)
- [content_encoding_and_type_consistent](../rules/content_encoding_and_type_consistent.md)
- [content_encoding_registered](../rules/content_encoding_registered.md)
- [content_type_valid](../rules/content_type_valid.md)
- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
- [digest_auth_valid](../rules/digest_auth_valid.md)
- [digest_header_syntax](../rules/digest_header_syntax.md)
- [expect_header_valid](../rules/expect_header_valid.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [header_field_names_token_valid](../rules/header_field_names_token_valid.md)
- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
- [link_header_valid](../rules/link_header_valid.md)
- [multipart_boundary_syntax](../rules/multipart_boundary_syntax.md)
- [pragma_token_valid](../rules/pragma_token_valid.md)
- [prefer_header_valid](../rules/prefer_header_valid.md)
- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
- [range_header_syntax](../rules/range_header_syntax.md)
- [request_method_token_valid](../rules/request_method_token_valid.md)
- [sec_websocket_extensions_syntax](../rules/sec_websocket_extensions_syntax.md)
- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
- [server_header_product_valid](../rules/server_header_product_valid.md)
- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
- [te_header_valid](../rules/te_header_valid.md)
- [trailer_header_valid](../rules/trailer_header_valid.md)
- [transfer_coding_registered](../rules/transfer_coding_registered.md)
- [upgrade_header_syntax](../rules/upgrade_header_syntax.md)
- [user_agent_token_valid](../rules/user_agent_token_valid.md)
- [vary_header_valid](../rules/vary_header_valid.md)
- [via_header_syntax](../rules/via_header_syntax.md)
- [websocket_handshake_valid](../rules/websocket_handshake_valid.md)
