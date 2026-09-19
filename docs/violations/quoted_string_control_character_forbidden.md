<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# quoted_string_control_character_forbidden

Quoted-string holds a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[violations.quoted_string_control_character_forbidden]
# Quoted-string holds a control character
# GRAMMAR obliges the sender, so this defaults to error.
# No input this tool accepts reaches this defect: the octet this names is a control octet, and no route carries one to the rules: on the wire the parser refuses the message before there is a transaction, and from a capture file `HeaderValue` refuses the record -- 0x7f with the rest of the class
severity = "error"
```

## Reported By

- [accept_header_media_type_syntax](../rules/accept_header_media_type_syntax.md)
- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
- [cache_control_token_valid](../rules/cache_control_token_valid.md)
- [charset_registered](../rules/charset_registered.md)
- [content_disposition_parameter_valid](../rules/content_disposition_parameter_valid.md)
- [content_type_valid](../rules/content_type_valid.md)
- [digest_auth_valid](../rules/digest_auth_valid.md)
- [expect_header_valid](../rules/expect_header_valid.md)
- [form_data_content_disposition_valid](../rules/form_data_content_disposition_valid.md)
- [forwarded_header_valid](../rules/forwarded_header_valid.md)
- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
- [link_header_valid](../rules/link_header_valid.md)
- [multipart_boundary_syntax](../rules/multipart_boundary_syntax.md)
- [pragma_token_valid](../rules/pragma_token_valid.md)
- [prefer_header_valid](../rules/prefer_header_valid.md)
- [preference_applied_header_valid](../rules/preference_applied_header_valid.md)
- [proxy_authenticate_challenge_syntax](../rules/proxy_authenticate_challenge_syntax.md)
- [sec_websocket_extensions_syntax](../rules/sec_websocket_extensions_syntax.md)
- [server_timing_header_syntax](../rules/server_timing_header_syntax.md)
- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
- [te_header_valid](../rules/te_header_valid.md)
- [warning_header_syntax](../rules/warning_header_syntax.md)
- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
