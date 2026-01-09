<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Lint Rules

`lint-http` includes several built-in rules to check for HTTP best practices.

Note: rules are **disabled by default** and are enabled/configured via your TOML config; when adding rules, include docs in `docs/rules/<rule_id>.md` and register the rule in `src/rules/mod.rs`.

## Connection Rules

- [message_connection_upgrade](rules/message_connection_upgrade.md) - If `Connection` includes `upgrade`, `Upgrade` header MUST be present.

## Client Rules

- [client_accept_encoding_present](rules/client_accept_encoding_present.md) - Checks if `Accept-Encoding` header is present.
- [client_user_agent_present](rules/client_user_agent_present.md) - Checks if `User-Agent` header is present.
- [client_cache_respect](rules/client_cache_respect.md) - Verifies clients send conditional headers when re-requesting cached resources.
- [client_host_header](rules/client_host_header.md) - Ensures `Host` header is present and valid: presence, port numeric/range, IPv6 bracket rules, and no userinfo.
- [client_request_method_token_uppercase](rules/client_request_method_token_uppercase.md) - Method token should be uppercase and composed of valid token characters.
- [client_expect_header_valid](rules/client_expect_header_valid.md) - `Expect` header members must be syntactically valid; `100-continue` must not have parameters. (RFC 9110 §10.1.1)
- [client_request_target_no_fragment](rules/client_request_target_no_fragment.md) - Request-target MUST NOT include a URI fragment (`#`) in origin-form.
- [client_request_target_form_checks](rules/client_request_target_form_checks.md) - Enforce correct request-target forms: `CONNECT` uses authority-form; `*` only valid for `OPTIONS`. (RFC 9112 §2.7).
- [client_request_uri_percent_encoding_valid](rules/client_request_uri_percent_encoding_valid.md) - Percent-encodings in the request-target must be well-formed (`%` followed by two hex digits). (RFC 3986 §2.1)
- [client_range_header_syntax_valid](rules/client_range_header_syntax_valid.md) - `Range` header value must match byte-range-set syntax when present. (RFC 9110 §14.1.2)

## Server Rules

- [server_cache_control_present](rules/server_cache_control_present.md) - Checks for `Cache-Control` header on cacheable responses.
- [server_etag_or_last_modified](rules/server_etag_or_last_modified.md) - Checks for `ETag` or `Last-Modified` headers.
- [server_last_modified_rfc1123_format](rules/server_last_modified_rfc1123_format.md) - Ensures `Last-Modified` header uses IMF-fixdate (RFC 9110 §7.7.1).
- [server_location_header_uri_valid](rules/server_location_header_uri_valid.md) - `Location` header value should be a valid URI-reference.
- [server_response_location_on_redirect](rules/server_response_location_on_redirect.md) - Redirect responses SHOULD include `Location` header when semantics require it (RFC 9110 §10.2.2, §15.4).
- [server_x_content_type_options](rules/server_x_content_type_options.md) - Checks for `X-Content-Type-Options: nosniff`.
- [server_response_405_allow](rules/server_response_405_allow.md) - Checks `Allow` header is present on `405` responses.
- [server_charset_specification](rules/server_charset_specification.md) - Checks text-based `Content-Type` headers include charset parameter.
- [server_clear_site_data](rules/server_clear_site_data.md) - Checks logout endpoints include `Clear-Site-Data` header (configurable paths).
- [server_no_body_for_1xx_204_304](rules/server_no_body_for_1xx_204_304.md) - Flags responses with status 1xx, 204, or 304 that appear to include a message body.
- [server_status_code_valid_range](rules/server_status_code_valid_range.md) - HTTP response status codes must be in the range 100–599.
- [server_content_type_present](rules/server_content_type_present.md) - Ensure responses that likely contain a body include `Content-Type`.
- [server_accept_ranges_values_valid](rules/server_accept_ranges_values_valid.md) - `Accept-Ranges` should be either `bytes` or `none` and `none` must not be combined with other values. (RFC 9110 §7.3.4)


## Message Rules

- [message_content_type_well_formed](rules/message_content_type_well_formed.md) - Validates `Content-Type` header parses as a `media-type` with valid type/subtype and parameters.
- [message_http_version_syntax_valid](rules/message_http_version_syntax_valid.md) - Start-line `HTTP-version` must match `HTTP/DIGIT.DIGIT` (RFC 9112 §2.3).
- [message_content_length_vs_transfer_encoding](rules/message_content_length_vs_transfer_encoding.md) - Flags messages that include both `Content-Length` and `Transfer-Encoding`.
- [message_content_length](rules/message_content_length.md) - Validates Content-Length values and multiple Content-Length header consistency.
- [message_header_field_names_token](rules/message_header_field_names_token.md) - Validates header field-names conform to the `token` grammar.
- [message_transfer_encoding_chunked_final](rules/message_transfer_encoding_chunked_final.md) - Ensures `chunked` (when used) is the final transfer-coding in `Transfer-Encoding` headers.
- [message_via_header_syntax_valid](rules/message_via_header_syntax_valid.md) - `Via` header values must follow the field-value syntax.
- [message_connection_header_tokens_valid](rules/message_connection_header_tokens_valid.md) - `Connection` header tokens must be valid header field-names (token grammar).
- [message_retry_after_date_or_delay](rules/message_retry_after_date_or_delay.md) - `Retry-After` must be either an HTTP-date or a non-negative delay-seconds.
- [message_age_header_numeric](rules/message_age_header_numeric.md) - `Age` header value must be a non-negative integer (delta-seconds).
