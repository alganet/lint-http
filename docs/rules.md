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
- [client_request_origin_header_present_for_cors](rules/client_request_origin_header_present_for_cors.md) - CORS preflight requests and cross-origin absolute-form requests should include an `Origin` header. (RFC 6454)
- [client_request_uri_percent_encoding_valid](rules/client_request_uri_percent_encoding_valid.md) - Percent-encodings in the request-target must be well-formed (`%` followed by two hex digits). (RFC 3986 §2.1)
- [client_range_header_syntax_valid](rules/client_range_header_syntax_valid.md) - `Range` header value must match byte-range-set syntax when present. (RFC 9110 §14.1.2)

## Server Rules

- [server_cache_control_present](rules/server_cache_control_present.md) - Checks for `Cache-Control` header on cacheable responses.
- [server_etag_or_last_modified](rules/server_etag_or_last_modified.md) - Checks for `ETag` or `Last-Modified` headers.
- [server_last_modified_rfc1123_format](rules/server_last_modified_rfc1123_format.md) - Ensures `Last-Modified` header uses IMF-fixdate (RFC 9110 §7.7.1).
- [server_location_header_uri_valid](rules/server_location_header_uri_valid.md) - `Location` header value should be a valid URI-reference.
- [server_response_location_on_redirect](rules/server_response_location_on_redirect.md) - Redirect responses SHOULD include `Location` header when semantics require it (RFC 9110 §10.2.2, §15.4).
- [server_x_content_type_options](rules/server_x_content_type_options.md) - Checks for `X-Content-Type-Options: nosniff`.
- [server_x_frame_options_value_valid](rules/server_x_frame_options_value_valid.md) - `X-Frame-Options` header must be `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <origin>` and must not appear multiple times. (RFC 7034 §2.1)
- [server_x_xss_protection_value_valid](rules/server_x_xss_protection_value_valid.md) - `X-XSS-Protection` header value should be `0` or `1; mode=block` when present (case-insensitive). (MDN)
- [server_response_405_allow](rules/server_response_405_allow.md) - Checks `Allow` header is present on `405` responses.
- [server_charset_specification](rules/server_charset_specification.md) - Checks text-based `Content-Type` headers include charset parameter.
- [server_clear_site_data](rules/server_clear_site_data.md) - Checks logout endpoints include `Clear-Site-Data` header (configurable paths).
- [server_no_body_for_1xx_204_304](rules/server_no_body_for_1xx_204_304.md) - Flags responses with status 1xx, 204, or 304 that appear to include a message body.
- [server_status_code_valid_range](rules/server_status_code_valid_range.md) - HTTP response status codes must be in the range 100–599.
- [server_content_type_present](rules/server_content_type_present.md) - Ensure responses that likely contain a body include `Content-Type`.
- [server_accept_ranges_values_valid](rules/server_accept_ranges_values_valid.md) - `Accept-Ranges` should be either `bytes` or `none` and `none` must not be combined with other values. (RFC 9110 §7.3.4)
- [server_vary_header_valid](rules/server_vary_header_valid.md) - `Vary` header value must be `*` or a list of header field-names. (RFC 9110 §7.3.6)
- [server_patch_accept_patch_header](rules/server_patch_accept_patch_header.md) - `PATCH` responses should include `Accept-Patch` to declare supported patch media types. (RFC 5789 §2.2)
- [server_server_timing_header_syntax](rules/server_server_timing_header_syntax.md) - `Server-Timing` header metrics must use valid metric-name and metric-parameter syntax (token-based names and parameters). (W3C Server-Timing spec §3)
- [server_alt_svc_header_syntax](rules/server_alt_svc_header_syntax.md) - `Alt-Svc` header must follow `protocol=authority` syntax. (RFC 7838)


## Message Rules

- [message_content_type_well_formed](rules/message_content_type_well_formed.md) - Validates `Content-Type` header parses as a `media-type` with valid type/subtype and parameters.
- [message_language_tag_format_valid](rules/message_language_tag_format_valid.md) - Validates `Content-Language` and `Accept-Language` language-tags follow BCP 47-style syntax (RFC 5646).
- [message_access_control_allow_credentials_when_origin](rules/message_access_control_allow_credentials_when_origin.md) - If `Access-Control-Allow-Origin` is `*`, `Access-Control-Allow-Credentials` must not be `true`. (CORS)
- [message_access_control_allow_origin_valid](rules/message_access_control_allow_origin_valid.md) - `Access-Control-Allow-Origin` must be a single value: `*`, `null`, or a serialized origin (`scheme://host[:port]`). (CORS)
- [message_cross_origin_opener_policy_valid](rules/message_cross_origin_opener_policy_valid.md) - `Cross-Origin-Opener-Policy` must be `same-origin`, `same-origin-allow-popups`, or `unsafe-none`. (W3C / Fetch)
- [message_cross_origin_resource_policy_valid](rules/message_cross_origin_resource_policy_valid.md) - `Cross-Origin-Resource-Policy` must be `same-site`, `same-origin`, or `cross-origin`. (W3C / MDN)
- [message_cross_origin_embedder_policy_valid](rules/message_cross_origin_embedder_policy_valid.md) - `Cross-Origin-Embedder-Policy` should be `require-corp` or `credentialless` (W3C / MDN)
- [message_referer_uri_valid](rules/message_referer_uri_valid.md) - `Referer` header value should be a valid URI-reference. (RFC 9110 §7.5.3)
- [message_from_header_email_syntax](rules/message_from_header_email_syntax.md) - `From` header should be a valid mailbox-list (addr-spec or display-name <addr-spec>). (RFC 9110 §7.1.1, RFC 5322 §3.4)
- [message_max_forwards_numeric](rules/message_max_forwards_numeric.md) - `Max-Forwards` header value must be a non-negative decimal integer (RFC 9110 §7.6.2)
- [message_content_encoding_iana_registered](rules/message_content_encoding_iana_registered.md) - Validates `Content-Encoding` and `Accept-Encoding` tokens are IANA-registered or explicitly allowed; flags invalid tokens. (RFC 9110 §5.3)
- [message_transfer_coding_iana_registered](rules/message_transfer_coding_iana_registered.md) - Validates `Transfer-Encoding` and `TE` transfer-coding tokens are IANA-registered or explicitly allowed; `TE: trailers` is accepted. (RFC 9112 §6.1, RFC 9110 §10.1.4)
- [message_digest_header_syntax](rules/message_digest_header_syntax.md) - `Content-Digest`/`Repr-Digest`/`Want-*` fields must follow RFC 9530 structured syntax; legacy `Digest`/`Content-MD5` are deprecated. (RFC 9530 §2–§4)
- [message_if_none_match_etag_syntax](rules/message_if_none_match_etag_syntax.md) - `If-None-Match` header must be `*` or a comma-separated list of valid entity-tags (ETags). (RFC 9110 §7.6, §7.8.4)
- [message_http_version_syntax_valid](rules/message_http_version_syntax_valid.md) - Start-line `HTTP-version` must match `HTTP/DIGIT.DIGIT` (RFC 9112 §2.3).
- [message_content_length_vs_transfer_encoding](rules/message_content_length_vs_transfer_encoding.md) - Flags messages that include both `Content-Length` and `Transfer-Encoding`.
- [message_content_length](rules/message_content_length.md) - Validates Content-Length values and multiple Content-Length header consistency.
- [message_range_and_content_range_consistency](rules/message_range_and_content_range_consistency.md) - Validate Range/Content-Range semantics for 206/416 and Content-Length consistency.
- [message_header_field_names_token](rules/message_header_field_names_token.md) - Validates header field-names conform to the `token` grammar.
- [message_transfer_encoding_chunked_final](rules/message_transfer_encoding_chunked_final.md) - Ensures `chunked` (when used) is the final transfer-coding in `Transfer-Encoding` headers.
- [message_te_header_constraints](rules/message_te_header_constraints.md) - `TE` header must use only valid members (transfer-coding or `trailers`), valid parameters (e.g., `q` with up to three decimals), and requests with `TE` must include `Connection: TE`.
- [message_via_header_syntax_valid](rules/message_via_header_syntax_valid.md) - `Via` header values must follow the field-value syntax.
- [message_connection_header_tokens_valid](rules/message_connection_header_tokens_valid.md) - `Connection` header tokens must be valid header field-names (token grammar).
- [message_retry_after_date_or_delay](rules/message_retry_after_date_or_delay.md) - `Retry-After` must be either an HTTP-date or a non-negative delay-seconds.
- [message_prefer_header_valid](rules/message_prefer_header_valid.md) - `Prefer` header directives and parameters must be syntactically valid. (RFC 7240 §2)
- [message_allow_header_method_tokens](rules/message_allow_header_method_tokens.md) - `Allow` header must contain valid HTTP method tokens. (RFC 9110 §7.1.1)
- [message_age_header_numeric](rules/message_age_header_numeric.md) - `Age` header value must be a non-negative integer (delta-seconds).
