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
- [client_sec_websocket_headers_consistency](rules/client_sec_websocket_headers_consistency.md) - Validates WebSocket handshake request headers: `Upgrade`, `Connection`, `Sec-WebSocket-Key` and `Sec-WebSocket-Version` (RFC 6455).
- [client_cache_respect](rules/client_cache_respect.md) - Verifies clients send conditional headers when re-requesting cached resources.
- [stateful_conditional_request_handling](rules/stateful_conditional_request_handling.md) - Ensure conditional requests are only sent after observing validators (ETag/Last-Modified); recommend `304` for conditional `GET`/`HEAD` when validators match. (RFC 9110 §7.8)
- [client_host_header](rules/client_host_header.md) - Ensures `Host` header is present and valid: presence, port numeric/range, IPv6 bracket rules, and no userinfo.
- [client_request_method_token_valid](rules/client_request_method_token_valid.md) - Method token must match the `token` grammar with uppercase alphabetic characters. (RFC 9112 §5.1)
- [client_request_method_body_consistency](rules/client_request_method_body_consistency.md) - Flags unexpected request message bodies on safe methods (GET, HEAD). (RFC 9110 §6.3)
- [client_patch_method_content_type_match](rules/client_patch_method_content_type_match.md) - If previous response advertised `Accept-Patch`, `PATCH` requests SHOULD use `Content-Type` matching one of the advertised media types. (RFC 5789 §2.2)
- [client_expect_header_valid](rules/client_expect_header_valid.md) - `Expect` header members must be syntactically valid; `100-continue` must not have parameters. (RFC 9110 §10.1.1)
- [client_request_target_no_fragment](rules/client_request_target_no_fragment.md) - Request-target MUST NOT include a URI fragment (`#`) in origin-form.
- [client_request_target_form_checks](rules/client_request_target_form_checks.md) - Enforce correct request-target forms: `CONNECT` uses authority-form; `*` only valid for `OPTIONS`. (RFC 9112 §2.7).
- [client_request_origin_header_present_for_cors](rules/client_request_origin_header_present_for_cors.md) - CORS preflight requests and cross-origin absolute-form requests should include an `Origin` header. (RFC 6454)
- [semantic_origin_matching_for_cors](rules/semantic_origin_matching_for_cors.md) - `Access-Control-Allow-Origin` must match the request `Origin`, and `*` is forbidden when credentials are allowed. (RFC 6454, Fetch CORS)
- [client_accept_ranges_on_partial_content](rules/client_accept_ranges_on_partial_content.md) - Clients should track `Accept-Ranges` advertised by servers and avoid sending `Range` requests when server advertises `none` or a previous `206` did not advertise support. (RFC 9110 §7.3.4; RFC 7233 §4.1)
- [client_request_uri_percent_encoding_valid](rules/client_request_uri_percent_encoding_valid.md) - Percent-encodings in the request-target must be well-formed (`%` followed by two hex digits). (RFC 3986 §2.1)
- [client_range_header_syntax_valid](rules/client_range_header_syntax_valid.md) - `Range` header value must match byte-range-set syntax when present. (RFC 9110 §14.1.2)

## Server Rules

- [server_cache_control_present](rules/server_cache_control_present.md) - Checks for `Cache-Control` header on cacheable responses.
- [server_status_and_caching_semantics](rules/server_status_and_caching_semantics.md) - Certain status codes are cacheable by default; other responses require explicit freshness directives (Cache-Control: max-age/s-maxage or Expires). (RFC 9111 §3)
- [server_etag_or_last_modified](rules/server_etag_or_last_modified.md) - Checks for `ETag` or `Last-Modified` headers.
- [message_etag_syntax](rules/message_etag_syntax.md) - Validates `ETag` header is a single, syntactically valid entity-tag (strong or weak); flags invalid `*` usage and multiple header fields. (RFC 9110 §7.6, §8.8.3)
- [server_last_modified_rfc1123_format](rules/server_last_modified_rfc1123_format.md) - Ensures `Last-Modified` header uses IMF-fixdate (RFC 9110 §7.7.1).
- [server_location_header_uri_valid](rules/server_location_header_uri_valid.md) - `Location` header value should be a valid URI-reference.
- [server_response_location_on_redirect](rules/server_response_location_on_redirect.md) - Redirect responses SHOULD include `Location` header when semantics require it (RFC 9110 §10.2.2, §15.4).
- [server_redirect_status_and_location_validity](rules/server_redirect_status_and_location_validity.md) - `Location` should only appear on redirect or creation responses; presence on other statuses may indicate misconfiguration. (RFC 9110 §10.2.2, §15.4)
- [server_retry_after_status_validity](rules/server_retry_after_status_validity.md) - `Retry-After` is expected on 503, 429, or 3xx responses; other statuses are unusual. (RFC 9110 §10.2.3, RFC 6585 §4)
- [stateful_redirect_chain_validity](rules/stateful_redirect_chain_validity.md) - Detect circular redirects and repeated redirect targets for the same client+resource; helps identify redirect loops and misconfigurations. (RFC 9110 §6.4)
- [stateful_103_early_hints_before_final](rules/stateful_103_early_hints_before_final.md) - Ensure `103 Early Hints` responses are sent *before* the final response for the same client+resource; flags `103` observed after a final response. (RFC 8297)
- [server_3xx_vs_request_method](rules/server_3xx_vs_request_method.md) - When responding to unsafe request methods (POST/PUT/PATCH/DELETE), prefer 303 to redirect-to-GET or 307/308 to preserve method and body; 301/302 are historically ambiguous. (RFC 9110 §6.4)
- [server_x_content_type_options](rules/server_x_content_type_options.md) - Checks for `X-Content-Type-Options: nosniff`.
- [server_problem_details_content_type](rules/server_problem_details_content_type.md) - Problem Details responses SHOULD use `application/problem+json` or `application/problem+xml`. (RFC 7807)
- [message_problem_details_structure](rules/message_problem_details_structure.md) - `application/problem+json` responses for 4xx/5xx SHOULD include a non-empty JSON problem object; when a captured or explicit `Content-Length` is zero this is likely an error. (RFC 7807 §3.1)
- [server_x_frame_options_value_valid](rules/server_x_frame_options_value_valid.md) - `X-Frame-Options` header must be `DENY`, `SAMEORIGIN`, or `ALLOW-FROM <origin>` and must not appear multiple times. (RFC 7034 §2.1)
- [server_x_xss_protection_value_valid](rules/server_x_xss_protection_value_valid.md) - `X-XSS-Protection` header value should be `0` or `1; mode=block` when present (case-insensitive). (MDN)
- [server_content_security_policy_validity](rules/server_content_security_policy_validity.md) - Validates basic `Content-Security-Policy` directive syntax and common structural issues (unterminated quotes, empty directives). (W3C CSP)
- [message_strict_transport_security_validity](rules/message_strict_transport_security_validity.md) - Validates `Strict-Transport-Security` header directives: `max-age` required (numeric), `includeSubDomains` and `preload` must not have values. (RFC 6797)
- [message_content_security_policy_and_frame_options_consistency](rules/message_content_security_policy_and_frame_options_consistency.md) - Warn when `Content-Security-Policy: frame-ancestors` contradicts `X-Frame-Options` (`DENY`, `SAMEORIGIN`, `ALLOW-FROM`), which may cause inconsistent framing behavior across user agents.
- [server_response_405_allow](rules/server_response_405_allow.md) - Checks `Allow` header is present on `405` responses.
- [server_charset_specification](rules/server_charset_specification.md) - Checks text-based `Content-Type` headers include charset parameter.
- [server_clear_site_data](rules/server_clear_site_data.md) - Checks logout endpoints include `Clear-Site-Data` header (configurable paths).
- [server_no_body_for_1xx_204_304](rules/server_no_body_for_1xx_204_304.md) - Flags responses with status 1xx, 204, or 304 that appear to include a message body.
- [server_200_vs_204_body_consistency](rules/server_200_vs_204_body_consistency.md) - Warn when a 200 (OK) response contains no body (e.g., `Content-Length: 0`); consider using `204 No Content` instead. (RFC 9110 §15.3.1)
- [server_status_code_valid_range](rules/server_status_code_valid_range.md) - HTTP response status codes must be in the range 100–599.
- [server_content_type_present](rules/server_content_type_present.md) - Ensure responses that likely contain a body include `Content-Type`.
- [server_accept_ranges_values_valid](rules/server_accept_ranges_values_valid.md) - `Accept-Ranges` should be either `bytes` or `none` and `none` must not be combined with other values. (RFC 9110 §7.3.4)
- [message_accept_ranges_and_206_consistency](rules/message_accept_ranges_and_206_consistency.md) - If response is `206` (Partial Content), `Accept-Ranges` SHOULD indicate support (e.g., `bytes`) and must not be `none`. (RFC 7233 §4.1; RFC 9110 §7.3.4)
- [server_vary_header_valid](rules/server_vary_header_valid.md) - `Vary` header value must be `*` or a list of header field-names. (RFC 9110 §7.3.6)
- [server_vary_and_cache_consistency](rules/server_vary_and_cache_consistency.md) - Warn when `Vary: *` is present alongside cacheability directives such as `Cache-Control: max-age`/`s-maxage`/`public` because `Vary: *` prevents caches from selecting stored responses. (RFC 7234 §4.1)
- [server_patch_accept_patch_header](rules/server_patch_accept_patch_header.md) - `PATCH` responses should include `Accept-Patch` to declare supported patch media types. (RFC 5789 §2.2)
- [server_server_timing_header_syntax](rules/server_server_timing_header_syntax.md) - `Server-Timing` header metrics must use valid metric-name and metric-parameter syntax (token-based names and parameters). (W3C Server-Timing spec §3)
- [server_authentication_challenge_validity](rules/server_authentication_challenge_validity.md) - `WWW-Authenticate` challenges SHOULD avoid advertising the same `realm` value across different auth-schemes to prevent protection-space ambiguity. (RFC 9110 §11.5)
- [semantic_status_code_semantics](rules/semantic_status_code_semantics.md) - Warn on clear mismatches between status codes and response headers/payloads (e.g., missing `WWW-Authenticate` on `401`, or `WWW-Authenticate` present on a non-`401`). (RFC 9110 §6, §15.5.1, §15.6.1)
- [semantic_head_response_headers_match_get](rules/semantic_head_response_headers_match_get.md) - `HEAD` responses SHOULD include the same header fields the server would send for `GET` on the same resource. This rule requires a `headers` array in configuration (no default); special-cases: `Content-Length`, `Transfer-Encoding`, and `Vary` follow RFC 9110 §9.3.2.
- [semantic_trace_method_echo](rules/semantic_trace_method_echo.md) - TRACE requests must not carry content; when TRACE responses carry content, they should use `Content-Type: message/http`. (RFC 9110 §9.3.8)
- [server_keep_alive_timeout_reasonable](rules/server_keep_alive_timeout_reasonable.md) - `Keep-Alive: timeout` directive should be a positive integer and within reasonable bounds (not zero or extremely large). (RFC 7230 §6.7)
- [message_server_header_product_valid](rules/message_server_header_product_valid.md) - Validates `Server` header product tokens and optional versions; allows parenthesized comments. (RFC 9110 §7.1.1)
- [server_deprecation_header_syntax](rules/server_deprecation_header_syntax.md) - `Deprecation` header must be a structured date item (e.g., `@1688169599`) per RFC 9745; legacy forms (`true` or HTTP-date) are deprecated.
- [server_priority_and_cacheability_consistency](rules/server_priority_and_cacheability_consistency.md) - When a server emits `Priority` in a response, it should control cacheability using `Cache-Control` and/or `Vary` (RFC 9218 §5).
- [server_alt_svc_header_syntax](rules/server_alt_svc_header_syntax.md) - `Alt-Svc` header must follow `protocol=authority` syntax. (RFC 7838)
- [server_alt_svc_protocol_iana_registered](rules/server_alt_svc_protocol_iana_registered.md) - `Alt-Svc` protocol identifiers SHOULD be IANA-registered or match an allowlist (e.g., `h2`, `h3`). (RFC 7838)
- [server_must_revalidate_and_immutable_mismatch](rules/server_must_revalidate_and_immutable_mismatch.md) - `Cache-Control` MUST NOT include both `must-revalidate` and `immutable` as they conflict in caching semantics. (RFC 9111 §5.2.2.2; RFC 8246)

## Message Rules

- [message_content_type_well_formed](rules/message_content_type_well_formed.md) - Validates `Content-Type` header parses as a `media-type` with valid type/subtype and parameters.
- [message_content_type_iana_registered](rules/message_content_type_iana_registered.md) - `Content-Type` media types SHOULD be IANA-registered or match an allowlist; supports `type/subtype`, `type/*`, and `+suffix` patterns.
- [message_media_type_suffix_validity](rules/message_media_type_suffix_validity.md) - Flags media types using unknown `+suffix` structured-syntax suffixes (e.g., `+json`, `+xml`). (RFC 6838)
- [message_charset_iana_registered](rules/message_charset_iana_registered.md) - If `Content-Type` includes a `charset` parameter, its value SHOULD be an IANA-registered character set name or match an allowlist. (RFC 9110 §6.4)
- [message_multipart_boundary_syntax](rules/message_multipart_boundary_syntax.md) - `multipart/*` Content-Type must include a `boundary` parameter; boundary value must be 1..70 characters, not end with whitespace, and use allowed characters. (RFC 2046 §5.1.1)
- [message_multipart_content_type_and_body_consistency](rules/message_multipart_content_type_and_body_consistency.md) - When `Content-Type` is `multipart/*` and a body is captured, the body MUST contain boundary markers (`--<boundary>`) and a terminating marker (`--<boundary>--`). (RFC 2046 §5.1.1)
- [message_content_disposition_token_valid](rules/message_content_disposition_token_valid.md) - `Content-Disposition` header disposition-type must be a valid token. (RFC 6266 §4)
- [message_content_disposition_parameter_validity](rules/message_content_disposition_parameter_validity.md) - `Content-Disposition` parameters such as `filename`, `filename*` and `size` must be syntactically valid (RFC 6266 §4, RFC 5987 §3.2)
- [message_form_data_content_disposition_valid](rules/message_form_data_content_disposition_valid.md) - `Content-Disposition: form-data` parts MUST include a non-empty `name` parameter (RFC 7578 §4.2)
- [message_accept_header_media_type_syntax](rules/message_accept_header_media_type_syntax.md) - Validates `Accept` header media-range syntax, parameters, and `q` values. (RFC 9110 §7.2.1)
- [message_accept_and_content_type_negotiation](rules/message_accept_and_content_type_negotiation.md) - Warn when response `Content-Type` does not match the request's `Accept` header; consider returning 406 Not Acceptable. (RFC 9110 §12.5.1)
- [message_cache_control_token_valid](rules/message_cache_control_token_valid.md) - `Cache-Control` directive names and unquoted values must follow the `token` grammar; quoted-string values are validated as such. (RFC 9110 §5.2)
- [message_expires_and_cache_control_consistency](rules/message_expires_and_cache_control_consistency.md) - If `Expires` and `Cache-Control` both present, values should not contradict; `Cache-Control` takes precedence. (RFC 9111 §5.3)
- [message_cache_control_directive_validity](rules/message_cache_control_directive_validity.md) - Validate directive-specific `Cache-Control` argument formats (e.g., numeric `max-age`, field-name lists for `private`/`no-cache`). (RFC 9110 §5.2)
- [message_caching_directive_interaction](rules/message_caching_directive_interaction.md) - Detect contradictory or redundant `Cache-Control` directive combinations (e.g., `public` with `private`, `no-store` with visibility directives, `no-cache` with `max-age=0`). (RFC 9111 §3)
- [message_cache_control_and_pragma_consistency](rules/message_cache_control_and_pragma_consistency.md) - If `Pragma: no-cache` and `Cache-Control` appear together, detect contradictions (e.g., `only-if-cached` vs `no-cache`) and flag `Pragma` usage in responses (RFC 7234 §5.4). (RFC 7234 §5.4)
- [message_pragma_token_valid](rules/message_pragma_token_valid.md) - `Pragma` header directives must follow `token` or `token="quoted-string"` syntax. (RFC 9110 §8.2)
- [message_priority_header_syntax](rules/message_priority_header_syntax.md) - `Priority` header must follow `u` (urgency 0..7) and optional `i` (incremental boolean) parameter syntax. (RFC 9218 §4–§5)
- [message_structured_headers_validity](rules/message_structured_headers_validity.md) - Validates configured headers follow RFC 8941 Structured Field syntax (Item/List/Dictionary). (RFC 8941)
- [message_permissions_policy_directives_valid](rules/message_permissions_policy_directives_valid.md) - Validates `Permissions-Policy` directives are well-formed, feature identifiers are valid, member values are correct forms, and `report-to` (if present) is a quoted-string. (W3C Permissions Policy §5.2; RFC 8941 §5.2)
- [message_language_tag_format_valid](rules/message_language_tag_format_valid.md) - Validates `Content-Language` and `Accept-Language` language-tags follow BCP 47-style syntax (RFC 5646).
- [message_user_agent_token_valid](rules/message_user_agent_token_valid.md) - Validates `User-Agent` header product tokens and optional versions; allows parenthesized comments. (RFC 9110 §10.1.5)
- [message_access_control_allow_credentials_when_origin](rules/message_access_control_allow_credentials_when_origin.md) - If `Access-Control-Allow-Origin` is `*`, `Access-Control-Allow-Credentials` must not be `true`. (CORS)
- [message_access_control_allow_origin_valid](rules/message_access_control_allow_origin_valid.md) - `Access-Control-Allow-Origin` must be a single value: `*`, `null`, or a serialized origin (`scheme://host[:port]`). (CORS)
- [message_timing_allow_origin_validity](rules/message_timing_allow_origin_validity.md) - `Timing-Allow-Origin` header values must be `*`, `null`, or serialized origin(s) (`scheme://host[:port]`) (W3C Resource Timing §4.5.1)
- [message_cross_origin_opener_policy_valid](rules/message_cross_origin_opener_policy_valid.md) - `Cross-Origin-Opener-Policy` must be `same-origin`, `same-origin-allow-popups`, or `unsafe-none`. (W3C / Fetch)
- [message_cross_origin_resource_policy_valid](rules/message_cross_origin_resource_policy_valid.md) - `Cross-Origin-Resource-Policy` must be `same-site`, `same-origin`, or `cross-origin`. (W3C / MDN)
- [message_cross_origin_embedder_policy_valid](rules/message_cross_origin_embedder_policy_valid.md) - `Cross-Origin-Embedder-Policy` should be `require-corp` or `credentialless` (W3C / MDN)
- [message_origin_isolated_header_validity](rules/message_origin_isolated_header_validity.md) - `Origin-Isolation` header must be a single structured-headers boolean `?1` to enable origin isolation. (Origin Isolation explainer)
- [message_sec_fetch_site_value_valid](rules/message_sec_fetch_site_value_valid.md) - `Sec-Fetch-Site` must be one of `cross-site`, `same-origin`, `same-site`, or `none`. (W3C / Fetch)
- [message_sec_fetch_dest_value_valid](rules/message_sec_fetch_dest_value_valid.md) - `Sec-Fetch-Dest` must be a destination token such as `image`, `document`, `script`, `worker`, `empty`, etc. (W3C / Fetch)
- [message_sec_fetch_mode_value_valid](rules/message_sec_fetch_mode_value_valid.md) - `Sec-Fetch-Mode` must be one of `cors`, `no-cors`, `same-origin`, `navigate`, or `websocket`. (W3C / Fetch)
- [message_sec_fetch_user_value_valid](rules/message_sec_fetch_user_value_valid.md) - `Sec-Fetch-User` must be `?1` when present (navigation requests only). (W3C / Fetch)
- [message_referer_uri_valid](rules/message_referer_uri_valid.md) - `Referer` header value should be a valid URI-reference. (RFC 9110 §7.5.3)
- [message_content_location_and_uri_consistency](rules/message_content_location_and_uri_consistency.md) - `Content-Location` header must be a valid absolute or partial URI and, for successful responses, should identify the representation matching the request target when appropriate. (RFC 9110 §8.7)
- [message_well_known_uri_format](rules/message_well_known_uri_format.md) - Well-known URIs must follow the `/.well-known/` path convention (RFC 8615)
- [message_link_header_validity](rules/message_link_header_validity.md) - Validates `Link` header parameters and semantics (`rel`, `title`, `preload`, `next`); enforces `as` when `rel=preload` and recommends `rel=preload`+`as` for 103 Early Hints.
- [message_from_header_email_syntax](rules/message_from_header_email_syntax.md) - `From` header should be a valid mailbox-list (addr-spec or display-name <addr-spec>). (RFC 9110 §7.1.1, RFC 5322 §3.4)
- [message_max_forwards_numeric](rules/message_max_forwards_numeric.md) - `Max-Forwards` header value must be a non-negative decimal integer (RFC 9110 §7.6.2)
- [message_content_encoding_iana_registered](rules/message_content_encoding_iana_registered.md) - Validates `Content-Encoding` and `Accept-Encoding` tokens are IANA-registered or explicitly allowed; flags invalid tokens. (RFC 9110 §5.3)
- [message_content_encoding_and_type_consistency](rules/message_content_encoding_and_type_consistency.md) - Validates `Content-Encoding` members: token syntax, duplicate codings, and presence on no-body responses. (RFC 9110 §5.3, §6.3)
- [message_compression_and_transfer_encoding_consistency](rules/message_compression_and_transfer_encoding_consistency.md) - Ensures compression codings are not duplicated in `Content-Encoding` and `Transfer-Encoding` (RFC 9110 §5.3)
- [message_early_data_header_safe_method](rules/message_early_data_header_safe_method.md) - `Early-Data: 1` should only appear on safe methods (GET, HEAD, OPTIONS, TRACE). (RFC 8470)
- [message_accept_encoding_parameter_validity](rules/message_accept_encoding_parameter_validity.md) - Validates `Accept-Encoding` header members' parameters (e.g., `q`) must be valid qvalues and parameters must be token or quoted-string. (RFC 9110 §12.5.3, §12.4.2, §5.6.6)
- [message_accept_language_weight_validity](rules/message_accept_language_weight_validity.md) - Validates `Accept-Language` header `q` quality values and parameter forms (0..1, up to three decimals). (RFC 9110 §7.2.5)
- [message_content_transfer_encoding_valid](rules/message_content_transfer_encoding_valid.md) - Validates `Content-Transfer-Encoding` is a single token from the set `7bit|8bit|binary|quoted-printable|base64`. (RFC 2045 §6)
- [message_transfer_coding_iana_registered](rules/message_transfer_coding_iana_registered.md) - Validates `Transfer-Encoding` and `TE` transfer-coding tokens are IANA-registered or explicitly allowed; `TE: trailers` is accepted. (RFC 9112 §6.1, RFC 9110 §10.1.4)
- [message_trailer_headers_valid](rules/message_trailer_headers_valid.md) - Validates `Trailer` header members are valid header field-names and not hop-by-hop headers (e.g., `Connection`, `TE`, `Trailer`, `Transfer-Encoding`). (RFC 7230 §4.1.2, §6.1)
- [message_digest_header_syntax](rules/message_digest_header_syntax.md) - `Content-Digest`/`Repr-Digest`/`Want-*` fields must follow RFC 9530 structured syntax; legacy `Digest`/`Content-MD5` are deprecated. (RFC 9530 §2–§4)
- [message_content_md5_vs_digest_preference](rules/message_content_md5_vs_digest_preference.md) - When both `Content-Digest` and legacy `Content-MD5` are present, prefer validating with `Content-Digest` and avoid `Content-MD5` (RFC 9530).
- [message_warning_header_syntax](rules/message_warning_header_syntax.md) - `Warning` header members must follow the `warn-code warn-agent warn-text [warn-date]` syntax; codes are 3-digit, `warn-text` is a quoted-string, `warn-date` (if present) must be a quoted HTTP-date. (RFC 7234 §5.5)
- [message_www_authenticate_challenge_syntax](rules/message_www_authenticate_challenge_syntax.md) - `WWW-Authenticate` header must contain valid auth-scheme and optional parameters. (RFC 9110 §7.2.1)
- [message_auth_scheme_iana_registered](rules/message_auth_scheme_iana_registered.md) - Authentication schemes used in `WWW-Authenticate`/`Authorization` SHOULD be IANA-registered or match a configured allowlist. (IANA HTTP Auth registry; RFC 9110 §7.2.1)
- [message_authorization_credentials_present](rules/message_authorization_credentials_present.md) - `Authorization` header must include an auth-scheme and non-empty credentials. (RFC 9110 §7.6.2)
- [message_digest_auth_validity](rules/message_digest_auth_validity.md) - `Authorization: Digest` must include required parameters (`username, realm, nonce, uri, response`) and use valid token/quoted-string forms. (RFC 7616 §3.2.2)
- [message_bearer_token_format_validity](rules/message_bearer_token_format_validity.md) - `Authorization: Bearer` tokens MUST not contain whitespace and MUST follow token68-like character constraints. (RFC 6750, RFC 7235 §2.1)
- [message_basic_auth_base64_validity](rules/message_basic_auth_base64_validity.md) - `Authorization: Basic` credentials MUST be valid base64-encoded `user-id:password` octet sequences and must not contain control characters. (RFC 7617 §2)
- [message_cookie_attribute_consistency](rules/message_cookie_attribute_consistency.md) - `Set-Cookie` attributes should be syntactically valid and follow security consistency rules (SameSite/Secure, Max-Age numeric, Expires date). (RFC 6265 §5.2.2)
- [message_cookie_path_validity](rules/message_cookie_path_validity.md) - `Set-Cookie` `Path` attribute should be a valid path-value starting with `/` and not contain control or unencoded whitespace (RFC 6265 §5.2.4).
- [message_cookie_domain_validity](rules/message_cookie_domain_validity.md) - `Set-Cookie` `Domain` attributes should be valid domain names and must not be IP literals or contain invalid characters. (RFC 6265 §5.2.3)
- [message_if_none_match_etag_syntax](rules/message_if_none_match_etag_syntax.md) - `If-None-Match` header must be `*` or a comma-separated list of valid entity-tags (ETags). (RFC 9110 §7.6, §7.8.4)
- [message_if_match_etag_syntax](rules/message_if_match_etag_syntax.md) - `If-Match` header must be `*` or a comma-separated list of valid entity-tags (ETags). (RFC 9110 §7.6, §7.8.3)
- [message_if_modified_since_date_format](rules/message_if_modified_since_date_format.md) - `If-Modified-Since` header must be a valid HTTP-date (IMF-fixdate). (RFC 9110 §7.8.1)
- [message_if_unmodified_since_date_format](rules/message_if_unmodified_since_date_format.md) - `If-Unmodified-Since` header must be a valid HTTP-date (IMF-fixdate). (RFC 9110 §7.8.2)
- [message_conditional_headers_consistency](rules/message_conditional_headers_consistency.md) - Conditional headers MUST respect evaluation precedence (e.g., `If-Modified-Since` is ignored when `If-None-Match` is present); `If-Range` must be used only with `Range` and not contain weak ETags. (RFC 9110 §13.1, §13.2, §14.2)
- [message_date_and_time_headers_consistency](rules/message_date_and_time_headers_consistency.md) - Validate `Date`, `Last-Modified`, `If-Modified-Since`, and `Sunset` formats and simple cross-header consistency (IMF-fixdate; no future Last-Modified; Sunset should be in the future).
- [message_sunset_and_deprecation_consistency](rules/message_sunset_and_deprecation_consistency.md) - When both `Sunset` and `Deprecation` are present, ensure `Deprecation` (structured `@<seconds>`) is not later than `Sunset` (RFC 8594, RFC 9745).
- [message_http_version_syntax_valid](rules/message_http_version_syntax_valid.md) - Start-line `HTTP-version` must match `HTTP/DIGIT.DIGIT` (RFC 9112 §2.3).
- [message_http2_pseudo_headers_validity](rules/message_http2_pseudo_headers_validity.md) - HTTP/2 pseudo-headers (`:method`, `:scheme`, `:authority`, `:path`, `:status`) must be present and valid (RFC 9113 §8.1.2).
- [message_content_length_vs_transfer_encoding](rules/message_content_length_vs_transfer_encoding.md) - Flags messages that include both `Content-Length` and `Transfer-Encoding`.
- [message_content_length](rules/message_content_length.md) - Validates Content-Length values and multiple Content-Length header consistency.
- [message_response_body_length_accuracy](rules/message_response_body_length_accuracy.md) - Ensures `Content-Length` matches the captured body length when available; flags mismatches and invalid values. (RFC 9110 §8.6, RFC 9112 §6.3)
- [message_request_body_length_accuracy](rules/message_request_body_length_accuracy.md) - Ensures `Content-Length` in requests matches the captured request body length when available; flags mismatches and invalid values. (RFC 9112 §6.2, RFC 9112 §6.3)
- [message_range_and_content_range_consistency](rules/message_range_and_content_range_consistency.md) - Validate Range/Content-Range semantics for 206/416 and Content-Length consistency.
- [message_header_field_names_token](rules/message_header_field_names_token.md) - Validates header field-names conform to the `token` grammar.
- [message_extension_headers_registered](rules/message_extension_headers_registered.md) - Non-standard header field-names SHOULD be explicitly allowed via configuration to avoid accidental custom headers and typos. (IANA HTTP Field Name registry; RFC 9110 §5.1)
- [message_transfer_encoding_chunked_final](rules/message_transfer_encoding_chunked_final.md) - Ensures `chunked` (when used) is the final transfer-coding in `Transfer-Encoding` headers.
- [message_te_header_constraints](rules/message_te_header_constraints.md) - `TE` header must use only valid members (transfer-coding or `trailers`), valid parameters (e.g., `q` with up to three decimals), and requests with `TE` must include `Connection: TE`.
- [message_via_header_syntax_valid](rules/message_via_header_syntax_valid.md) - `Via` header values must follow the field-value syntax.
- [message_forwarded_header_validity](rules/message_forwarded_header_validity.md) - `Forwarded` header must follow correct syntax with valid IP addresses and parameters. (RFC 7239)
- [message_x_forwarded_consistency](rules/message_x_forwarded_consistency.md) - `X-Forwarded-*` headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`) should be syntactically valid and use expected values (IPs for `X-Forwarded-For`, `http`/`https` for `X-Forwarded-Proto`, valid host for `X-Forwarded-Host`).
- [message_connection_header_tokens_valid](rules/message_connection_header_tokens_valid.md) - `Connection` header tokens must be valid header field-names (token grammar).
- [message_retry_after_date_or_delay](rules/message_retry_after_date_or_delay.md) - `Retry-After` must be either an HTTP-date or a non-negative delay-seconds.
- [message_refresh_header_syntax_valid](rules/message_refresh_header_syntax_valid.md) - `Refresh` header (non-standard) must be `delta-seconds` or `delta-seconds; url=<URI>` and follow URI syntax for `url` parameter. (MDN)
- [message_prefer_header_valid](rules/message_prefer_header_valid.md) - `Prefer` header directives and parameters must be syntactically valid. (RFC 7240 §2)
- [message_preference_applied_header_valid](rules/message_preference_applied_header_valid.md) - `Preference-Applied` header must list preferences that were present in the request's `Prefer` header; parameters are not allowed. (RFC 7240 §3)
- [client_prefer_header_and_preference_applied](rules/client_prefer_header_and_preference_applied.md) - When a request includes `Prefer`, responses should include `Preference-Applied` to indicate which preferences were applied (RFC 7240 §3). (Best-practice)
- [message_allow_header_method_tokens](rules/message_allow_header_method_tokens.md) - `Allow` header must contain valid HTTP method tokens. (RFC 9110 §7.1.1)
- [message_age_header_numeric](rules/message_age_header_numeric.md) - `Age` header value must be a non-negative integer (delta-seconds).
