<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Lint Rules

`lint-http` includes several built-in rules to check for HTTP best practices.

## Connection Rules

- [connection_efficiency](rules/connection_efficiency.md) - Tracks requests per connection and warns about inefficient connection reuse.
- [message_connection_upgrade](rules/message_connection_upgrade.md) - If `Connection` includes `upgrade`, `Upgrade` header MUST be present.

## Client Rules

- [client_accept_encoding_present](rules/client_accept_encoding_present.md) - Checks if `Accept-Encoding` header is present.
- [client_user_agent_present](rules/client_user_agent_present.md) - Checks if `User-Agent` header is present.
- [client_cache_respect](rules/client_cache_respect.md) - Verifies clients send conditional headers when re-requesting cached resources.
- [client_host_header_present](rules/client_host_header_present.md) - Checks that requests include the mandatory `Host` header.
- [client_host_header_syntax](rules/client_host_header_syntax.md) - Validates `Host` header syntax: numeric port (1–65535), IPv6 literals must be bracketed when a port is present, and userinfo is not permitted.
- [client_request_method_token_uppercase](rules/client_request_method_token_uppercase.md) - Method token should be uppercase and composed of valid token characters.

## Server Rules

- [server_cache_control_present](rules/server_cache_control_present.md) - Checks for `Cache-Control` header on cacheable responses.
- [server_etag_or_last_modified](rules/server_etag_or_last_modified.md) - Checks for `ETag` or `Last-Modified` headers.
- [server_x_content_type_options](rules/server_x_content_type_options.md) - Checks for `X-Content-Type-Options: nosniff`.
- [server_response_405_allow](rules/server_response_405_allow.md) - Checks `Allow` header is present on `405` responses.
- [server_charset_specification](rules/server_charset_specification.md) - Checks text-based `Content-Type` headers include charset parameter.
- [server_clear_site_data](rules/server_clear_site_data.md) - Checks logout endpoints include `Clear-Site-Data` header (configurable paths).
- [server_no_body_for_1xx_204_304](rules/server_no_body_for_1xx_204_304.md) - Flags responses with status 1xx, 204, or 304 that appear to include a message body.
- [server_content_type_present](rules/server_content_type_present.md) - Ensure responses that likely contain a body include `Content-Type`.

## Message Rules

- [message_content_length_vs_transfer_encoding](rules/message_content_length_vs_transfer_encoding.md) - Flags messages that include both `Content-Length` and `Transfer-Encoding`.
- [message_content_length](rules/message_content_length.md) - Validates Content-Length values and multiple Content-Length header consistency.
- [message_transfer_encoding_chunked_final](rules/message_transfer_encoding_chunked_final.md) - Ensures `chunked` (when used) is the final transfer-coding in `Transfer-Encoding` headers.
- [message_connection_header_tokens_valid](rules/message_connection_header_tokens_valid.md) - `Connection` header tokens must be valid header field-names (token grammar).
