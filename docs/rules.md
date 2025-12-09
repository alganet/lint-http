<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Lint Rules

`lint-http` includes several built-in rules to check for HTTP best practices.

## Client Rules

- [client_accept_encoding_present](rules/client_accept_encoding_present.md) - Checks if `Accept-Encoding` header is present.
- [client_user_agent_present](rules/client_user_agent_present.md) - Checks if `User-Agent` header is present.
- [client_cache_respect](rules/client_cache_respect.md) - Verifies clients send conditional headers when re-requesting cached resources.
- [connection_efficiency](rules/connection_efficiency.md) - Tracks requests per connection and warns about inefficient connection reuse.

## Server Rules

- [server_cache_control_present](rules/server_cache_control_present.md) - Checks for `Cache-Control` header on cacheable responses.
- [server_etag_or_last_modified](rules/server_etag_or_last_modified.md) - Checks for `ETag` or `Last-Modified` headers.
- [server_x_content_type_options](rules/server_x_content_type_options.md) - Checks for `X-Content-Type-Options: nosniff`.
- [server_response_405_allow](rules/server_response_405_allow.md) - Checks `Allow` header is present on `405` responses.
- [server_charset_specification](rules/server_charset_specification.md) - Checks text-based `Content-Type` headers include charset parameter.
- [server_clear_site_data](rules/server_clear_site_data.md) - Checks logout endpoints include `Clear-Site-Data` header (configurable paths).
