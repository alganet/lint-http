<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# field_line_duplicated

A field is written on more lines than its definition allows

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[violations.field_line_duplicated]
# A field is written on more lines than its definition allows
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [access_control_allow_origin_valid](../rules/access_control_allow_origin_valid.md)
- [conditional_headers_consistent](../rules/conditional_headers_consistent.md)
- [content_disposition_token_valid](../rules/content_disposition_token_valid.md)
- [content_location_and_uri_consistent](../rules/content_location_and_uri_consistent.md)
- [content_type_valid](../rules/content_type_valid.md)
- [cross_origin_embedder_policy_valid](../rules/cross_origin_embedder_policy_valid.md)
- [cross_origin_opener_policy_valid](../rules/cross_origin_opener_policy_valid.md)
- [cross_origin_resource_policy_valid](../rules/cross_origin_resource_policy_valid.md)
- [deprecation_header_syntax](../rules/deprecation_header_syntax.md)
- [etag_syntax](../rules/etag_syntax.md)
- [from_header_email_syntax](../rules/from_header_email_syntax.md)
- [host_header](../rules/host_header.md)
- [location_header_uri_valid](../rules/location_header_uri_valid.md)
- [max_forwards_numeric](../rules/max_forwards_numeric.md)
- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
- [origin_matching_for_cors](../rules/origin_matching_for_cors.md)
- [referer_uri_valid](../rules/referer_uri_valid.md)
- [refresh_header_syntax](../rules/refresh_header_syntax.md)
- [retry_after_date_or_delay](../rules/retry_after_date_or_delay.md)
- [sec_fetch_dest_value_valid](../rules/sec_fetch_dest_value_valid.md)
- [sec_fetch_mode_value_valid](../rules/sec_fetch_mode_value_valid.md)
- [sec_fetch_site_value_valid](../rules/sec_fetch_site_value_valid.md)
- [sec_fetch_user_value_valid](../rules/sec_fetch_user_value_valid.md)
- [singleton_fields_not_repeated](../rules/singleton_fields_not_repeated.md)
- [strict_transport_security_valid](../rules/strict_transport_security_valid.md)
- [x_frame_options_value_valid](../rules/x_frame_options_value_valid.md)
- [x_xss_protection_value_valid](../rules/x_xss_protection_value_valid.md)
