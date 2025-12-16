<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_obs_fold_disallowed

**Goal:** Detect and flag obsolete header line folding (obs-fold) in header field values.

## Why

RFC 7230 (and newer RFC 9110) disallow line folding (obs-fold) in header field values because it makes parsing ambiguous and invites injection or header-splitting attacks. Obs-fold is defined as a carriage return (CR) followed by line feed (LF) followed by a space or horizontal tab (CRLF SP / CRLF HTAB).

## What this rule checks

- For each header field value (requests and responses), if the header value contains the byte sequence `"\r\n `" (CRLF followed by space) or `"\r\n\t"` (CRLF followed by horizontal tab), the rule flags a violation.

## Examples

- Violation: a header value containing `"foo\r\n bar"` or `"v1\r\n\tv2"`
- OK: normal header values without embedded CRLFs

## Configuration

This rule has no configuration; enable it by adding the following to your configuration:

```toml
[rules.message_obs_fold_disallowed]
enabled = true
severity = "warn"
```
