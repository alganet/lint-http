<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# keep_alive_connection_option_missing

Keep-Alive is sent with no keep-alive connection-option in Connection

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 2068 §19.7.1.1](https://www.rfc-editor.org/rfc/rfc2068.html#section-19.7.1.1): The `Keep-Alive` grammar, the sentence saying HTTP/1.1 defines no parameters for it, and the field's one requirement on a sender — the matching connection token. Obsoleted, and still the document RFC 9110 §7.6.1 names for this field, so this is where the productions are read from. The reference here used to be RFC 7230 §6.7, which is `Upgrade`

## Configuration

```toml
[violations.keep_alive_connection_option_missing]
# Keep-Alive is sent with no keep-alive connection-option in Connection
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [keep_alive_header_valid](../rules/keep_alive_header_valid.md)
