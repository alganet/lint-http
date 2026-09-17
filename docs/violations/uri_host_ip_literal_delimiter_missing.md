<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# uri_host_ip_literal_delimiter_missing

An IPv6 address is written without the brackets that mark it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere

## Configuration

```toml
[violations.uri_host_ip_literal_delimiter_missing]
# An IPv6 address is written without the brackets that mark it
severity = "warn"
```

## Reported By

- [host_header](../rules/host_header.md)
