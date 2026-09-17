<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# authority_tunnel_missing

A CONNECT names no host and port to open a tunnel to

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5): The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them
- [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4): The CONNECT Method — the MUST that a CONNECT request be constructed with `:scheme` and `:path` omitted and `:authority` carrying the host and port to connect to, and the sentence making a request that does not malformed

## Configuration

```toml
[violations.authority_tunnel_missing]
# A CONNECT names no host and port to open a tunnel to
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [http2_pseudo_headers_valid](../rules/http2_pseudo_headers_valid.md)
- [http3_pseudo_headers_valid](../rules/http3_pseudo_headers_valid.md)
