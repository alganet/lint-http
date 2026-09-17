<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alpn_protocol_name_unregistered

ALPN protocol name is not one this deployment serves

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7838 §2](https://www.rfc-editor.org/rfc/rfc7838.html#section-2): Alternative Services Concepts: an alternative service is identified by an ALPN protocol name as per RFC 7301, a host and a port; §2.4 requires a client to treat a connection that does not negotiate the expected protocol as failed

## Configuration

```toml
[violations.alpn_protocol_name_unregistered]
# ALPN protocol name is not one this deployment serves
severity = "warn"
```

## Reported By

- [alt_svc_protocol_registered](../rules/alt_svc_protocol_registered.md)
