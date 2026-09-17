<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# quic_idle_timeout_invalid

QUIC idle timeout reclaims nothing

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Configuration

```toml
[violations.quic_idle_timeout_invalid]
# QUIC idle timeout reclaims nothing
severity = "info"
```

## Reported By

- [quic_transport_parameters_valid](../rules/quic_transport_parameters_valid.md)
