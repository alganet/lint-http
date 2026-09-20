<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_connect_framing_forbidden

A successful response to CONNECT frames a body the tunnel leaves no room for

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the request message does not have content, and the interpretation of anything after its header section is specific to the version of HTTP in use

## Configuration

```toml
[violations.method_connect_framing_forbidden]
# A successful response to CONNECT frames a body the tunnel leaves no room for
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [connect_response_framing_valid](../rules/connect_response_framing_valid.md)
