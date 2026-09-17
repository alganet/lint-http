<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_connect_form_invalid

A CONNECT's request-target is not a host and port

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §3.2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3): authority-form — `authority-form = uri-host ":" port`, the MUST that a CONNECT send only the host and port of the tunnel destination as its request-target, and the form being used for CONNECT requests only

## Configuration

```toml
[violations.request_target_connect_form_invalid]
# A CONNECT's request-target is not a host and port
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
