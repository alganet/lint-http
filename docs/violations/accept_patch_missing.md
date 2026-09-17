<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_patch_missing

A response that should name the patch formats names none

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2): Error handling: a 415 (Unsupported Media Type) answering a PATCH SHOULD carry an Accept-Patch naming the patch document media types the resource supports
- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): `Accept-Patch`: `1#media-type`, defined as a response header, and the SHOULD that asks for it in the OPTIONS response of any resource supporting PATCH

## Configuration

```toml
[violations.accept_patch_missing]
# A response that should name the patch formats names none
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [accept_patch_header_valid](../rules/accept_patch_header_valid.md)
