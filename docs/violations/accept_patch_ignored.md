<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# accept_patch_ignored

A PATCH sends a format the resource never advertised

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): `Accept-Patch`: `1#media-type`, defined as a response header, and the SHOULD that asks for it in the OPTIONS response of any resource supporting PATCH

## Configuration

```toml
[violations.accept_patch_ignored]
# A PATCH sends a format the resource never advertised
severity = "warn"
```

## Reported By

- [patch_method_content_type_match](../rules/patch_method_content_type_match.md)
