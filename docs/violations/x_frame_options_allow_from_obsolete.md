<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_frame_options_allow_from_obsolete

X-Frame-Options carries the retired ALLOW-FROM variant

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [HTML Speculative Loading §7.7](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header): Governing definition: conformance ABNF `"DENY" / "SAMEORIGIN"`, case-insensitive processing, `ALLOW-FROM` not to be implemented

## Configuration

```toml
[violations.x_frame_options_allow_from_obsolete]
# X-Frame-Options carries the retired ALLOW-FROM variant
severity = "warn"
```

## Reported By

- [x_frame_options_value_valid](../rules/x_frame_options_value_valid.md)
