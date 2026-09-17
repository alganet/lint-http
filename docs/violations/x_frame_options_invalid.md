<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_frame_options_invalid

X-Frame-Options carries neither DENY nor SAMEORIGIN

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [HTML Speculative Loading §7.7](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header): Governing definition: conformance ABNF `"DENY" / "SAMEORIGIN"`, case-insensitive processing, `ALLOW-FROM` not to be implemented

## Configuration

```toml
[violations.x_frame_options_invalid]
# X-Frame-Options carries neither DENY nor SAMEORIGIN
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [x_frame_options_value_valid](../rules/x_frame_options_value_valid.md)
