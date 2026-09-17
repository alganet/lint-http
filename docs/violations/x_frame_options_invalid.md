<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# x_frame_options_invalid

X-Frame-Options carries neither DENY nor SAMEORIGIN

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML Speculative Loading §7.7](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header): Governing definition: conformance ABNF `"DENY" / "SAMEORIGIN"`, case-insensitive processing, `ALLOW-FROM` not to be implemented

## Configuration

```toml
[violations.x_frame_options_invalid]
# X-Frame-Options carries neither DENY nor SAMEORIGIN
severity = "warn"
```

## Reported By

- [x_frame_options_value_valid](../rules/x_frame_options_value_valid.md)
