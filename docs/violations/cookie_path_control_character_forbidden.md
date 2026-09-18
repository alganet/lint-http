<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_path_control_character_forbidden

Set-Cookie Path attribute holds a control character

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

**It departs from that level.** RFC 6265 states its own grammar as a SHOULD NOT for historical reasons, and says in the same section that it is stricter than what a user agent will accept. A control octet in a `Path` is a hazard whatever the keyword: it is what smuggles a header boundary past a parser that splits on one, and no deployment wants it at `warn`.

## Specifications

- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`

## Configuration

```toml
[violations.cookie_path_control_character_forbidden]
# Set-Cookie Path attribute holds a control character
# SHOULD obliges the sender, so this defaults to warn.
# Departs from that: RFC 6265 states its own grammar as a SHOULD NOT for historical reasons, and says in the same section that it is stricter than what a user agent will accept. A control octet in a `Path` is a hazard whatever the keyword: it is what smuggles a header boundary past a parser that splits on one, and no deployment wants it at `warn`.
# No input this tool accepts reaches this defect: the octet this names is a control octet, and no route carries one to the rules: on the wire the parser refuses the message before there is a transaction, and from a capture file `HeaderValue` refuses the record -- 0x7f with the rest of the class
severity = "error"
```

## Reported By

- [cookie_path_valid](../rules/cookie_path_valid.md)
