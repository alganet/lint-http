<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# boundary_length_invalid

Boundary is empty or longer than seventy characters

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 2046 §5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1): Multipart common syntax: the required `boundary` parameter, the `boundary`/`bchars`/`bcharsnospace` grammar, the 1-to-70-character limit and the ban on a trailing space, and the warning that a boundary often has to be quoted

## Configuration

```toml
[violations.boundary_length_invalid]
# Boundary is empty or longer than seventy characters
severity = "warn"
```

## Reported By

- [multipart_boundary_syntax](../rules/multipart_boundary_syntax.md)
