<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# weight_missing

Member writes the weight's ';' and no weight after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values — `weight = OWS ";" OWS "q=" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means

## Configuration

```toml
[violations.weight_missing]
# Member writes the weight's ';' and no weight after it
severity = "warn"
```

## Reported By

- [accept_encoding_parameter_valid](../rules/accept_encoding_parameter_valid.md)
- [accept_language_weight_valid](../rules/accept_language_weight_valid.md)
