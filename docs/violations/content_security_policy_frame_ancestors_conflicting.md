<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_frame_ancestors_conflicting

frame-ancestors and X-Frame-Options state different framing policies

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [CSP3 §6.4.2](https://www.w3.org/TR/CSP3/#directive-frame-ancestors): `frame-ancestors` — which URLs may embed the resource, the rough equivalences between its source expressions and `X-Frame-Options`' values, and § 6.4.2.2's statement that an enforced `frame-ancestors` overrides that header outright

## Configuration

```toml
[violations.content_security_policy_frame_ancestors_conflicting]
# frame-ancestors and X-Frame-Options state different framing policies
severity = "warn"
```

## Reported By

- [content_security_policy_and_frame_options_consistent](../rules/content_security_policy_and_frame_options_consistent.md)
