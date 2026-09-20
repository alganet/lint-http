<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# p3p_obsolete

A response advertises a privacy policy in a field whose specification is obsolete

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [P3P](https://www.w3.org/TR/P3P/): The Platform for Privacy Preferences 1.0 — a W3C Recommendation of April 2002, obsoleted 30 August 2018. Its Status section states that the specification is obsolete and should no longer be used as a basis for implementation, that P3P never saw sufficient ecosystem uptake, and that what deployments actually sent were general policies copied rather than encoded — which is why this catalogue reads the field's presence and not its value
- [P3P §2.2.2](https://www.w3.org/TR/P3P/#syntax_ext): The P3P response header: the `policyref` pointing at a policy reference file and the `compact-policy-field` carrying a compact policy, which is the half a user agent was expected to act on without a second request

## Configuration

```toml
[violations.p3p_obsolete]
# A response advertises a privacy policy in a field whose specification is obsolete
severity = "info"
```

## Reported By

- [p3p_field_obsolete](../rules/p3p_field_obsolete.md)
