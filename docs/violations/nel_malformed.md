<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# nel_malformed

NEL does not parse, so the origin registers no policy

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [Network Error Logging §4.1](https://www.w3.org/TR/network-error-logging/#nel-response-header): NEL response header — `NEL = json-field-value`, the array of JSON objects it is interpreted as, and the MUST that a valid field carries one object with every REQUIRED member
- [Network Error Logging §4.2](https://www.w3.org/TR/network-error-logging/#process-policy-headers): Process policy headers — the sequence of *abort these steps* that makes any one of these defects cost the whole policy, and the `max_age` of 0 that removes it and skips the rest
- [draft-reschke-http-jfv-07 §4](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-4): Recipient Requirements — combine the field lines, add a leading "[" and a trailing "]", run a JSON parser; pinned to -07 because the unversioned draft is now a stub with no § 4 in it

## Configuration

```toml
[violations.nel_malformed]
# NEL does not parse, so the origin registers no policy
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [nel_policy_valid](../rules/nel_policy_valid.md)
