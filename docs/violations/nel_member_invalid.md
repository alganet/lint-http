<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# nel_member_invalid

A NEL member carries a value its definition refuses

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [Network Error Logging §4.1.1](https://www.w3.org/TR/network-error-logging/#the-report_to-member): The report_to member — REQUIRED to register a NEL policy, OPTIONAL to remove one, and a MUST that its value is a string
- [Network Error Logging §4.1.2](https://www.w3.org/TR/network-error-logging/#the-max_age-member): The max_age member — REQUIRED, a MUST that its value is a non-negative integer, and the 0 that removes the policy
- [Network Error Logging §4.1.4](https://www.w3.org/TR/network-error-logging/#the-success_fraction-member): The success_fraction member — a MUST that its value is a number between 0.0 and 1.0 inclusive, "any other value will result in a parse error"
- [Network Error Logging §4.1.5](https://www.w3.org/TR/network-error-logging/#the-failure_fraction-member): The failure_fraction member — the same MUST as success_fraction, for the other direction
- [Network Error Logging §4.1.6](https://www.w3.org/TR/network-error-logging/#the-request_headers-member): The request_headers member — a MUST that its value is a list of strings; `response_headers` in § 4.1.7 is the same sentence
- [Network Error Logging §4.2](https://www.w3.org/TR/network-error-logging/#process-policy-headers): Process policy headers — the sequence of *abort these steps* that makes any one of these defects cost the whole policy, and the `max_age` of 0 that removes it and skips the rest

## Configuration

```toml
[violations.nel_member_invalid]
# A NEL member carries a value its definition refuses
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [nel_policy_valid](../rules/nel_policy_valid.md)
