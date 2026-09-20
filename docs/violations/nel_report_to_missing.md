<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# nel_report_to_missing

NEL registers a policy and names no endpoint group

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [Network Error Logging §4.1.1](https://www.w3.org/TR/network-error-logging/#the-report_to-member): The report_to member — REQUIRED to register a NEL policy, OPTIONAL to remove one, and a MUST that its value is a string
- [Network Error Logging §4.2](https://www.w3.org/TR/network-error-logging/#process-policy-headers): Process policy headers — the sequence of *abort these steps* that makes any one of these defects cost the whole policy, and the `max_age` of 0 that removes it and skips the rest

## Configuration

```toml
[violations.nel_report_to_missing]
# NEL registers a policy and names no endpoint group
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [nel_policy_valid](../rules/nel_policy_valid.md)
