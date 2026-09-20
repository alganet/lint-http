<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# NEL Policy Value

## Description

This rule reads the `NEL` response header — the network error logging policy an origin registers for itself — and reports the ways Network Error Logging §4.2 throws the whole policy away.

**Every finding here costs the entire policy.** §4.2 is a sequence of *abort these steps*: one member of the wrong type and the user agent registers nothing, so the origin's error reporting is silently off and no report ever says so. That is the same harm `structured_field_malformed` states for a Structured Field a parse refuses, and the commonest real defect is the same one — JSON writes a string with DQUOTE, so a policy written `{'report_to':'default'}` is refused entire.

**The syntax is not NEL's own.** §4.2 hands parsing to Section 4 of HTTP-JFV, which combines the field lines, wraps them in `[` and `]` and runs a JSON parser: the value is a *list* of objects, and a bare object — which is what every origin sends — is that list with one element.

**Which element the user agent reads is a question the document answers twice**, and a finding here has to be true under both. §4.2's fourth step is "let item be the first element of list"; §4.1 says the user agent "MUST process the first *valid* policy in the array and ignore any additional policies". They disagree exactly where an early element is defective and a later one is not — §4.2 aborts, §4.1 registers the good one. So this rule is silent the moment any element reads clean, and reports the first element's defects otherwise. With the single element every real value carries, the two readings are the same reading.

**`max_age: 0` is a withdrawal, not a defective policy.** §4.2 removes any cached policy for the origin at that point and skips every remaining step, so `report_to` — REQUIRED to register — is expressly optional beside it, as §4.1.1 says in its own words. A rule asking for it unconditionally would report the documented way to withdraw a policy.

**`max_age` is read more strictly than a recipient reads it, on purpose.** §4.2 aborts only where the value "is not a number", which `1.5` is; §4.1.2 binds the *sender* to a non-negative integer, and the sender is who this catalogue reports.

**Not reported:** `include_subdomains` with a value that is not a boolean. §4.1.3 says such a value simply does not enable the policy for subdomains — no step aborts and nothing is discarded, so it is not a finding however wrong it looks beside the others. Nor is a well-formed list of two policy objects, for the reason above.

## Violations

- [nel_malformed](../violations/nel_malformed.md) — NEL does not parse, so the origin registers no policy
- [nel_max_age_missing](../violations/nel_max_age_missing.md) — NEL states no max_age, and the policy is discarded
- [nel_member_invalid](../violations/nel_member_invalid.md) — A NEL member carries a value its definition refuses
- [nel_report_to_missing](../violations/nel_report_to_missing.md) — NEL registers a policy and names no endpoint group

## Specifications

- [Network Error Logging §4.1](https://www.w3.org/TR/network-error-logging/#nel-response-header): NEL response header — `NEL = json-field-value`, the array of JSON objects it is interpreted as, and the MUST that a valid field carries one object with every REQUIRED member
- [Network Error Logging §4.2](https://www.w3.org/TR/network-error-logging/#process-policy-headers): Process policy headers — the sequence of *abort these steps* that makes any one of these defects cost the whole policy, and the `max_age` of 0 that removes it and skips the rest
- [draft-reschke-http-jfv-07 §4](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-4): Recipient Requirements — combine the field lines, add a leading "[" and a trailing "]", run a JSON parser; pinned to -07 because the unversioned draft is now a stub with no § 4 in it
- [Network Error Logging §4.1.1](https://www.w3.org/TR/network-error-logging/#the-report_to-member): The report_to member — REQUIRED to register a NEL policy, OPTIONAL to remove one, and a MUST that its value is a string
- [Network Error Logging §4.1.2](https://www.w3.org/TR/network-error-logging/#the-max_age-member): The max_age member — REQUIRED, a MUST that its value is a non-negative integer, and the 0 that removes the policy
- [Network Error Logging §4.1.3](https://www.w3.org/TR/network-error-logging/#the-include_subdomains-member): The include_subdomains member — the one member with no parse error attached, which is why a non-boolean there is not a finding
- [Network Error Logging §4.1.4](https://www.w3.org/TR/network-error-logging/#the-success_fraction-member): The success_fraction member — a MUST that its value is a number between 0.0 and 1.0 inclusive, "any other value will result in a parse error"
- [Network Error Logging §4.1.5](https://www.w3.org/TR/network-error-logging/#the-failure_fraction-member): The failure_fraction member — the same MUST as success_fraction, for the other direction
- [Network Error Logging §4.1.6](https://www.w3.org/TR/network-error-logging/#the-request_headers-member): The request_headers member — a MUST that its value is a list of strings; `response_headers` in § 4.1.7 is the same sentence
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Why several field lines are one value here: HTTP-JFV § 4 combines them before parsing, which is this section's list rule

## Configuration

```toml
[rules.nel_policy_valid]
enabled = true
```

## Examples

### ✅ Good (a policy that registers)

```http
HTTP/1.1 200 OK
NEL: {"report_to":"default","max_age":2592000,"include_subdomains":true}
```

### ✅ Good (max_age 0 withdraws the policy, and needs no report_to)

```http
HTTP/1.1 200 OK
NEL: {"max_age":0}
```

### ✅ Good (the sampling rates at both ends of their inclusive range)

```http
HTTP/1.1 200 OK
NEL: {"report_to":"g","max_age":604800,"success_fraction":0.0,"failure_fraction":1.0}
```

### ❌ Bad (JSON writes a string with DQUOTE, so this policy is discarded whole)

```http
HTTP/1.1 200 OK
NEL: {'report_to':'default','max_age':604800}
```

### ❌ Bad (no max_age, which §4.1.2 makes REQUIRED)

```http
HTTP/1.1 200 OK
NEL: {"report_to":"default"}
```

### ❌ Bad (a lifetime that registers a policy, and no endpoint group to report to)

```http
HTTP/1.1 200 OK
NEL: {"max_age":3600}
```

### ❌ Bad (a sampling rate outside 0.0 to 1.0)

```http
HTTP/1.1 200 OK
NEL: {"report_to":"g","max_age":3600,"success_fraction":1.5}
```
