<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# CSP report-to Names A Group

## Description

Reads the `report-to` directive of every policy a response delivers, in both `Content-Security-Policy` and `Content-Security-Policy-Report-Only`, and reports one thing: that the directive wrote no endpoint group name.

**The value is a name, not a location.** CSP3 §6.5.2 writes `directive-value = token` — one token, which §5.5 looks up as the name of a reporting endpoint group declared elsewhere in the response by `Reporting-Endpoints` (or by the `Report-To` it replaced). A value that is no token names no group, and the violation report has nowhere to go.

**The mistake this catches is a URL**, and it is the neighbouring directive's value. §6.5.1 gives the deprecated `report-uri` a `uri-reference *( required-ascii-whitespace uri-reference )`; §6.5.2 gives `report-to` a bare `token`. One subsection apart, and a deployment that pastes its collector's URL into both has not merely failed to improve on `report-uri` — §5.5 skips `report-uri` outright whenever a `report-to` is present, so writing the broken directive disables the working one.

**A `report-uri` beside a well-formed `report-to` is not reported.** §6.5.1 asks for exactly that pairing to keep older user agents working, and a finding against it would contradict the sentence this rule rests on.

**Nothing here asks whether the group exists.** Reporting configuration is registered per origin and a response need not carry the declaration it names, so a rule reading one message cannot tell a name nothing declares from one an earlier response declared. What is decidable from the message alone is whether a name was written at all, and that is the whole of this reading.

**Scope.** A field line is a comma-delimited series of serialized policies (§2.2) and each is enforced on its own, so the policies are separated before the directives are; within one policy a directive name written twice keeps the first (§2.2.1), which is the occurrence a user agent acts on and therefore the one read here. Directive names are matched case-insensitively, as §2.2.1 requires. The value is split on ASCII whitespace, which is §2.2.1's own step — so `report-to  grp` is one token and `report-to a b` is two.

**Whether the policy is enforced or merely monitored makes no difference to this finding, and the report-only field is where it costs most.** §3.2 delivers a policy so a developer can watch it; a monitored policy whose reports go nowhere is a header that does nothing at all.

## Violations

- [content_security_policy_report_to_malformed](../violations/content_security_policy_report_to_malformed.md) — A report-to directive names no endpoint group, so violation reports go nowhere

## Specifications

- [CSP3 §6.5.2](https://www.w3.org/TR/CSP3/#directive-report-to): `report-to` — `directive-value = token`, one token naming a reporting endpoint group declared elsewhere in the response, where the deprecated `report-uri` takes URI-references instead
- [CSP3 §6.5.1](https://www.w3.org/TR/CSP3/#directive-report-uri): `report-uri` — the deprecated directive whose value really is a URI-reference, which this rule exists to tell apart from its neighbour, and whose presence beside a `report-to` is suggested rather than reported
- [CSP3 §2.2](https://www.w3.org/TR/CSP3/#framework-policy): Policies — a field line is a comma-delimited series of serialized CSPs, each enforced on its own, which is why the directives of one policy are not read against another's
- [CSP3 §2.2.1](https://www.w3.org/TR/CSP3/#parse-serialized-policy): Parse a serialized CSP — a directive value is the token split on ASCII whitespace, directive names are case-insensitive, and a name already in the directive set makes the later occurrence be skipped

## Configuration

```toml
[rules.content_security_policy_report_to_named]
enabled = true
```

## Examples

### ✅ Good (the token names a group the response declares)

```http
HTTP/1.1 200 OK
Reporting-Endpoints: csp-endpoint="https://example.com/csp"
Content-Security-Policy: script-src 'self'; report-to csp-endpoint
```

### ✅ Good (a report-uri beside it is what § 6.5.1 suggests)

```http
HTTP/1.1 200 OK
Content-Security-Policy: script-src 'self'; report-uri https://example.com/csp; report-to csp-endpoint
```

### ❌ Bad (a URL is report-uri's value, and report-to takes a name)

```http
HTTP/1.1 200 OK
Content-Security-Policy: script-src 'self'; report-to https://example.com/csp
```

### ❌ Bad (the directive is named and lists nothing)

```http
HTTP/1.1 200 OK
Content-Security-Policy-Report-Only: script-src 'self'; report-to
```

### ❌ Bad (one reporting endpoint, so two tokens name none)

```http
HTTP/1.1 200 OK
Content-Security-Policy: script-src 'self'; report-to primary backup
```
