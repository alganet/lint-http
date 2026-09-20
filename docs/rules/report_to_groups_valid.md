<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Report-To Endpoint Groups

## Description

This rule reads the `Report-To` response header — the named endpoint groups an origin declares as the destination for its CSP violation reports, network errors and deprecation reports — and reports two things about it.

**No specification defines the field any more.** The W3C Reporting API once did; the document at that URL now defines `Reporting-Endpoints` and no longer contains the string `Report-To` at all. So there is no current specification to read the field against and no superseded one that says what replaced it, and MDN's page — which marks the field Deprecated and Non-standard and says in as many words that `Reporting-Endpoints` replaced it — is the document this rule cites. That is the footing `x_xss_protection_value_valid` already stands on: a field deployments send in quantity and no standards document defines.

**The finding is a move, not a deletion.** The group names declared here are exactly the names a `Content-Security-Policy` `report-to` directive and a `NEL` policy's `report_to` member point at, so an origin that simply drops the field loses the reporting it still has. The message names `Reporting-Endpoints` for that reason.

**The syntax is `NEL`'s syntax.** MDN writes the value as one or more endpoint-group definitions "defined as a JSON array that omits the surrounding `[` and `]` markers", which is HTTP-JFV §4: combine the field lines, add the brackets back, run a JSON parser. A value that does not survive that is `report_to_malformed`, and it costs the origin every group in the field rather than the malformed one — the array is one JSON document, so a parser that refuses it declares nothing.

**Joining the lines is not a nicety.** A response declaring two groups commonly writes them on two field lines — major CDNs do — and a rule reading only the first line would report half a well-formed array as a broken one. The lines are joined before anything parses them, as HTTP-JFV §4's own first step requires and RFC 9110 §5.3 licenses.

**The delimiter is what real origins get wrong, and they get it wrong twice.** JSON writes a string with DQUOTE, so `{'group':'default','max_age':3600}` is refused entire — and an origin whose templating wrote `Report-To` with apostrophes wrote its `NEL` the same way. `nel_malformed` reports that one. Both findings are needed for either to be actionable: repairing the policy alone leaves it naming a group that a still-unparseable `Report-To` never declared.

**Members are not read.** MDN names `group`, `max_age` and `endpoints` and marks none of them required, and the draft that did state requirements is a snapshot the W3C has replaced. An entry claiming a member is REQUIRED would rest on no document in force, so the reading stops at the parse.

## Violations

- [report_to_malformed](../violations/report_to_malformed.md) — Report-To does not parse, so none of the endpoint groups it declares exist
- [report_to_obsolete](../violations/report_to_obsolete.md) — A response declares its endpoint groups in a field that has been replaced

## Specifications

- [MDN Report-To](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Report-To): Report-To — a response header marked Deprecated and Non-standard, replaced by `Reporting-Endpoints`, whose value is one or more endpoint-group definitions written as a JSON array with the surrounding brackets omitted
- [draft-reschke-http-jfv-07 §2](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-2): Syntax — `json-field-value = #json-field-item`, the comma-separated list of JSON texts that a field deferring to this draft carries
- [draft-reschke-http-jfv-07 §4](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-4): Recipient Requirements — combine the field lines, add a leading "[" and a trailing "]", run a JSON parser; pinned to -07 because the unversioned draft is now a stub with no § 4 in it
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Why several field lines are one value here: HTTP-JFV § 4 combines them before parsing, which is this section's list rule

## Configuration

```toml
[rules.report_to_groups_valid]
enabled = true
```

## Examples

### ✅ Good (the field the groups move to)

```http
HTTP/1.1 200 OK
Reporting-Endpoints: csp-endpoint="https://example.com/csp-reports"
```

### ❌ Bad (a well-formed value, in a field that has been replaced)

```http
HTTP/1.1 200 OK
Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://example.com/csp-reports"}]}
```

### ❌ Bad (JSON writes a string with DQUOTE, so no group is declared at all)

```http
HTTP/1.1 200 OK
Report-To: {'group':'default','max_age':3600,'endpoints':[{'url':'https://example.com/reports'}]}
```

### ❌ Bad (two groups on two field lines are one array, and it parses)

```http
HTTP/1.1 200 OK
Report-To: {"group":"a","max_age":3600,"endpoints":[{"url":"https://example.com/a"}]}
Report-To: {"group":"b","max_age":3600,"endpoints":[{"url":"https://example.com/b"}]}
```
