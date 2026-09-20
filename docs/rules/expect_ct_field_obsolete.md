<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Expect-CT Field Obsolete

## Description

Reports a response carrying an `Expect-CT` header field.

**A live specification and a dead field, which is a third footing and not either of the two this catalogue already had.** RFC 9163 defines `Expect-CT` and nothing has superseded it, so unlike `Report-To` there is a current document to read the field against; and unlike `X-XSS-Protection` a standards body did write it down. What withdrew the field was its only implementation. Chromium — the sole engine that ever implemented `Expect-CT` — removed the header in version 107 "because Chromium now enforces CT by default", so the opt-in the field expresses is both unread and redundant. That is a fact about deployment, which an RFC does not revise itself to record, so the sentence cited for it is MDN's. IANA's HTTP Field Name Registry agrees, and lists the name `deprecated`.

**Why the field is pointless and not merely quiet.** It asked a browser to check that certificates for the site appear in public Certificate Transparency logs. Since May 2018 every new publicly-trusted certificate is expected to carry signed certificate timestamps, and the last certificates issued before that — which were allowed 39-month lifetimes — expired in June 2021. So there is no certificate left for the check to fail on, and a browser that did read the field would find nothing the platform had not already enforced.

**The value is deliberately not graded.** RFC 9163 §2.1 gives the field a grammar and the `max-age`, `report-uri` and `enforce` directives it takes, so a malformed `max-age` or a `report-uri` that is no URI is a defect that could be reported. It is not, because it is a claim about how a dead field is spelled: no recipient reads the value, so whether it parses changes nothing for anyone. What an operator can act on is that the line does nothing at all, and that is one finding. The value is printed rather than parsed, because a `report-uri` in it names a collector the deployment probably still believes is receiving reports.

**The repair is a deletion.** No other field in a message names an `Expect-CT` policy, so unlike `Report-To` — whose group names a `Content-Security-Policy` directive and a `NEL` policy point at — there is nothing to move first. An operator wanting the guarantee the field was for already has it: the platform enforces CT for every certificate.

**Advice, not a violation.** Nothing prohibits sending the field, no recipient behaves differently, and the message is well-formed. What the finding tells an operator is that a security control they believe they have configured is not in effect anywhere.

Scope: this rule reads a response's header section. Several field lines are read as one value (RFC 9110 §5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a response that has none.

## Violations

- [expect_ct_obsolete](../violations/expect_ct_obsolete.md) — A response asks for Certificate Transparency in a field no browser reads

## Specifications

- [MDN Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT): Expect-CT — marked Deprecated, and the page that says why: Chromium was the only engine that implemented the header and removed it in version 107 because it now enforces Certificate Transparency by default, while the certificates that predated universal SCT support expired in June 2021, leaving nothing for the check to catch
- [RFC 9163 §1](https://www.rfc-editor.org/rfc/rfc9163.html#section-1): Expect-CT: the response header by which a host declares that it expects Signed Certificate Timestamps in subsequent TLS connections — the definition this catalogue reads the field's presence against, and the reason a finding names a live document rather than only a third party's account of it

## Configuration

```toml
[rules.expect_ct_field_obsolete]
enabled = true
# The evidence is what implementations did rather than a keyword addressed to a
# sender, so the finding is advice and the severity says so. The comment sits
# *below* the line it explains: the generated file runs these sections
# together, and a comment above a key reads as introducing everything under it.
```

## Examples

### ✅ Good (the transport guarantee, which the platform now enforces itself)

```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=63072000
```

### ❌ Bad (enforcement asked of a browser that removed the field)

```http
HTTP/1.1 200 OK
Expect-CT: max-age=86400, enforce
```

### ❌ Bad (a collector nothing will report to)

```http
HTTP/1.1 200 OK
Expect-CT: max-age=3600, report-uri="https://example.com/ct-report"
```
