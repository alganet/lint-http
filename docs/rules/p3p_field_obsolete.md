<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# P3P Field Obsolete

## Description

Reports a response carrying a `P3P` header field.

**The field's own specification is the evidence, which is unusual for an `_obsolete` finding.** The Platform for Privacy Preferences 1.0 became a W3C Recommendation in April 2002 and was obsoleted on 30 August 2018; the document at that URL is the obsoletion notice, and its Status section says the specification "is obsolete and should no longer be used as a basis for implementation". Compare `report_to_groups_valid`, where the W3C removed the field from the Reporting API and left no sentence behind, so the fact had to be cited to MDN; and `x_xss_protection_value_valid`, where no standards body ever defined the field at all. Here the document being cited is the one that defined the header.

**What the field bought, and why nothing reads it now.** §2.2.2 defines the header as where a site points at its policy reference file and, through the `compact-policy-field`, states a performance-optimised summary of its privacy practices so a user agent need not fetch the full policy. Exactly one user agent ever acted on it: Internet Explorer used the presence of a compact policy as a broad gate on whether to accept third-party cookies. That is why the field was deployed at the scale it was, and it is why nothing reads it today.

**The value is deliberately not graded, and W3C's own account of the failure is the reason.** The Status section explains that when Internet Explorer made a compact policy the gate, "web site administrators chose to copy general policies rather than encode specific policies that reflected their sites' own privacy practices", and that no enforcement followed where a policy misdescribed a site. So a compact policy on the wire is evidence about a template somebody copied rather than about the site sending it, and measuring one against §4's compact vocabulary would report the template's author. The value is printed in the finding rather than parsed.

**The repair is a deletion, and that is not true of every retired field.** `Report-To`'s group names are pointed at by a `Content-Security-Policy` `report-to` directive and by a `NEL` policy, so dropping it breaks reporting that still works; a compact policy is named by nothing else in the message, so there is nothing to move first.

**Advice, not a violation.** Nothing prohibits sending the field, no recipient behaves differently, and the message is well-formed. What the finding tells an operator is that a header on every response is buying the cookie acceptance it was configured for from a browser that no longer exists.

Scope: this rule reads a response's header section. Several field lines are read as one value (RFC 9110 §5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a response that has none.

## Violations

- [p3p_obsolete](../violations/p3p_obsolete.md) — A response advertises a privacy policy in a field whose specification is obsolete

## Specifications

- [P3P](https://www.w3.org/TR/P3P/): The Platform for Privacy Preferences 1.0 — a W3C Recommendation of April 2002, obsoleted 30 August 2018. Its Status section states that the specification is obsolete and should no longer be used as a basis for implementation, that P3P never saw sufficient ecosystem uptake, and that what deployments actually sent were general policies copied rather than encoded — which is why this catalogue reads the field's presence and not its value
- [P3P §2.2.2](https://www.w3.org/TR/P3P/#syntax_ext): The P3P response header: the `policyref` pointing at a policy reference file and the `compact-policy-field` carrying a compact policy, which is the half a user agent was expected to act on without a second request

## Configuration

```toml
[rules.p3p_field_obsolete]
enabled = true
# The evidence is a document status rather than a keyword addressed to a
# sender, so the finding is advice and the severity says so. The comment sits
# *below* the line it explains: the generated file runs these sections
# together, and a comment above a key reads as introducing everything under it.
```

## Examples

### ✅ Good (no compact policy, and nothing asks for one)

```http
HTTP/1.1 200 OK
Content-Type: text/html
```

### ❌ Bad (a compact policy, in a specification obsoleted in 2018)

```http
HTTP/1.1 200 OK
P3P: CP="NOI DSP COR ADMa DEVa OUR IND"
```

### ❌ Bad (the policy reference half is as unread as the compact one)

```http
HTTP/1.1 200 OK
P3P: policyref="/w3c/p3p.xml", CP="NOI DSP ADM DEV"
```
