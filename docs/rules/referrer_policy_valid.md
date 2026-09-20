<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Referrer-Policy Value

## Description

This rule reads the `Referrer-Policy` response header as the `1#policy-token` list Referrer Policy §4.1 defines it to be, and reports a field that names **no** referrer policy at all.

**The finding is about the field, never about a member, and the specification is what decides that.** §8.1 walks the tokens, sets the policy to the last one it recognises and ignores every other, and §11.1 makes that the documented way to deploy a new policy value with a fallback for older user agents: `Referrer-Policy: origin, unsafe-url` is a pattern the document tells authors to write. So a token outside the eight is reported only when *every* token is, which is the one case where the grammar and the algorithm agree — the field derives from no `1#policy-token`, §8.1 returns the empty string, and §8.2 leaves the request's referrer policy exactly where the header had never been sent.

**What that costs is the whole header.** A site that meant `no-referrer` and wrote `no-referer` still serves a well-formed field, and still leaks the full URL of every page to every cross-origin destination it links to. Nothing on the wire distinguishes it from a site that set no policy on purpose.

**Case is not a defect.** §4.1 writes `policy-token` as bare ABNF string literals, and RFC 5234 §2.3 makes those case-insensitive, so `NO-REFERRER` derives from the production. This is the difference from the `Sec-Fetch-*` family, whose values are RFC 9651 structured-field tokens and fold no case.

**Several field lines are one list**, as RFC 9110 §5.3's exception for comma-separated fields provides, so a response writing the field twice is not reported for repeating it — the lines are joined in order and read as the single list a recipient acts on. The header section only: §8.1 parses `Referrer-Policy` in the response's *header list*, and a trailer arrives after a user agent has already determined the policy for the requests this one governs.

**The list construct's own two defects are reported under the ids every list-valued field uses**: a stray comma is `list_member_empty` and a field with no member at all is `list_member_missing`, the `1#` floor.

## Violations

- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [list_member_missing](../violations/list_member_missing.md) — List with a one-element floor holds no element
- [referrer_policy_invalid](../violations/referrer_policy_invalid.md) — Referrer-Policy names no referrer policy

## Specifications

- [Referrer Policy §4.1](https://www.w3.org/TR/referrer-policy/#referrer-policy-header): Delivery via Referrer-Policy header — `"Referrer-Policy:" 1#policy-token`, and the eight literals `policy-token` is one of
- [Referrer Policy §8.1](https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header): Parse a referrer policy from a Referrer-Policy header — unknown tokens are ignored, the last recognised one wins, and a field with none of them yields the empty string
- [Referrer Policy §11.1](https://www.w3.org/TR/referrer-policy/#unknown-policy-values): Unknown Policy Values — the fallback idiom the § 8.1 walk exists to allow, and the reason this catalogue judges the field rather than its members
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Why several field lines are one list here rather than a duplication: the exception turns on the field being a comma-separated list, and `1#policy-token` is one
- [RFC 5234 §2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3): ABNF string literals are case-insensitive, which is why `NO-REFERRER` derives from `policy-token` where a Structured Field token would not

## Configuration

```toml
[rules.referrer_policy_valid]
enabled = true
```

## Examples

### ✅ Good (a policy the eight literals print)

```http
HTTP/1.1 200 OK
Referrer-Policy: strict-origin-when-cross-origin
```

### ✅ Good (§11.1's fallback idiom: an older user agent takes the first)

```http
HTTP/1.1 200 OK
Referrer-Policy: origin, unsafe-url
```

### ✅ Good (an ABNF string literal is case-insensitive)

```http
HTTP/1.1 200 OK
Referrer-Policy: NO-REFERRER
```

### ❌ Bad (one letter short of a policy, and the header does nothing)

```http
HTTP/1.1 200 OK
Referrer-Policy: no-referer
```

### ❌ Bad (a stray comma is an element the sender must not generate)

```http
HTTP/1.1 200 OK
Referrer-Policy: no-referrer,,origin
```

### ❌ Bad (a `1#` list needs at least one non-empty element)

```http
HTTP/1.1 200 OK
Referrer-Policy: 
```
