<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Warning Header Syntax

## Description

Parses the `Warning` field of a request and of a response — every field line of one section joined into the single list they are — against the grammar that defines it: `Warning = 1#warning-value`, where `warning-value = warn-code SP warn-agent SP warn-text [ SP warn-date ]`, `warn-code = 3DIGIT`, `warn-agent = ( uri-host [ ":" port ] ) / pseudonym`, `warn-text = quoted-string` and `warn-date = DQUOTE HTTP-date DQUOTE`. RFC 9110 §2.2 is what makes a value outside that grammar a finding.

**The field is obsolete, and its presence is not reported.** RFC 9111 §5.5 obsoletes `Warning`, and §8.1 registers it with the status `obsoleted` — but §5.5 holds no BCP 14 keyword at all, so nothing there forbids a sender to write the field and nothing here reports one for existing. What §5.5 also does not carry is a grammar: the last document to state one is RFC 7234 §5.5, which RFC 9111 obsoleted, so this rule names both documents rather than pretending the current one still defines a syntax. The leaf productions RFC 7234 imported from RFC 7230 and RFC 7231 are read from RFC 9110 instead, where each of them survived under its own name: `token` and `quoted-string` (§5.6.2, §5.6.4), `OWS` (§5.6.3), `pseudonym` (§7.6.3), `uri-host` and `port` (§4.1, reaching RFC 3986 §3.2.2 and §3.2.3), and `HTTP-date` (§5.6.7).

Four consequences of that grammar are worth stating.

- **The separators are single spaces.** The production writes `SP` between the parts and `OWS` nowhere inside a member, so `214 example.net  "text"` is not two spaces' worth of slack — it is a member whose `warn-agent` is empty and whose `warn-text` begins with a letter. `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a `uri-host` of no characters is one and an empty `warn-agent` between the two spaces is accepted rather than reported.
- **A `warn-agent` is a host and optional port, or a token.** `user@example.com`, `a^b`, `{a}` and `[not-an-address]` derive from neither alternative and are reported; `a|b^c` and `%zz` are `token`s and are not, because the second alternative does not have to agree with the first about what a character means. A bracketed IPv6 literal *is* generated here, unlike in `Via`, whose identical `( uri-host [ ":" port ] ) / pseudonym` RFC 9110 §B.2 narrowed to a bare pseudonym; RFC 7234's copy was never narrowed. A port is `*DIGIT` — no range and no minimum — so `:0`, `:99999` and a colon with no digits after it are all syntax-conforming.
- **A `warn-date` is an `HTTP-date`, and a sender may only write one of its three formats.** RFC 9110 §5.6.7 requires IMF-fixdate, so the two obsolete formats are reported as themselves rather than accepted or called "not a date". The DQUOTEs sit directly against the date, so whitespace inside them is reported too: SP is `qdtext`, which makes `" Wed, 21 Oct 2015 07:28:00 GMT "` a well-formed quoted-string holding something that is not an `HTTP-date`.
- **`1#` has a floor and `#` does not.** A `Warning` field value carrying no member at all — an empty value, or one that is nothing but commas — is reported, because at least one non-empty element is required (RFC 9110 §5.6.1.2 prints `""`, `","` and `",   ,"` as the invalid values of exactly this construct). An empty member *between* two real ones is a separate finding, RFC 9110 §5.6.1.1's sender MUST NOT, and a member written empty at a line boundary is one of those: the lines of one section are one list.

**What this rule does not decide.**

- **Which `warn-code` was used.** `warn-code = 3DIGIT` is the whole of the syntax. The codes are an IANA registry with its own registration procedure, and RFC 7234 §5.5's own list is seven of them, so an unregistered three-digit code is not a syntax finding.
- **Whether a `1xx` code was allowed to be there.** §5.5 lets a cache generate one only when validating a stored response, and requires a cache to delete it after validation — both are statements about what the sender is and what it just did, and no captured message says either.
- **Whether a `1xx` code needed a `warn-date`.** §5.5's MUST applies when the message is going "to a recipient known to implement only HTTP/1.0". A capture records the version each message *arrived under*, which is its sender's conformance (RFC 9110 §2.5) — it never records the recipient's, so the antecedent has no representation here.
- **Whether a `warn-date` agrees with `Date`.** §5.5's requirement there is on a recipient that uses, evaluates or displays the field, and it is to exclude the warning-value; nothing in it makes the disagreement the sender's defect.
- **Repeated codes, and where a field line sits.** §5.5 permits multiple warnings with the same `warn-code` differing only in `warn-text`, so duplicates are not counted; and its MUST to append new field lines after existing ones distinguishes fields this message arrived with from fields its sender added, which a capture does not record.
- **A `warn-agent` holding a comma.** `,` is a `sub-delim` and so a `reg-name` character, and it is also the list's separator: nothing in the field value tells the two apart. The separator wins here, which is what a list parser does, and the halves are then judged as members.

## Specifications

- [RFC 7234 §5.5](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5): The last statement of the `Warning` grammar, and the requirements about warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which removed the field rather than restating it — so this is where the productions are read from, and RFC 9111 §5.5 is where the field's status is read from
- [RFC 9111 §5.5](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.5): Where `Warning` is obsoleted. The section carries no BCP 14 keyword, so it states no requirement on a sender and the field's presence is not reported
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT behind every finding here: a value that derives from none of §5.5's productions is a protocol element matching no ABNF rule
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct's sender requirement — an empty member is the finding, and §5.6.1.2's worked example is what makes an empty *value* one too, because `Warning` is `1#`
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string`, the `qdtext` that admits `obs-text` inside a warn-text, and the recipient's handling of a `quoted-pair` — which is why a warn-date is unescaped before it is read as a date
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): `HTTP-date`, and the MUST that a sender generate it in the IMF-fixdate format — the two obsolete formats parse and are still findings. This reference said §7.1.1.1, which is RFC 7231's number for it and does not exist in RFC 9110
- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): `pseudonym = token`, the second alternative of `warn-agent`. RFC 7234 imported the name from RFC 7230 §5.7.1; this is where it lives now
- [RFC 9110 §B.2](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2): Why `Via` and `Warning` no longer agree: RFC 9110 removed `uri-host` from `received-by`, and RFC 7234's `warn-agent` — the same production — was never touched, so a bracketed IPv6 literal is a finding there and not here
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): `host`, which `warn-agent`'s first alternative reaches through RFC 9110 §4.1 — including the `reg-name` that derives the empty string

## Configuration

```toml
[rules.message_warning_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good §5.5.1's code, with the "-" §5.5 recommends when the agent is unknown

```http
HTTP/1.1 200 OK
Warning: 110 - "Response is stale"
```

### ✅ Good A warn-agent that is a uri-host and a port

```http
HTTP/1.1 200 OK
Warning: 214 example.com:80 "Transformation applied"
```

### ✅ Good The exchange §5.5 itself prints for the 1xx warn-date requirement

```http
HTTP/1.1 200 OK
Date: Sat, 25 Aug 2012 23:34:45 GMT
Warning: 112 - "network down" "Sat, 25 Aug 2012 23:34:45 GMT"
```

### ✅ Good A warn-agent of no characters, which `reg-name = *( ... )` generates

```http
HTTP/1.1 200 OK
Warning: 214  "Transformation applied"
```

### ❌ Bad A 1# list needs one non-empty member, and §5.6.1.2 prints this value as invalid

```http
HTTP/1.1 200 OK
Warning: ,
```

### ❌ Bad A warn-code is three digits

```http
HTTP/1.1 200 OK
Warning: 21a host "text"
```

### ❌ Bad A warn-text is a quoted-string

```http
HTTP/1.1 200 OK
Warning: 214 host text
```

### ❌ Bad "@" is the userinfo delimiter: no uri-host holds one, and it is not a tchar

```http
HTTP/1.1 200 OK
Warning: 214 user@example.com "text"
```

### ❌ Bad A warn-date that is not an HTTP-date at all

```http
HTTP/1.1 200 OK
Warning: 214 host "x" "not-a-date"
```

### ❌ Bad An RFC 850 date parses, and §5.6.7 lets a sender generate only IMF-fixdate

```http
HTTP/1.1 200 OK
Warning: 214 host "x" "Saturday, 25-Aug-12 23:34:45 GMT"
```
