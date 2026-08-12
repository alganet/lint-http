<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request URI Percent Encoding Valid

## Description

Reads the characters of the request target and asks whether it is properly percent-encoded — percent-encoding being the one mechanism a URI has for carrying an octet whose character is outside the set a URI may be written with (RFC 3986 §2.1).

**Every `%` opens a triplet.** `pct-encoded = "%" HEXDIG HEXDIG`, and the percent character has no second role: it is *"the indicator for percent-encoded octets"*, so one meant as data is written `%25` (RFC 3986 §2.4). A `%` at the end of the value, or one followed by anything that is not two hexadecimal digits, therefore derives from no production. The two are reported as themselves — a run that stops short and a run with a non-hex character are different mistakes — and both matter to the recipient rather than only to the sender: *"Once produced, a URI is always in its percent-encoded form"*, so what follows a `%` is read as an encoding whatever was meant by it, and §2.4 warns that octets decoded before their components are separated can be taken for delimiters.

**Every other character has to be one a URI is composed from.** A URI is written with *"digits, letters, and a few graphic symbols"* (RFC 3986 §2), and the notation's terminals are US-ASCII codepoints — so `{`, `}`, `|`, `\`, `^`, `` ` ``, `<`, `>`, `"`, a space and every non-ASCII character are outside the alphabet, whatever component they sit in. Each is an octet §2.1 asks to be percent-encoded, and writing it raw is the same defect as a malformed triplet seen from the other side: `/café/` is reported and `/caf%C3%A9/` is not. Both branches rest on RFC 9110 §2.2's *"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules"*, which reaches a URI production because §4.1 adopts the generic syntax's rules by name for the HTTP elements that carry one.

**The rule is not version-gated.** An HTTP/1.x capture records the request-target from the request-line; HTTP/2 and HTTP/3 send no request-line, and what is recorded is the target URI their transport reassembled from pseudo-header fields, whose `:path` is the path and query parts of that same target URI (RFC 9113 §8.3.1, RFC 9114 §4.3.1). The characters are the same productions' characters either way, and RFC 9110 §7.1's *"request target"* is the name that covers all three.

**Hexadecimal case is not part of the check, and that is a decision.** RFC 3986 §2.1 recommends uppercase — *"For consistency, URI producers and normalizers should use uppercase hexadecimal digits for all percent-encodings"* — and the sentence immediately before it is why the recommendation is not a finding: the digits are *"equivalent"*, and two URIs differing only in that case are the same URI. The notation says it from the other direction, a quoted string in an ABNF rule being case-insensitive (RFC 5234 §2.3), so `%2f` derives from `HEXDIG` exactly as `%2F` does. RFC 3986 states no BCP 14 requirement anywhere in the document; reporting a lowercase digit would be enforcing a preference as a rule.

**What this rule can and cannot see.** A malformed triplet survives the proxy's own capture path intact — the URI parser it builds `tx.request.uri` with accepts `%`, `%2`, `%2G` and `%zz` without complaint — so these findings are reachable on live traffic, unlike a fragment, which that same parser removes before a transaction exists. The character half is reachable in part: `{`, `}`, `|`, `\`, `^`, `"` and non-ASCII characters all reach a capture, while `<`, `>`, `` ` `` and a space are refused before one is written and arrive only in a capture recorded elsewhere and read back through the `lint` subcommand. A test pins that boundary.

**What this rule does not decide.** Which of the four forms an HTTP/1.x request-target derives from, and whether the method may use that form, is `client_request_target_form_checks` — which also reports whitespace in a request-line's target on a sentence of its own (RFC 9112 §3.2 excludes whitespace from the request-target by name and asks a recipient not to autocorrect it), so a space in an HTTP/1.x target draws two findings saying two different things about it. Whether the target carries a fragment is `client_request_target_no_fragment`. Whether an encoded octet *should* have been left decoded — RFC 3986 §6.2.2.2's normalization of a percent-encoded unreserved character — is nobody's finding: the two spellings identify the same resource.

## Specifications

- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding: the triplet production, and percent-encoding as the mechanism for an octet whose character is outside the allowed set
- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters: the limited set a URI is composed from, whose terminals the notation maps back through US-ASCII
- [RFC 3986 §2.4](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.4): When to Encode or Decode: a URI on the wire is already in its percent-encoded form, a '%' meant as data is written %25, and octets decoded before their components are separated can be taken for delimiters
- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References: the generic syntax's productions are adopted by name for the HTTP elements that carry a URI
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT that a value matching no production breaks
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource: the components sent are collectively the request target on every major protocol version
- [RFC 5234 §2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3): ABNF strings are case insensitive, which is why a lowercase hexadecimal digit derives from HEXDIG

## Configuration

```toml
[rules.client_request_uri_percent_encoding_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Request

```http
GET /path%20with%20spaces HTTP/1.1
Host: example.com
```

### ✅ Good (characters outside the URI alphabet, encoded)

```http
GET /caf%C3%A9/menu?q=100%25 HTTP/1.1
Host: example.com
```

### ❌ Bad (a triplet that stops short, or is not two hex digits)

```http
GET /path%2 HTTP/1.1
GET /path%GG HTTP/1.1
GET /100% HTTP/1.1
```

### ❌ Bad (characters no URI is composed from, written raw)

```http
GET /café/menu HTTP/1.1
GET /path/{id} HTTP/1.1
GET /a|b HTTP/1.1
```
