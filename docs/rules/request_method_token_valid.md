<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Request Method Token Valid

## Description

Reports a request whose method token does not derive from `method = token` (RFC 9110 §9.1), and a request whose method is a standardized method's name written in a different case.

**Two findings of different strengths.** A method token that is empty or carries a character outside `tchar` matches no production, and RFC 9110 §2.2 is what makes that a violation: "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules." The case finding rests on no requirement at all — §9.1 says only "By convention, standardized methods are defined in all-uppercase US-ASCII letters", which is a statement about how standards write their definitions, not one addressed to a sender.

**What makes the case finding worth reporting is the sentence next to the convention.** §9.1: "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names." So `get` is not a badly typed `GET`; it is a method nothing defines, and §9.1 has an origin server answer an unrecognized method with `501 (Not Implemented)`. The finding is that a request asking for a standardized method will not get one.

**Not reported: a lowercase method that is nobody's standardized method.** A deployment's private `x-purge` is a well-formed `token`, and the convention §9.1 states is about standardized methods — so there is no sentence under a report of it, and this rule used to make one anyway. `registered_methods` is what separates the two cases.

**`registered_methods` is required, and the reason is that the names live in a registry.** RFC 9110 §16.1.1 registers method names at IANA and admits new ones by IETF Review; §9.1 says every method specified outside RFC 9110 "ought to be registered" there. The eight methods RFC 9110 defines are only the ones that document defines, so a list compiled into this rule would be a snapshot of an open registry presented as though it were the grammar. The array is also where a deployment records its own uppercase-by-convention names: add `PURGE` to it and `purge` is reported; leave it out and it is not.

**A missing or empty array stops the whole rule, not only the case finding.** The two grammar questions never read these names, so silencing just the third would leave a configuration mistake looking like a clean run. A deployment that wants the grammar half and not the case advice disables the rule rather than emptying the array.

**An incomplete array costs coverage and never a false report.** A name missing from it means one spelling goes unremarked — unlike the same shape in `early_data_header_safe_method`, where an absent name *is* the finding, because RFC 8470 §4 names "methods whose safety is not known" alongside the unsafe ones.

**Every HTTP version is read, and there is no version gate.** `method = token` is written in the version-independent document; RFC 9112 §3.1 is where an HTTP/1.1 message carries the result, and RFC 9113 §8.3.1 and RFC 9114 §4.3.1 put the same value in a `:method` pseudo-header. `http2_pseudo_headers_valid` used to report the `tchar` half a second time, on every version; it now stops on a method that derives from no `token` and leaves the finding here, because a value naming no method names nothing for its own branches to turn on.

**The two grammar findings do not arise in traffic this proxy captured.** A capture's method comes from `hyper::Method`, whose accepted character table is `tchar` exactly and which refuses a zero-length method, so a request that reaches the wire through this proxy cannot carry either defect. They are reachable in a capture written elsewhere and deserialized into the transaction model, which is the only reason the checks are here.

## Specifications

- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): `method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sentence that makes a value outside its ABNF a violation rather than an observation
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token = 1*tchar`. The character set is transcribed once, in `helpers::token::is_tchar`; the `1*` floor is what the empty-method branch here reads
- [RFC 9110 §16.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.1.1): The IANA method registry, which holds the names `registered_methods` is a deployment's copy of, and grows by IETF Review
- [RFC 9112 §3.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.1): Where an HTTP/1.1 message carries the method. This reference said §5.1, which is Field Line Parsing
- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): The `:method` pseudo-header field, which is where an HTTP/2 request carries the same value
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): The `:method` pseudo-header field over HTTP/3

## Configuration

```toml
[rules.request_method_token_valid]
enabled = true
severity = "warn"
# The standardized method names this deployment expects to see spelled the way their
# definitions spell them. RFC 9110 §9.1 states the convention this rule reports against
# — "standardized methods are defined in all-uppercase US-ASCII letters" — and says
# every method specified outside that document "ought to be registered" in the IANA
# "Hypertext Transfer Protocol (HTTP) Method Registry" (§16.1.1), which grows by IETF
# Review. So the set below is that registry's Method Name column and not a grammar: the
# `token` production admits every lowercase spelling this rule reports.
# A name missing here costs one unremarked spelling and never a false report. Add a
# private method — `PURGE`, `BAN` — to have its own case convention checked too.
# The array is required, and an absent or empty one stops the rule outright rather than
# only its case check: the grammar questions do not read these names, so silencing just
# that branch would leave a configuration mistake looking like a clean run.
registered_methods = [
  "ACL",
  "BASELINE-CONTROL",
  "BIND",
  "CHECKIN",
  "CHECKOUT",
  "CONNECT",
  "COPY",
  "DELETE",
  "GET",
  "HEAD",
  "LABEL",
  "LINK",
  "LOCK",
  "MERGE",
  "MKACTIVITY",
  "MKCALENDAR",
  "MKCOL",
  "MKREDIRECTREF",
  "MKWORKSPACE",
  "MOVE",
  "OPTIONS",
  "ORDERPATCH",
  "PATCH",
  "POST",
  "PRI",
  "PROPFIND",
  "PROPPATCH",
  "PUT",
  "QUERY",
  "REBIND",
  "REPORT",
  "SEARCH",
  "TRACE",
  "UNBIND",
  "UNCHECKOUT",
  "UNLINK",
  "UNLOCK",
  "UPDATE",
  "UPDATEREDIRECTREF",
  "VERSION-CONTROL",
]
```

## Examples

### ✅ Good a standardized method, spelled as its definition spells it

```http
GET /index.html HTTP/1.1
```

### ✅ Good a private method no registry knows: a well-formed token, and the convention §9.1 states is about standardized methods

```http
x-purge /cache/entry HTTP/1.1
```

### ❌ Bad a standardized method's name in another case — the token is case-sensitive, so this asks for a method nobody defined

```http
get /index.html HTTP/1.1
```

### ❌ Bad `@` is not a `tchar`, so this method derives from no production

```http
G@T /index.html HTTP/1.1
```
