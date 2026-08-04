<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Transfer Coding Iana Registered

## Description

Validate `Transfer-Encoding` and `TE` header values: transfer-coding names must be syntactically valid `token`s and must appear in the configured `allowed` list. The `TE` header's `trailers` member is not a coding name and is skipped.

**The rule is named after a registry it does not read.** Nothing here fetches IANA's HTTP Transfer Coding registry; names are compared against the configured `allowed` list, whose shipped default is `chunked`, `compress`, `gzip`, `deflate`. The registry also holds `x-compress` and `x-gzip` (both Deprecated) and `identity` (withdrawn), which the default omits on purpose — reporting them is the useful answer. `trailers` is registered as reserved and never reaches the comparison. Widen or narrow the list to suit; an unregistered name is a configuration question, because RFC 9112 §7.3 puts registration behind IETF Review and no linter can stand in for that.

**The strongest thing RFC 9112 §7 says about registration is "ought to"** — not MUST, not SHOULD. An unrecognised coding is therefore reported for its consequence rather than for disobedience: §6.1, "A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented)."

**Every field line of both fields is read**, since each is a list whose members may be spread across lines — and for `Transfer-Encoding` a second field line is the shape request smuggling arrives in, so reading only the first is the one omission this rule cannot afford. Values are decoded from the raw octets: an octet outside visible US-ASCII is not a `tchar`, so where a coding name belongs it is reported rather than used as a reason to skip the line.

**Members are split on commas that are not inside a quoted-string.** `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`, so `chunked;ext="a,b"` is one coding carrying one parameter, not two members. Quoting that never closes leaves the members undelimitable and is reported here rather than passed over, because no other rule reports a malformed `Transfer-Encoding`.

**`chunked` is reported in `TE` and only there.** RFC 9112 §7.4: "A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients." It is a registered coding, so the registry check waves it through; this is the one place where a recognised name is still the wrong name. In `Transfer-Encoding` it is the ordinary case.

**A parameter on a compression coding is reported.** RFC 9112 §7.2 defines `compress`, `x-compress`, `deflate`, `gzip` and `x-gzip`, states that they "do not define any parameters", and says their presence "SHOULD be treated as an error". The `q` in `TE: deflate;q=0.5` is exempt — the grammar puts the `weight` outside `transfer-coding` and §7.3 calls it a pseudo-parameter — but `Transfer-Encoding` has no weight in its grammar, so a `q` there is an ordinary parameter. This reaches no other coding: `chunked;ext=1` is unreported because §7.2's sentence is about the compression codings and no sentence makes a parameter on `chunked` an error, and a coding you add to `allowed` answers to its own registration.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding = #transfer-coding, and the 501 a recipient owes a coding it does not understand
- [RFC 9112 §7](https://www.rfc-editor.org/rfc/rfc9112.html#section-7): Transfer codings: the names are case-insensitive and 'ought to be' registered — the whole of this rule's strength
- [RFC 9112 §7.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2): The five compression codings, which define no parameters
- [RFC 9112 §7.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.4): Negotiating transfer codings: chunked is forbidden in TE, an empty TE is conforming, and the q is a rank
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE, and the grammar both fields share — including the quoted-string a transfer-parameter may carry
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#transfer-coding): The registry this rule is named after and does not read: names are checked against the configured 'allowed' list instead

## Configuration

```toml
[rules.message_transfer_coding_iana_registered]
enabled = true
severity = "warn"
# The registry also holds x-compress and x-gzip (both Deprecated) and identity
# (withdrawn in an erratum to RFC 2616); they are left out so that using them is
# reported. "trailers" is registered as reserved and is not a coding name.
allowed = ["chunked", "compress", "gzip", "deflate"]
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

0
```

### ✅ Good (TE request)

```http
GET / HTTP/1.1
Host: example.com
TE: trailers
```

### ✅ Good (TE ranks a coding; the q is a weight, not a parameter)

```http
GET / HTTP/1.1
Host: example.com
TE: trailers, deflate;q=0.5
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Transfer-Encoding: x-custom
```

### ❌ Bad (chunked is always acceptable, so TE cannot name it)

```http
GET / HTTP/1.1
Host: example.com
TE: chunked;q=0.8
```

### ❌ Bad (the compression codings define no parameters)

```http
HTTP/1.1 200 OK
Transfer-Encoding: gzip;level=9, chunked
```
