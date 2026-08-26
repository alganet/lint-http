<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Allow Header Method Tokens

## Description

Validates the `Allow` header field's own value — the set of methods a resource advertises as supported.

The field is `Allow = [ method *( OWS "," OWS method ) ]` (RFC 9110 §A), and a `method` is a `token` (§9.1). So every member must be `1*tchar`: `Allow: GET POST` names one member and no method, because SP is not a `tchar`, and `Allow: PO@T` fails on a delimiter (§5.6.2). No member may be empty — `Allow: GET,,POST` and `Allow: GET,` are lists a sender MUST NOT generate (§5.6.1.1).

**An empty value is not an empty member, and this rule used to report it.** The production's outer brackets make a list of no methods a list, and §10.2.1 goes further than tolerating it: "An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration." So `Allow:` is a resource saying something, in the response the section names — and a rule reporting it contradicted the sentence it was written from. `Allow:   ` is the same value: §5.5 excludes whitespace around a field value before it is evaluated.

Where the field appears on several lines in one section, the lines are one value (§5.2) — so `Allow: GET` followed by `Allow:` is a list whose second member is empty, which *is* reported, while a lone `Allow:` is not. A value carrying an octet outside US-ASCII is measured rather than skipped: `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a token, which is what is wrong with it. The finding names that octet — `0xC9`, not the code point some encoding would read it as — while the member beside it is shown escaped for legibility, so the two halves of the message are read differently on purpose.

**Not reported: a method name written in an unexpected case.** `Allow: get, POST` advertises a method whose name is `get`, and the method token is case-sensitive (§9.1) — but nothing in §10.2.1 restricts which names a resource may advertise, and separating a mis-cased standard name from a deployment's own lowercase extension needs the registry. `request_method_token_valid` is the rule that asks that question, of a request's method, and it carries the required `registered_methods` array the question needs; making that array required here would silence this grammar check on every deployment that has not written one.

**Not reported: whether the advertised methods are the right ones.** §10.2.1 says "The actual set of allowed methods is defined by the origin server at the time of each request", so no capture disagrees with an `Allow` list by holding a different one. A duplicated member is not reported either — the section calls the value a set in prose, and the production repeats `method` without restriction.

**Not checked at all: "A proxy MUST NOT modify the Allow header field" (§10.2.1).** A capture records one message as this proxy saw it, not the same message before and after a hop, so the two values that requirement compares are never both present. It is left here as a decline rather than as an unremarked gap.

Scope: this rule reads header sections — a request's and a response's — and measures the value whatever protocol version carried it, because the production is written in the version-independent document. §10.2 places the field among response context fields; an `Allow` in a request is unusual rather than forbidden, so it is measured and not reported for being there. **A trailer section is not read.** Whether a field name may arrive as a trailer at all is §6.5.1's question, and it is asked of every name at once by `message_trailer_fields_validity` rather than field by field here — so an `Allow` in a trailer draws whatever that rule says about it and nothing from this one. Whether a 405 response carries the field at all is §15.5.6's question and `status_405_allow_valid`'s; whether an OPTIONS response carries it is `options_method_capabilities`'s.

## Specifications

- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): The field itself: its grammar, what the set of methods means, and the sentence that gives an empty field value a meaning rather than making it a defect
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not, and where `method = token` is quotable
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The sender's half of the list construct — the empty-member finding. The recipient's half (§5.6.1.2, parse and ignore them) is a different party's requirement, which is why the lenient list reader is not used here
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token = 1*tchar`, transcribed once in `helpers::token::is_tchar`, and the delimiter set that makes splitting this field on every comma exact
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): A field value excludes the whitespace around it, so a value that is only whitespace is the empty value — and `obs-text` is an octet field content admits, which is why the value is read as octets rather than through a UTF-8 decode
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sentence that makes a value outside its own grammar a violation, and the reason both halves of the exchange are measured: it addresses whoever generated the element

## Configuration

```toml
[rules.allow_header_method_tokens_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good The section's own example of use

```http
HTTP/1.1 200 OK
Allow: GET, HEAD, PUT
```

### ✅ Good A list of no methods is a list — the resource allows none, which §10.2.1 puts in exactly this response

```http
HTTP/1.1 405 Method Not Allowed
Allow:
```

### ✅ Good An extension method is a token like any other

```http
HTTP/1.1 200 OK
Allow: GET, X-CUSTOM-METHOD
```

### ✅ Good Two field lines in one section are one list

```http
HTTP/1.1 200 OK
Allow: GET
Allow: POST
```

### ❌ Bad An empty member — the list construct's sender requirement

```http
HTTP/1.1 200 OK
Allow: GET, , POST
```

### ❌ Bad A trailing comma is an empty member too

```http
HTTP/1.1 405 Method Not Allowed
Allow: GET,
```

### ❌ Bad An empty line beside a non-empty one is an empty member of the joined list

```http
HTTP/1.1 200 OK
Allow: GET
Allow:
```

### ❌ Bad SP is not a `tchar`, so this is one member and no method

```http
HTTP/1.1 200 OK
Allow: GET POST
```

### ❌ Bad A delimiter inside a member

```http
HTTP/1.1 200 OK
Allow: GET, PO@T
```
