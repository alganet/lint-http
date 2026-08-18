<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Context Fields Direction

## Description

Reports a message context field arriving in the direction it is not defined for: one of RFC 9110 §10.1's five request context fields (`Expect`, `From`, `Referer`, `TE`, `User-Agent`) in a response, or one of §10.2's four response context fields (`Allow`, `Location`, `Retry-After`, `Server`) in a request.

**The finding is advice, and its message says so.** §10 attaches no BCP 14 keyword to the arrival — the split into *Request Context Fields* and *Response Context Fields* is how the document says what each field is about, not a stated prohibition — so the report is that the field states nothing where it was sent: each section's subject is a fact about the other direction (`Server` is *"information about the software used by the origin server to handle the request"*; `From` is the human controlling *"the requesting user agent"*), and no definition gives the field a meaning elsewhere. The finding names the field's own subject rather than inventing a modal, and the shipped severity is `info`.

**This is the placement question, not the value question.** Each of the nine fields has a rule reading its value in the direction it is defined for, and each of those rules correctly declines the other direction — there is no sentence to measure the value against there. That decline is what left the arrival itself unreported: a `Server` field in a request was walked past by every rule in the catalogue.

**`TE` is also a connection-specific field**, so over HTTP/2 and HTTP/3 `message_no_connection_specific_fields` reports its presence in either direction under a different and stronger sentence (RFC 9113 §8.2.2). The two findings answer different questions — that one is about hop-by-hop fields surviving into a multiplexed protocol, this one is about a field defined for the other direction — and only this one exists over HTTP/1.1.

**Only header sections are read.** A context field in a *trailer* section is a different fault with its own sentences, and `message_trailer_fields_validity` owns them.

**Fields defined for both directions are not here.** `Content-Location` is defined in both (§8.7 gives the request side its own meaning), and the general representation fields travel with content in either direction, so nothing about them is a placement fault.

## Specifications

- [RFC 9110 §10.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1): Request Context Fields — the five fields whose subjects are the user, user agent and resource behind a request; the section split this rule reads the direction from
- [RFC 9110 §10.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2): Response Context Fields — the four whose subjects are the server, the target resource and related resources. No sentence in either section forbids the misdirection, which is why the finding is advice

## Configuration

```toml
[rules.message_context_fields_direction]
# RFC 9110 §10 attaches no BCP 14 keyword to a context field arriving in the
# direction it is not defined for; the finding is that the field states
# nothing where it was sent, so it ships as advice.
enabled = true
severity = "info"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.0

HTTP/1.1 200 OK
Server: httpd/2.4
Allow: GET, HEAD
```

### ❌ Bad (Server is response context — it says nothing in a request)

```http
GET / HTTP/1.1
Host: example.com
Server: httpd/2.4
```

### ❌ Bad (User-Agent is request context — it says nothing in a response)

```http
HTTP/1.1 200 OK
User-Agent: curl/8.0
```
