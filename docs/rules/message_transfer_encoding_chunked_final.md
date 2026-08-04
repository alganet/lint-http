<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Transfer-Encoding Chunked Final

## Description

Enforces RFC 9112 §6.1's requirements on the sequence of transfer codings: `chunked` may be applied at most once, and when any other coding is applied `chunked` must come last. Codings are read in wire order across every `Transfer-Encoding` field line.

**Three findings, three sentences.**

- *"A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed)."* — `chunked, chunked` is reported as duplication, not as a position problem.
- *"If any transfer coding other than chunked is applied to a request's content, the sender MUST apply chunked as the final transfer coding to ensure that the message is properly framed."* — this is unconditional, so a request reading `Transfer-Encoding: gzip` is reported: it applies a coding and never frames the result.
- *"If any transfer coding other than chunked is applied to a response's content, the sender MUST either apply chunked as the final transfer coding or terminate the message by closing the connection."* — a **response** therefore has a second way to comply.

**The response exemption, and what it rests on.** A transaction records no connection teardown, so the second alternative is read from `Connection: close`. RFC 9112 §9.6 makes announcing a close a **SHOULD**, not a MUST — so a response that closes silently is still reported here, and that is a known false positive rather than an oversight. It is also, in that state, disregarding §9.6. Narrowing further would mean giving up the response side entirely.

**A response with no body is not judged.** §6.1 permits `Transfer-Encoding` on a response to `HEAD` and on a `304 (Not Modified)`, "neither of which includes a message body", where it indicates what the origin *would have* applied to an unconditional `GET`. All three requirements above speak of a coding applied to content, so none of them engage. The *request's* own field is judged as usual, whatever its method.

**§7.1 does not say `chunked` must be last.** It defines the chunked coding — its grammar, its role in framing, and (at the end) that it takes no parameters. This rule's specifications used to cite §7.1 for the ordering requirement, which lives in §6.1.

**Parsing.** Members are split on commas outside quoted-strings, the coding *name* is taken from in front of any parameters (so `chunked;ext=1` is still `chunked`), names are folded case-insensitively per §7, and values are decoded from raw octets — dropping a field line here would not merely lose a finding, it would silently reorder the sequence being judged. A value whose quoting never closes is declined, because its members cannot be delimited; `message_transfer_coding_iana_registered` is the rule that reports it.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — every requirement this rule enforces is here: chunked at most once, and chunked last (unconditionally for requests, or the connection closes for responses)
- [RFC 9112 §9.6](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.6): The 'close' connection option — how a response announces the alternative §6.1 gives it. §9.6 makes announcing a SHOULD, which bounds what this rule can conclude
- [RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1): Chunked Transfer Coding — what chunked is, and why nothing may follow it. It does NOT contain the ordering requirement this rule's SpecRef used to attribute to it
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): The transfer-coding grammar the members are parsed with, including the quoted-string a parameter may carry

## Configuration

```toml
[rules.message_transfer_encoding_chunked_final]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /upload HTTP/1.1
Host: example.com
Transfer-Encoding: gzip, chunked
```

### ✅ Good (response closes the connection instead of chunking)

```http
HTTP/1.1 200 OK
Transfer-Encoding: gzip
Connection: close
```

### ❌ Bad (request applies gzip and never frames the result)

```http
POST /upload HTTP/1.1
Host: example.com
Transfer-Encoding: gzip
```

### ❌ Bad (nothing may follow chunked)

```http
POST /upload HTTP/1.1
Host: example.com
Transfer-Encoding: chunked, gzip
```

### ❌ Bad (chunking an already chunked message)

```http
POST /upload HTTP/1.1
Host: example.com
Transfer-Encoding: chunked, chunked
```
