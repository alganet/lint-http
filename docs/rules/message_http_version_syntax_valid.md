<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Http Version Syntax Valid

## Description

Reads the HTTP version a captured message arrived under and asks whether it is what `HTTP-version = HTTP-name "/" DIGIT "." DIGIT` generates: the four letters of `HTTP` in exactly that case, a `/`, one decimal digit, a `.`, and one decimal digit. RFC 9112 §2.3 states the case-sensitivity twice — once in the notation, where `%s` marks a case-sensitive string, and once in prose beside it — so `http/1.1` is not a spelling of `HTTP/1.1`. The requirement that a mismatch is a violation is RFC 9110 §2.2's, reached from an HTTP/1.1 production through §1.1, which puts this document's conformance criteria in the other one.

The finding names which of the production's three terminals failed, because they are three different mistakes: a name in the wrong case or absent, a version number that is not two digits around a period (`HTTP/1`, `HTTP/1.10`, `HTTP/11.0`), and the right shape holding a character that is not a digit (`HTTP/1.x`). It does **not** name the protocol version the message arrived under: the value that failed is the only thing that would have said, which is why a report of a malformed version can describe the value and nothing around it.

**Only HTTP/1.x messages carry this as a field.** RFC 9112 §2.3 says the version of an HTTP/1.x message is indicated by an `HTTP-version` field in the start-line, and the other two versions say in so many words that they have nowhere to put one: RFC 9113 §8.3.1 and §8.3.2 give every HTTP/2 request and response an implicit protocol version of `2.0`, RFC 9114 §4.3.1 and §4.3.2 give every HTTP/3 request and response `3.0`. Both are written with the minor digit present, which is RFC 9110 §2.5's general rule — when a major version defines no minor versions, `0` is used wherever a minor version identifier is required. So the value is measured on every version: for one it is a transcription of what the message carried, and for the other two it is a number their own specifications state, written the way those specifications write it.

**What this proxy records can never fail this rule.** The capture's version is rendered from an enumerated protocol version, so it is one of six strings — `HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`, and `HTTP/1.1` again for a version the HTTP library does not name — and every one of them derives from the production. A malformed version never reaches a capture either, because a request whose start-line does not parse is refused before there is a transaction to record. Every finding this rule can make is therefore about a capture written by some other tool and read back through `lint`, and that is the traffic it exists for.

Two things it does not check. RFC 9112 §2.3 requires an intermediary that is not a tunnel to send **its own** `HTTP-version` in forwarded messages; a capture records the message as received, not as forwarded, so nothing here can compare the two. And the relation between a request's version and the response's is left alone deliberately: §2.3 says a server **MAY** send an HTTP/1.0 response to an HTTP/1.1 request, and states no requirement for the pair to agree.

## Specifications

- [RFC 9112 §2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3): The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line
- [RFC 9110 §2.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.5): What the two digits mean, and the `0` used for a major version that defines no minor versions
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The MUST NOT that makes a value matching no production a finding; RFC 9112 §1.1 is the bridge to it
- [RFC 9112 §3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3): The request-line, which ends with the protocol version
- [RFC 9112 §4](https://www.rfc-editor.org/rfc/rfc9112.html#section-4): The status-line, which begins with it
- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): HTTP/2 carries no version indicator; its implicit protocol version is `2.0`
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): HTTP/3 has nowhere to carry the identifier the request line holds; its implicit protocol version is `3.0`
- [RFC 5234 §B.1](https://www.rfc-editor.org/rfc/rfc5234.html#appendix-B.1): `DIGIT = %x30-39` — the alphabet the two positions admit

## Configuration

```toml
[rules.message_http_version_syntax_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Both start-lines carry the production: the name in uppercase, one digit either side of the period.

```http
GET /path HTTP/1.1
Host: example

HTTP/1.1 200 OK
Content-Type: text/plain

Hello
```

### ✅ Good A version with no minor versions of its own is written with the `0` RFC 9110 §2.5 supplies, which is how RFC 9114 §4.3.1 states it. Neither line is on the wire — HTTP/3 has no start-line — but a capture records the version anyway, and this is the spelling.

```http
GET /path HTTP/3.0
Host: example

HTTP/3.0 200 OK
Content-Type: text/plain

Hello
```

### ❌ Bad The name is a case-sensitive string, so `http` is not the name; and `1.10` is two digits in the minor position where the production writes one.

```http
GET /path http/1.1
Host: example

HTTP/1.10 200 OK
Content-Type: text/plain

Hello
```

### ❌ Bad The right shape, the wrong alphabet: `x` is not a `DIGIT`. The request is reported first because a capture always holds one.

```http
GET /path HTTP/1.x
Host: example

HTTP/1.1 200 OK
Content-Type: text/plain

Hello
```
