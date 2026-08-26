<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Status 103 Early Hints Before Final

## Description

A `103 (Early Hints)` response is *interim*: RFC 9110 §15 gives a single request zero or more interim responses "followed by exactly one final response", and RFC 8297 §2 defines the status as telling the client that a final response is still likely to come. This rule reports a capture in which the response recorded for a request **is** the `103` — an exchange whose final response is not in the capture, or an interim response that some recipient took for the final one (RFC 8297 §3 describes exactly that mishandling). It also reports a `103` answering an HTTP/1.0 request, which RFC 9110 §15.2 makes a MUST NOT because HTTP/1.0 defined no `1xx` status codes at all.

**What this rule does not report, and why.** A conforming `103` followed by a final response is not a defect and is not visible either: a transaction in this capture format has one response field, so a `103` and the final response for the same request are never both recorded. The check this rule used to make — a `103` for a client and target whose *previous* transaction had ended in a final response — was therefore not about RFC 9110 §15's requirement at all. Two transactions are two requests, and a repeat request to a URI answered with a `103` is the document's ordinary case; that finding is retired.

**RFC 8297 states no requirement on a server.** Its three BCP 14 requirements — two MUST NOTs and a SHOULD NOT — are addressed to the client and concern what it does with the fields, which no captured message states. Its two server sentences are MAYs: a `103` may carry only some of the fields expected in the final response, and a server may emit several of them. Comparing a `103`'s fields against a final response's is declined at the source, since §2 calls the repetition typical and then names cases where omitting it is right.

**Where a `103` in a capture comes from.** On the HTTP/1.x and HTTP/2 upstream legs this proxy discards interim responses before recording anything — hyper's HTTP/1.x client skips `100` and `102..=199` outright, and its HTTP/2 client reads `h2`'s main response, which steps over interim headers. The HTTP/3 leg does not: `h3`'s `recv_response` returns the first HEADERS frame whatever its status, so a `103` from an HTTP/3 origin becomes the recorded response. That leg and `lint` over capture files written elsewhere are where this rule's findings live.

## Specifications

- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): The requirement this rule rests on: a single request's interim responses are followed by exactly one final response — the sentence RFC 8297 never states, and the reason the finding is about one request rather than two transactions
- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): What makes a 103 interim, and the only MUST NOT in reach that is addressed to the sender: HTTP/1.0 defined no 1xx status codes, so a server must not send one to an HTTP/1.0 client
- [RFC 8297 §2](https://www.rfc-editor.org/rfc/rfc8297.html#section-2): The status code's definition, which is the scope gate — and every one of the document's BCP 14 keywords: three requirements addressed to the client and two MAYs addressed to the server, so nothing here is a requirement this rule could enforce
- [RFC 8297 §3](https://www.rfc-editor.org/rfc/rfc8297.html#section-3): Why an interim response recorded as the answer is worth reporting rather than shrugging at: the document's Security Considerations are about a recipient mishandling an informational response as a final one

## Configuration

```toml
[rules.status_103_early_hints_before_final]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — the response recorded for the request is the final one; a 103 that preceded it is not something this capture format holds

```http
> GET /resource HTTP/1.1

< 200 OK
< Content-Type: text/html; charset=utf-8
< Link: </static/style.css>; rel=preload; as=style
```

### ❌ Bad — the interim response is what the capture records as this request's answer, and no final response follows it

```http
> GET /resource HTTP/1.1

< 103 Early Hints
< Link: </static/style.css>; rel=preload; as=style
```

### ❌ Bad — HTTP/1.0 defined no 1xx status codes, so this one may not be sent at all

```http
> GET /resource HTTP/1.0

< 103 Early Hints
< Link: </static/style.css>; rel=preload; as=style
```
