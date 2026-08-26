<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Problem Details Content Type

## Description

Reports an error response (4xx or 5xx) whose `Content-Type` is one of the three **generic** JSON or XML media types — `application/json`, `application/xml`, `text/xml` — as a candidate for problem details, the format RFC 9457 defines to carry machine-readable details of an error as `application/problem+json` or `application/problem+xml`. RFC 9457 obsoletes RFC 7807.

**The finding is advisory: no RFC requires problem details.** RFC 9457 says they "can be used with any HTTP status code, but they most naturally fit the semantics of 4xx and 5xx responses", which is where this rule looks, and it twice says that a sender with a format of its own should keep it: §1 notes that where the response is still a representation of a resource "it's often preferable to describe the relevant details in that application's format", and §4 that problem details are "intended to avoid the necessity of establishing new 'fault' or 'error' document formats, not to replace existing domain-specific formats". A finding means this error response carries no error format at all, not that its sender did anything wrong.

That is why the reported set stops at the three generic media types. A subtype ending in `+json` or `+xml` (`application/hal+json`, `application/vnd.api+json`) names a specific format, so the sender has the one RFC 9457 prefers and the rule says nothing. It also says nothing about a `Content-Type` it cannot parse, which is `message_content_type_well_formed`'s finding, nor about a response carrying no `Content-Type` at all, which is `content_type_present`'s. A response carrying **two** `Content-Type` field lines is declined for a third reason: RFC 9110 §8.3 says recipients often act on the last syntactically valid member, so which media type the peer reads is not knowable, and `message_content_type_well_formed` reports the duplication itself.

## Specifications

- [RFC 9457 §1](https://www.rfc-editor.org/rfc/rfc9457.html#section-1): Which status codes problem details suit, and the two sentences saying an application-specific format is often the better answer — between them the reason this rule's finding is advice and not a defect
- [RFC 9457 §3](https://www.rfc-editor.org/rfc/rfc9457.html#section-3): The problem details JSON object, and the media type that identifies it: `application/problem+json`
- [RFC 9457 §B](https://www.rfc-editor.org/rfc/rfc9457.html#appendix-B): The equivalent XML format and its media type, `application/problem+xml` — the second value this rule accepts is defined in an appendix, not in the body of the document
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): The field this rule reads: that it is a singleton and what recipients do when it is sent twice (the reason a duplicated field line is declined), and, in §8.3.1, that its type and subtype tokens are case-insensitive

## Configuration

```toml
[rules.problem_details_content_type]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good problem details, in the media type that names them

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{"type":"https://example.com/probs/out-of-credit","title":"You do not have enough credit","status":400}
```

### ✅ Good an application's own error format — RFC 9457 §4 says to keep it

```http
HTTP/1.1 422 Unprocessable Content
Content-Type: application/vnd.api+json

{"errors":[{"status":"422","title":"must be a positive integer"}]}
```

### ❌ Bad the content is problem details; the media type does not say so

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"type":"https://example.com/probs/internal","title":"Internal error","status":500}
```
