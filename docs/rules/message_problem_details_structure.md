<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Problem Details Structure

## Description

Reports a response whose `Content-Type` is `application/problem+json` but whose content is not the problem details JSON object that media type identifies — content that is empty, that does not parse as JSON, or that parses as some other JSON value (an array, a string, a number). RFC 9457 defines the format; it obsoletes RFC 7807.

**Any status code.** RFC 9457 says problem details "can be used with any HTTP status code, but they most naturally fit the semantics of 4xx and 5xx responses". Whether they *suit* a status is `server_problem_details_content_type`'s question; this rule's is whether content labelled as problem details is problem details, and that question reads the same on a 200 as on a 500.

**An empty JSON object is conforming and is not reported.** Every member is optional: §3.1 introduces them with "can have", §3.1.1 says that when `type` is absent "its value is assumed to be `about:blank`", and §4.2.1 confirms that "any problem details object not carrying an explicit `type` member implicitly uses this URI" — the registered type meaning the problem has no semantics beyond the status code. So `{}` is a problem details object that says exactly that.

**What the finding rests on.** No RFC states a MUST that content match its `Content-Type`. RFC 9110 §8.1 defines representation data as being "in a format and encoding defined by the representation metadata header fields", §8.3 says the indicated media type "defines both the data format and how that data is intended to be processed by a recipient", and the same section calls a server that does otherwise one that has not been configured "to provide the correct Content-Type for a given representation". A finding is a contradiction between two things the message itself states, not a matter of taste — but it is definitional in origin, not a stated requirement.

**Limits.** Only the JSON serialization is checked: RFC 9457 defines an equivalent XML format (`application/problem+xml`) in Appendix B, and measuring an XML document against it needs a parser this crate does not have. A `Content-Encoding` means the captured octets are the coded form, so they are not parsed as JSON — the emptiness checks still apply, since a coded representation of nothing is still nothing. Two `Content-Type` field lines are declined: `Content-Type` is a singleton, recipients often act on the last member, and `message_content_type_well_formed` reports the duplication. A response carrying no `Content-Type` at all is `server_content_type_present`'s finding, and an unparseable one is `message_content_type_well_formed`'s.

Captured bodies are available to rules in memory; the `captures_include_body` setting only controls whether bodies are persisted to the captures file. A body captured as a truncated prefix is not parsed. Where no bytes are available — a transaction read back from a capture file — the emptiness half of the question is still answered from the counted octets, or failing that from a declared `Content-Length` of zero, which is evidence only when no `Transfer-Encoding` overrides it.

## Specifications

- [RFC 9457 §3](https://www.rfc-editor.org/rfc/rfc9457.html#section-3): The problem details JSON object and the media type that identifies it; §3.1 and §3.1.1 are where every member is made optional and `type` is given a value for its own absence
- [RFC 9457 §4.2.1](https://www.rfc-editor.org/rfc/rfc9457.html#section-4.2.1): `about:blank`, the registered problem type for a problem with no semantics beyond the status code — and the sentence saying an object carrying no explicit `type` implicitly uses it, which is why an empty object is conforming
- [RFC 9110 §8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.1): Representation data is in the format its metadata names — the sentence that makes a mismatch between the content and the `Content-Type` a contradiction rather than a preference; §8.3 adds what the recipient does with the indicated media type, and §8.4 that a content coding has to be undone first
- [RFC 8259 §2](https://www.rfc-editor.org/rfc/rfc8259.html#section-2): What a JSON text is — the measure for content that is empty or does not parse; §8.1 adds the UTF-8 requirement the parser also enforces

## Configuration

```toml
[rules.message_problem_details_structure]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good a problem details object

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Content-Length: 70

{"type":"https://example.com/probs/out-of-credit","title":"No credit"}
```

### ✅ Good no member is required — this one means "about:blank"

```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json
Content-Length: 2

{}
```

### ❌ Bad the media type says JSON; the content is not a JSON document

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/problem+json
Content-Length: 21

Internal Server Error
```

### ❌ Bad well-formed JSON, but not the object the media type names

```http
HTTP/1.1 422 Unprocessable Content
Content-Type: application/problem+json
Content-Length: 41

[{"detail":"must be a positive integer"}]
```
