<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Status Code Valid Range

## Description

Reports a response whose status code falls outside the range RFC 9110 §15 defines — *"All valid status codes are within the range of 100 to 599, inclusive"* — and which the same section then calls invalid in as many words: *"Values outside the range 100..599 are invalid."*

No sentence spells this as a MUST, and it does not need one: the RFC states the invalidity outright, and §16.2.2 closes the range against ever widening, because new status codes *"are required to fall under one of the categories defined in Section 15"* and those five categories are 1xx through 5xx. Either way the recipient gets nothing it can act on — §15 directs a client receiving an invalid status code to process the response as if it had a 5xx.

**The three out-of-range cases have different causes, and the finding names which one it is.** A code in 600..999 is a three-digit value a status-line can carry, and §15 names that range as the one implementations use for internal, non-HTTP status such as library errors — so a finding there usually means an internal status leaked onto the wire. A value above 999 cannot be written as a `status-code` at all (RFC 9112 §4: `status-code = 3DIGIT`), and one below 100 only as a leading-zero code such as `007`, which the status parser on the capture path rejects for every version; both of those reach the rule from a capture file supplied to the `lint` subcommand, where the status is read as a plain integer. That is also why only the first has a published example: an example is a message, and no message this toolchain can parse carries the other two.

**It does not check whether the code is registered, and an unregistered code in range is not a finding.** §15 requires a client to understand a status code's *class* and to treat an unrecognized code as equivalent to the x00 of that class — the RFC's own example is a 471 read as a 400 — so an in-range code nobody has registered is still well defined for every recipient. §15.1 asks only that additional codes *"ought to be"* registered, which is weaker than SHOULD, and the registry is open.

The reason-phrase beside the code is not read: RFC 9112 §4 makes it optional and asks clients to ignore it. What a *valid* status code implies for the rest of the message — which fields it may carry, whether it may have content, whether it is cacheable — belongs to the rules for each of those questions.

## Specifications

- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): Status Codes: the three-digit code, the 100..599 range, the statement that values outside it are invalid, what 600..999 is used for, and what a client does with an invalid code
- [RFC 9110 §15.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.1): Overview of Status Codes: additional codes `ought to be` registered — the modal that keeps this rule from checking registration
- [RFC 9110 §16.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.2.2): Considerations for New Status Codes: a new code must fall under one of the five classes §15 defines, so the range cannot widen
- [RFC 9112 §4](https://www.rfc-editor.org/rfc/rfc9112.html#section-4): Status Line: `status-code = 3DIGIT`, the written form an HTTP/1.1 response can carry, and the optional reason phrase this rule does not read
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Conformance: a sender must not generate an element that does not match its ABNF — reached from RFC 9112 §1.1, and the modal behind the one value no `status-code` can express

## Configuration

```toml
[rules.server_status_code_valid_range]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
```

### ✅ Good Response (unregistered code, in range)

```http
HTTP/1.1 471 Unrecognized
```

### ❌ Bad Response (internal non-HTTP status on the wire)

```http
HTTP/1.1 600 Internal Library Error
```
