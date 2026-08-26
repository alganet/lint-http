<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Max Forwards Numeric

## Description

Validates the `Max-Forwards` request header field's value against its own production, `Max-Forwards = 1*DIGIT` (RFC 9110 §7.6.2): one or more ASCII digits and nothing else. The field limits how many times a `TRACE` or `OPTIONS` request may be forwarded, so a value a proxy cannot read is a limit that does not apply.

At least one digit is required. `Max-Forwards:` carrying nothing is reported — the opposite answer from the comma-separated-list fields, where a value of no members is a value the production generates; `1*DIGIT` names no such alternative.

The field is a **singleton**: its grammar has no comma-separated-list form, so a message carries at most one `Max-Forwards` field line (RFC 9110 §5.3), and two lines are reported as that. §5.2 makes them one value in any case, and the comma a recipient recombines them with is not a digit.

A value carrying an octet outside US-ASCII is measured rather than skipped, and the finding names the octet. This is not a UTF-8 question: `1*DIGIT` admits %x30–39 and nothing else, so `obs-text` is reported for not being a digit, which is what is wrong with it. Leading and trailing whitespace is excluded before the value is evaluated (§5.5), and only `SP`/`HTAB` count as that — %xA0 is an octet, not whitespace.

The value is never parsed into an integer. `1*DIGIT` puts no bound on its length, so `Max-Forwards: 0000000000000000000000005` is a conforming value that no integer type holds, and leading zeros are likewise fine.

**Scope: this rule reads the field's syntax and nothing else.** §7.6.2's requirements on the *value* are addressed to the intermediary forwarding the message — it MUST check and update the value before forwarding, MUST NOT forward at all when it receives zero (it responds as the final recipient instead), and §9.3.7 says a proxy MUST NOT generate the field while forwarding a request that arrived without it. A captured transaction records the request as it was received on one leg; the message that was forwarded upstream is not in it, so nothing here can tell whether the value was decremented, honoured at zero, or written by the sender at all. Those are gaps in what any rule can measure, not checks this rule leaves out.

The field on a method other than `TRACE` or `OPTIONS` is not reported. §7.6.2 says a recipient MAY ignore it there — a permission granted to the recipient, not a prohibition on the sender — so such a request has a syntactically valid field that limits nothing. Whether the field may appear in a *trailer* section is §6.5.1's question and `message_trailer_fields_validity`'s finding.

## Specifications

- [RFC 9110 §7.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.2): The field: its grammar (`1*DIGIT`), the methods it works with, and the recipient's permission to ignore it on the others. The section's requirements on intermediaries — check and update the value, do not forward at zero — are stated here and are not measurable from one captured leg; this rule reads the syntax only
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): A sender MUST NOT generate multiple field lines with the same name unless the field's definition allows them to be recombined as a comma-separated list. `Max-Forwards` has no such alternative, so two lines are reported
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Repeated field lines in one section are one field value, joined with a comma — so the value measured against `1*DIGIT` is the one a recipient reads
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Singleton fields, why detecting a singleton sent with several members is worth doing, and the MUST to exclude leading and trailing whitespace before evaluating a field value
- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): A client MAY send the field in an OPTIONS request to target a specific recipient, and a proxy MUST NOT generate it while forwarding a request that arrived without it — the second is undecidable from a captured message, since nothing on the wire records who wrote a field

## Configuration

```toml
[rules.max_forwards_numeric]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Zero: the request stops at the first recipient, which answers it

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: 0
```

### ✅ Good `1*DIGIT` says nothing about leading zeros or magnitude

```http
OPTIONS * HTTP/1.1
Host: example.com
Max-Forwards: 007
```

### ❌ Bad `-` is not a DIGIT; the production has no sign

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: -1
```

### ❌ Bad A decimal integer, not a decimal fraction

```http
OPTIONS * HTTP/1.1
Host: example.com
Max-Forwards: 1.0
```

### ❌ Bad A singleton sent with two members, on one line: `,` is not a DIGIT

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards: 120, 240
```

### ❌ Bad `1*DIGIT` requires a digit, so a value of none is not a value

```http
TRACE / HTTP/1.1
Host: example.com
Max-Forwards:
```
