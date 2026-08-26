<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Language Tag Format Valid

## Description

Check the language tags in `Content-Language` and the language ranges in `Accept-Language` for the syntax problems that are unambiguous: a non-alphanumeric character, whitespace, an empty subtag, a leading or trailing hyphen, a subtag longer than eight characters, and a first subtag that does not begin with a letter. Common forms pass — `en`, `en-US`, `zh-Hant`, `sr-Latn-RS`, `es-419`, and private-use tags like `x-custom`.

**The two fields do not use the same production, and RFC 9110 §8.5.1 says so outright:** "Accept-Language uses the broader `language-range` production defined in Section 12.5.4, whereas Content-Language uses the `language-tag` production defined below." A range is RFC 4647 §2.1; a tag is RFC 5646 §2.1. This rule's specifications used to claim that Accept-Language uses RFC 5646 tags, which is the opposite of what §8.5.1 says.

**One validator serves both, and it checks only what the two productions agree on.** That is deliberate. RFC 4647 is explicit that a basic language range carries no well-formedness requirement at all — an ill-formed one "will probably not match anything", which is a statement about matching rather than a licence to reject it. So the check is set at the properties a range and a tag share, and **where they differ this rule is lenient toward Content-Language**: `en-US-Latn` is a conforming range and not a conforming tag (script must precede region), and `e` is a conforming range whose single letter no `language` alternative of RFC 5646 admits. Neither is reported. Being stricter would take two validators and a decision about how much of RFC 5646 to implement; being wrong in the other direction would report conforming `Accept-Language` values, which is worse.

**`*` is skipped in Accept-Language and reported in Content-Language.** It is one of the two alternatives of `language-range` and is not a `language-tag`; `Content-Language = #language-tag` has no wildcard. The asymmetry belongs to the two grammars, not to this rule.

**Weights are not read here.** In `Accept-Language` everything from the first `;` onward is stripped and left to `accept_language_weight_valid`; in `Content-Language` there is no `;` in the grammar, so one reaches the validator and is reported as the invalid character it is.

**An octet outside visible US-ASCII is reported, not skipped.** Neither production has a quoted-string in it, so no such octet is ever legal here — and refusing to decode the value used to make the whole field line vanish, hiding any other defect on it.

**Every field line of both fields is read**, since each is a list whose members may be spread across lines.

## Specifications

- [RFC 9110 §8.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5.1): Language Tags: the sentence that assigns a different production to each of the two fields — `language-range` for Accept-Language, `language-tag` for Content-Language
- [RFC 5646 §2.1](https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1): Syntax: the `Language-Tag` production Content-Language carries. Its prose properties are enforced; its subtag ordering and length classes are not
- [RFC 4647 §2.1](https://www.rfc-editor.org/rfc/rfc4647.html#section-2.1): Basic Language Range: the production Accept-Language carries, including the `*` alternative and the statement that a range needs no well-formedness at all
- [RFC 9110 §8.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5): Content-Language: `#language-tag` — a list of tags, with no wildcard and no weight in it
- [RFC 9110 §12.5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4): Accept-Language: where the `language-range` production is pulled in by reference. The weight beside it is `accept_language_weight_valid`'s subject

## Configuration

```toml
[rules.language_tag_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Accept-Language: en, fr-CA;q=0.8
Content-Language: en-US
```

### ✅ Good (the wildcard is a language-range, and digits are fine after the first subtag)

```http
Accept-Language: *, es-419
Content-Language: mi, en
```

### ❌ Bad (an underscore is not a subtag separator)

```http
Accept-Language: en_US
```

### ❌ Bad (a subtag is at most eight characters)

```http
Content-Language: en-TooLongSubtag123
```

### ❌ Bad (neither a tag nor a range may begin with a digit)

```http
Accept-Language: 123-US
```

### ❌ Bad (Content-Language has no wildcard alternative)

```http
Content-Language: *
```
