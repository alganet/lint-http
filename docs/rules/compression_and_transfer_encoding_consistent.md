<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Compression And Transfer Encoding Consistent

## Description

Flags a message that names the same coding in both `Content-Encoding` and `Transfer-Encoding` — for example `Content-Encoding: gzip` alongside `Transfer-Encoding: gzip, chunked`. Both directions are checked, and the finding names the side it describes.

**This is advisory, and no sentence forbids it.** The two fields address different layers, which both specifications say in mirrored sentences: RFC 9112 §6.1, "Unlike Content-Encoding …, Transfer-Encoding is a property of the message, not of the representation"; RFC 9110 §8.4, "Unlike Transfer-Encoding …, the codings listed in Content-Encoding are a characteristic of the representation". Naming a coding at both layers means the representation is compressed and then compressed *again* in transit. That is decodable, not malformed — RFC 9112 §7.3 guarantees a transfer coding and a content coding sharing a name are "identical" transformations, and RFC 9110 §8.4 contemplates a coding "applied a second time" outright, remarking only that it would take "some bizarre reason". The finding says the message is almost certainly not what its sender meant; it does not say the message breaks a rule.

**What it does not do.** It makes no claim about the *body*: nothing here decodes anything or checks that the codings were really applied. `Content-Encoding` is taken at its word, which RFC 9110 §8.4 licenses — a sender that applied encodings "MUST generate a Content-Encoding header field that lists the content codings in the order in which they were applied".

**Parsing.** The two fields are split by their own grammars: `content-coding` is a bare `token`, so every comma separates; `transfer-coding` carries parameters whose values may be quoted-strings, so that split respects quoting. Names are compared case-insensitively, as both specifications define them to be, and values are decoded from raw octets so that one bad byte cannot hide the names beside it.

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): Content-Encoding — a property of the representation, and the MUST that makes it a trustworthy record of what was applied. Also contemplates a coding applied a second time, which is why this rule is advisory
- [RFC 9110 §8.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1): `content-coding = token` — no parameters, which is why this field's members are split naively
- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — a property of the message, not the representation. The mirror of §8.4's sentence, and the whole basis of the distinction this rule watches
- [RFC 9112 §7.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2): The compression transfer codings, defined by the same algorithm as the content coding of the same name
- [RFC 9112 §7.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.3): Transfer and content coding names may only overlap where the transformation is identical — so a shared name is unambiguous, and coding twice is coherent rather than malformed
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): The `transfer-coding` grammar, including the quoted-string a parameter may carry — why that field's split is quote-aware

## Configuration

```toml
[rules.compression_and_transfer_encoding_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Encoding: gzip
Transfer-Encoding: chunked
```

### ✅ Good (transfer-level gzip without Content-Encoding)

```http
HTTP/1.1 200 OK
Transfer-Encoding: gzip, chunked
```

### ✅ Good (different codings at each layer)

```http
HTTP/1.1 200 OK
Content-Encoding: br
Transfer-Encoding: gzip, chunked
```

### ❌ Bad (the same coding at both layers)

```http
HTTP/1.1 200 OK
Content-Encoding: gzip
Transfer-Encoding: gzip, chunked
```

### ❌ Bad (a request codes its body twice)

```http
POST /upload HTTP/1.1
Host: example.com
Content-Encoding: gzip
Transfer-Encoding: gzip, chunked
```
