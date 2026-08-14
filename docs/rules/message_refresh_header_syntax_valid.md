<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Refresh header syntax

## Description

Validate the syntax of the `Refresh` response header. Long treated as non-standard, it is now specified by the HTML Standard (§ 7.8), which says it is the HTTP equivalent of a `meta` element with `http-equiv="refresh"` and *takes the same value*. That value has exactly two conforming forms: a delay in seconds on its own, or a delay followed by `;`, one or more spaces, `URL=` (in any case), and a valid URL string that does not begin with a quote. This rule reports a value matching neither.

Where the verdicts come from, since § 7.8 states no requirement of its own: the `must` is the authoring conformance requirement written for the `meta` pragma's content attribute, and "takes the same value" is the sentence that carries it to the field. The URL is judged against the WHATWG URL Standard's alphabet — its *URL units* — rather than RFC 3986's, so a non-ASCII octet is a URL code point here, and a relative reference such as `1http://x` is a conforming URL rather than a malformed scheme.

Only the URL's alphabet is checked. Whether its components are in a legal order, and whether its host parses, are the URL parser's questions and are not asked.

More than one `Refresh` field line is reported on its own terms: HTML records that it has no specification for that case, so the finding is an interoperability report rather than a violation of a stated requirement, and nothing further is measured — the string a recipient parses is the combination of the lines, not any one of them.

## Specifications

- [HTML Speculative Loading §7.8](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-refresh-header): The `Refresh` header. Three sentences: it is the `meta` pragma's HTTP equivalent, it takes the same value, and its processing model is elsewhere. It states no requirement of its own
- [HTML Semantics §4.2.5.3](https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh): Refresh state: the shared declarative refresh steps, and the authoring conformance requirement this rule enforces — the only sentence in HTML that says what a conforming value looks like
- [HTML Document Lifecycle §7.5.1](https://html.spec.whatwg.org/multipage/document-lifecycle.html#initialise-the-document-object): Create and initialize a Document object: the field is isomorphic-decoded before parsing, and a note records that multiple field lines are unspecified
- [URL §4.3](https://url.spec.whatwg.org/#url-writing): URL writing: valid URL string, URL code points and URL units — the alphabet the `URL=` value is judged against, which is not RFC 3986's
- [MDN Refresh](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh): `Refresh` header, with browser support notes

## Configuration

```toml
[rules.message_refresh_header_syntax_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Refresh: 5

HTTP/1.1 200 OK
Refresh: 10; url=/new

HTTP/1.1 200 OK
Refresh: 0; URL=/report?from=a,b;to=c
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Refresh: bad

HTTP/1.1 200 OK
Refresh: +5

HTTP/1.1 200 OK
Refresh: 10;url=/new

HTTP/1.1 200 OK
Refresh: 5; url=

HTTP/1.1 200 OK
Refresh: 5; url="/new"

HTTP/1.1 200 OK
Refresh: 5; foo=bar

HTTP/1.1 200 OK
Refresh: 5, 10
```
