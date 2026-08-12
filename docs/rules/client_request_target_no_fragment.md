<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Target No Fragment

## Description

Reports a request whose target carries a fragment identifier — a number sign (`#`) and everything after it to the end of the value (RFC 3986 §3.5).

**A client has no fragment to send.** It resolves the URI reference it started from into the target URI, and that target URI *"excludes the reference's fragment component, if any, since fragment identifiers are reserved for client-side processing"* (RFC 9110 §7.1). RFC 3986 §3.5 says why: the fragment is separated from the rest of the URI before a dereference, and the information in it is dereferenced solely by the user agent, whatever the scheme. A recipient handed one has been sent a component addressed to the sender.

**Which protocol elements admit a fragment is decided by their ABNF, and no request target's does.** RFC 9110 §4.2.5 states the rule — elements that do not allow one use *"a specific rule that excludes fragments"* — and the generic syntax has the clearest example of such a rule: `absolute-URI` is `scheme ":" hier-part [ "?" query ]`, which is the `URI` production with `[ "#" fragment ]` dropped. HTTP/1.1's `absolute-form` is exactly that (RFC 9112 §3.2.2); `origin-form` is an absolute path and an optional query; a CONNECT's target is a host and a port; the asterisk is one character. HTTP/2 and HTTP/3 send no request-line at all, and their `:path` is the path and query parts of the target URI (RFC 9113 §8.3.1, RFC 9114 §4.3.1) — the same two productions. So the finding rests on RFC 9110 §2.2's *"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules"*, and RFC 9112 §1.1 is what carries that conformance criterion to an HTTP/1.1 production.

The rule is therefore **not version-gated**: only the last sentence of the finding differs, naming the request-line or the pseudo-header fields the fragment rode in on.

**A percent-encoded number sign is data and is not reported.** `%23` is what RFC 3986 §2.2 asks for when data would conflict with a reserved character's purpose as a delimiter, so `/a%23b` is a path segment containing a number sign and is clean. An empty fragment (`/a#`) is reported: the component is present, and the number sign is what says so.

**What this rule cannot see: anything this proxy captured itself.** Both transports build the recorded target from a parsed URI, and that parse truncates the value at the first number sign before a transaction exists — the fragment is gone before any rule runs, and it does not reach the upstream either. The finding is reachable when a capture recorded elsewhere is read back through the `lint` subcommand's JSONL file.

**What this rule does not decide.** Which of the four forms a request-target derives from, and whether the method may use that form, is `client_request_target_form_checks`; whether a percent-encoded triplet is well formed is `client_request_uri_percent_encoding_valid`. Whether a *field* carrying a URI reference may hold a fragment is that field's own question and not this one's — `Location = URI-reference` admits one (RFC 9110 §10.2.2), and `Referer` forbids one (§10.1.3).

## Specifications

- [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5): Fragment: indicated by a number sign and terminated by the end of the URI; separated from the rest of the URI before a dereference and resolved solely by the user agent
- [RFC 3986 §2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.2): Reserved characters: data that would conflict with a delimiter's purpose is percent-encoded before the URI is formed, which is why %23 is not this rule's finding
- [RFC 3986 §4.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3): absolute-URI: the URI production with the fragment component dropped
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource: the target URI excludes the reference's fragment, and the components sent are collectively the request target on every major version
- [RFC 9110 §4.2.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.5): http(s) references with fragment identifiers: whether an element admits a fragment is decided by the ABNF rule it uses
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT that a value matching no production breaks; RFC 9112 §1.1 carries it to the HTTP/1.1 productions
- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target: the four forms an HTTP/1.1 request-line may carry, none of which derives a fragment
- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): HTTP/2 request pseudo-header fields: :path is the path and query parts of the target URI
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): HTTP/3 request pseudo-header fields: the same two parts of the target URI

## Configuration

```toml
[rules.client_request_target_no_fragment]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Request

```http
GET /index.html HTTP/1.1
Host: example.com
```

### ✅ Good Request (a number sign as data, percent-encoded)

```http
GET /search?q=C%23 HTTP/1.1
Host: example.com
```

### ❌ Bad Request (fragment in origin-form)

```http
GET /index.html#section1 HTTP/1.1
Host: example.com
```

### ❌ Bad Request (fragment in absolute-form)

```http
GET http://example.com/index.html#section1 HTTP/1.1
Host: example.com
```
