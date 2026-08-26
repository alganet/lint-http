<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Referer Header URI Valid

## Description

Reads the `Referer` request header field against the production RFC 9110 §10.1.3 gives it — `Referer = absolute-URI / partial-URI` — and against the two components that section forbids a user agent to include.

**The field's value is not a `URI-reference`, and the difference is the whole point.** `URI` and `relative-ref` each end in an optional `[ "#" fragment ]` group; `absolute-URI` and `partial-URI` are those two rules with that group dropped, which RFC 9110 §4.1 states in as many words — a `partial-URI` *"is defined for protocol elements that can contain a relative URI but not a fragment component"* — and RFC 3986 §4.3 says the same of the absolute form. So a fragment in this field derives from no reading of the grammar, and §10.1.3's own MUST NOT names it beside the userinfo: *"A user agent MUST NOT include the fragment and userinfo components of the URI reference [URI], if any, when generating the Referer field value."* Both are reported. A percent-encoded `%23` is data, not a fragment.

**A userinfo is a credential leaking into a field servers log.** The finding withholds everything after the first colon of the subcomponent, which is what RFC 3986 §3.2.1 asks of an application rendering a URI, and it says so in the message; that section also deprecates the `user:password` form outright.

**An `https` referrer on an unsecured request is reported.** §10.1.3: *"A user agent MUST NOT send a Referer header field in an unsecured HTTP request if the referring resource was accessed with a secure protocol."* Both halves are read from a scheme — §4.2.2 defines `https` over a connection secured for HTTP communication and requires a client to secure its requests for such a resource, and §4.2.1 defines `http` over a TCP connection and nothing more. **The request's own scheme is not always on the wire**: it is there when the target is in absolute form, which is how HTTP/2 and HTTP/3 reassemble a target from `:scheme` and how an HTTP/1.1 request to a proxy is written, and it is absent from an origin-form target, where no captured field records it. A request whose scheme is unknown draws nothing from this check rather than being guessed at.

**The rest of the value.** Every character is measured against the set a URI is composed from — the union of `unreserved`, `gen-delims`, `sub-delims` and the `%` that opens a triplet — and each `%` against `pct-encoded = "%" HEXDIG HEXDIG`. That union is a **floor, not a ceiling**: `[` and `]` derive from no component but the host productions, and `:` and `@` from `pchar` but not from `reg-name`, so a character passing it has only been found somewhere in the generic syntax. What the value offers as a scheme is measured against `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, and a value failing it is not re-read as a relative reference, because a first path segment holding a colon is no `path-noscheme` (RFC 3986 §4.2). Where the value carries an authority — the `"//" authority path-abempty` alternative both `hier-part` and `relative-part` open with — the host and port are read as `uri-host [ ":" port ]`, and an empty host under `http` or `https` is the MUST NOT those two schemes each state for themselves.

**`Referer` is a singleton.** Neither alternative of its grammar is a comma-separated list, so RFC 9110 §5.3 forbids a second field line, and the report counts the lines rather than inspecting the joined value: a comma is a `sub-delims` character both alternatives admit inside a path or a query, so what a recipient recombines two lines into is a well-formed reference to a resource neither line named.

**An empty value is reported as advice and says so.** `partial-URI` admits `path-empty`, so it is a same-document reference (RFC 3986 §4.4) resolving to the target URI the request already carried, and the grammar has no complaint. What makes it worth a word here — and this field differs from `Location` and `Content-Location` in it — is that §10.1.3 names the two things a user agent with no referring URI to state does, omit the field or send `about:blank`, and an empty value is neither. The MUST behind that is not reachable from a capture, because nothing in a message says where the target URI came from.

**What this rule declines, and why.**

- **The cross-origin SHOULD NOT.** §10.1.3 asks a user agent not to send the field when the referring resource was accessed securely and the request target has a different origin — *"unless the referring resource explicitly allows Referer to be sent"*. That permission is stated by the referring resource's own response, in a different transaction, so the escape clause's antecedent is invisible here and a finding would report every conforming cross-origin request that carries it.
- **The exclude-or-`about:blank` MUST.** Its antecedent is that the target URI came from a source with no URI of its own — a keyboard, a bookmark. No field records that.
- **The intermediary SHOULD NOT** — *"An intermediary SHOULD NOT modify or delete the Referer header field when the field value shares the same scheme and host as the target URI."* Deciding it means comparing a message against the same message before some intermediary handled it, and a capture is one message.
- **Whether the value names the resource the request actually came from.** §10.1.3 permits a user agent to *"truncate parts other than the referring origin"*, so a value naming less than the full URI is conforming, and nothing in a single transaction knows what the referring resource was.
- **Whether an `http` or `https` authority resolves, or a port is one a transport could carry.** `port` is `*DIGIT` (RFC 3986 §3.2.3), which bounds nothing at either end.

**What other rules own.** A fragment on the *request target* is `request_target_no_fragment`'s, on every version; a malformed percent-encoding in the target is `request_uri_percent_encoding_valid`'s. The same `absolute-URI / partial-URI` production governs `Content-Location` (RFC 9110 §8.7), whose rule reads the same fragment question from the grammar and RFC 9110 §2.2 alone — no MUST NOT names the component for that field.

## Specifications

- [RFC 9110 §10.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3): Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals
- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References — `partial-URI` is the rule for elements that carry a relative URI but no fragment, and an element's ABNF is what says which forms it allows
- [RFC 9110 §4.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1): http URI Scheme — a TCP connection and no more, and the MUST NOT against an empty host identifier
- [RFC 9110 §4.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2): https URI Scheme — what "secured" means for a resource named by one, and the MUST NOT against an empty host identifier
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — the MUST NOT against a second field line for a field with no list alternative
- [RFC 9110 §17.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.9): Disclosure of Sensitive Information in URIs — why §10.1.3 limits the field
- [RFC 3986 §3.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1): User Information — the production, its `@` delimiter, the deprecated `user:password` form, and the request not to render what follows the first colon
- [RFC 3986 §4.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2): Relative Reference — `relative-part`, and why a first path segment holding a colon is not one
- [RFC 3986 §4.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3): Absolute URI — the form without a fragment identifier
- [RFC 3986 §4.4](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.4): Same-Document Reference — what an empty value is
- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — the triplet the `%` obliges

## Configuration

```toml
[rules.referer_uri_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The example §10.1.3 prints

```http
GET / HTTP/1.1
Referer: http://www.example.org/hypertext/Overview.html
```

### ✅ Good A `partial-URI`, resolved against the target URI

```http
GET / HTTP/1.1
Referer: /relative/path?q=1
```

### ✅ Good The value §10.1.3 names for a source that has no URI

```http
GET / HTTP/1.1
Referer: about:blank
```

### ✅ Good A network-path reference: `relative-part` opens with one

```http
GET / HTTP/1.1
Referer: //other.example/page
```

### ❌ Bad A fragment: neither alternative of the grammar generates one

```http
GET / HTTP/1.1
Referer: http://example.com/a#section
```

### ❌ Bad A userinfo subcomponent, credentials and all

```http
GET / HTTP/1.1
Referer: https://alice:s3cret@example.com/a
```

### ❌ Bad An `https` referrer on an unsecured request

```http
GET http://example.com/ HTTP/1.1
Referer: https://secure.example/page
```

### ❌ Bad A character no URI is composed from

```http
GET / HTTP/1.1
Referer: https://example.com/ bad
```

### ❌ Bad A `%` that does not open a triplet

```http
GET / HTTP/1.1
Referer: /bad%2Gencoding
```

### ❌ Bad An empty host identifier under `http`

```http
GET / HTTP/1.1
Referer: http:///page
```
