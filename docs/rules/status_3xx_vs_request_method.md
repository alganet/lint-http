<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# The two redirects that let the user agent pick the method

## Description

`301 Moved Permanently` and `302 Found` are the two redirect statuses whose own definitions permit a user agent to change the request method, and the method they name is `POST`. This rule reports a `301` or a `302` that answers a `POST` request and carries a `Location` for the user agent to follow — the response does not determine whether the redirected request arrives as a `POST` or as a `GET`.

**This is advice, not a violation.** The sentence it rests on is a note carrying a `MAY` addressed to user agents (RFC 9110 §15.4.2, §15.4.3); no sentence forbids a server from answering a `POST` with a `301` or a `302`, and a server that knows its clients may have nothing to fix. What the finding buys is that the ambiguity is a choice, not an accident.

**The alternative is per status, and they are not interchangeable:**

- `301` → `308 Permanent Redirect` — §15.4.2 names it, and it keeps the redirect permanent
- `302` → `307 Temporary Redirect` — §15.4.3 names it, and it keeps the redirect temporary
- either → `303 See Other`, where the change to `GET` is what the server wants. §9.3.3 permits this with a `MAY`, under a condition this rule cannot see: that the result of processing the `POST` is equivalent to a representation of an existing resource.

**No method other than `POST` is reported.** The two notes name `POST`, and §15.4's history records that `301` and `302` "have been adjusted to allow a POST request to be redirected as GET" — a `PUT`, `PATCH` or `DELETE` following one of them keeps its method, so there is nothing ambiguous to report. This rule previously reported every method not known to be safe.

**The method is compared exactly**, because §9.1 says the method token is case-sensitive: a request whose method is `post` is not a `POST` request. `request_method_token_valid` is the rule that reports it.

**Not reported:** a `301` or `302` carrying no `Location`. With nothing to follow there is no redirected request whose method could differ, and the missing field is `location_on_redirect_present`'s finding.

## Specifications

- [RFC 9110 §15.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2): 301 Moved Permanently: a user agent MAY change the method from POST to GET, and 308 is the status named for a server that does not want that
- [RFC 9110 §15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3): 302 Found: the same permission, answered by 307 rather than by 308 — the alternative is per status
- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): Why only these two: 307 and 308 were added to indicate method-preserving redirects, and 301 and 302 were adjusted to allow a POST to be redirected as GET. This is also the only sentence that says 308 preserves the method — §15.4.9 does not repeat it. Also what a provided Location buys: a user agent MAY follow it automatically
- [RFC 9110 §15.4.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8): 307 Temporary Redirect: the user agent MUST NOT change the request method when it redirects automatically — the unambiguous half of the 302 pair, and never reported by this rule
- [RFC 9110 §15.4.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4): 303 See Other: defined as a redirection to a resource the user agent retrieves, so the change of method is what the status means rather than something left open
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, so the rule compares it exactly rather than folding case
- [RFC 9110 §9.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3): The 303 alternative: an origin server MAY redirect a POST with a 303, if the result of processing it is equivalent to a representation of an existing resource

## Configuration

```toml
[rules.status_3xx_vs_request_method]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good 308 keeps the method, and keeps the redirect permanent

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 308 Permanent Redirect
Location: /submit-new
```

### ✅ Good 307 is the temporary one

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 307 Temporary Redirect
Location: /submit-new
```

### ✅ Good 303 asks for the change to GET rather than leaving it open

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 303 See Other
Location: /status
```

### ✅ Good A PUT is not reported: no sentence lets a user agent rewrite it

```http
PUT /doc HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: /doc-new
```

### ❌ Bad 301: the redirected request may arrive as POST or as GET

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: /submit-new
```

### ❌ Bad 302: the same ambiguity, and 307 is its alternative

```http
POST /submit HTTP/1.1
Host: example.com

HTTP/1.1 302 Found
Location: /submit-elsewhere
```
