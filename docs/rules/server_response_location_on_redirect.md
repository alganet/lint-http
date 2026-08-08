<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Response Location on Redirect

## Description

Five status codes are asked for a `Location` header field in their own status definition, and this rule reports a response on one of them that carries none.

- `301 Moved Permanently` — a preferred URI reference for the new permanent URI (RFC 9110 §15.4.2, SHOULD)
- `302 Found` — a URI reference for the different URI (§15.4.3, SHOULD)
- `303 See Other` — §15.4.4 defines the status as a redirection to the resource the field names; there is no separate SHOULD because the field is what the status *is*
- `307 Temporary Redirect` — a URI reference for the different URI (§15.4.8, SHOULD)
- `308 Permanent Redirect` — a preferred URI reference for the new permanent URI (§15.4.9, SHOULD)

**`300 Multiple Choices` is not reported.** §15.4.1's SHOULD is conditioned on the server *having* a preferred choice, which no field on the wire records; a 300 that offers alternatives with no preference among them is the status working as defined, and §15.4.1 asks that server for content listing the alternatives rather than for a `Location`.

**`201 Created` is not reported either.** §15.3.2 describes the response without the field rather than discouraging it — with no `Location`, the resource created is the target URI. The one sentence that asks a 201 for the field is §9.3.3's, which is about `POST`; `semantic_post_creates_resource` knows the request method and reports that case.

`304`, the deprecated `305` and `306`, and any unregistered 3xx are not reported: no sentence asks them for the field.

Only presence is read. Whether the value is a usable `URI-reference` belongs to `server_location_header_uri_valid`, and a `Location` on a status that gives it no referent belongs to `server_redirect_status_and_location_validity`.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): Defines `Location = URI-reference` and what the value refers to on a 201 and on a 3xx; it asks no one to send the field
- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): What a provided Location buys: a user agent MAY redirect to it automatically, even where it does not understand the status code
- [RFC 9110 §15.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.1): 300 Multiple Choices: the SHOULD applies only if the server has a preferred choice, so this rule does not report a 300
- [RFC 9110 §15.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2): 301 Moved Permanently: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI
- [RFC 9110 §15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3): 302 Found: the server SHOULD generate a Location header field containing a URI reference for the different URI
- [RFC 9110 §15.4.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4): 303 See Other: the status is defined as a redirection to the resource indicated by a URI in the Location header field
- [RFC 9110 §15.4.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8): 307 Temporary Redirect: the server SHOULD generate a Location header field containing a URI reference for the different URI
- [RFC 9110 §15.4.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.9): 308 Permanent Redirect: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI
- [RFC 9110 §15.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2): 201 Created: with no Location field, the resource created is identified by the target URI — which is why this rule does not report a 201

## Configuration

```toml
[rules.server_response_location_on_redirect]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good 301: the preferred URI reference for the new permanent URI

```http
HTTP/1.1 301 Moved Permanently
Location: https://example.org/new
```

### ✅ Good 303: the resource the user agent is being redirected to

```http
HTTP/1.1 303 See Other
Location: /orders/9001
```

### ✅ Good 300 with no preferred choice: §15.4.1's SHOULD does not apply, and the alternatives go in the content

```http
HTTP/1.1 300 Multiple Choices
Content-Type: text/html
```

### ✅ Good 201 with no Location: the resource created is the target URI. A POST that created one is `semantic_post_creates_resource`'s question

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

### ❌ Bad 302 with nothing to be found at

```http
HTTP/1.1 302 Found
Content-Type: text/html
```

### ❌ Bad 308: a permanent redirect that does not say where to

```http
HTTP/1.1 308 Permanent Redirect
Content-Type: text/html
```
