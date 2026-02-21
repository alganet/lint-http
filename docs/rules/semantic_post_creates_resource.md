<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# POST responses should use 201/Location for creations

## Description

When a `POST` request results in the origin server creating one or more new
resources, the server **should** respond with `201 Created` and include a
`Location` header field identifying the primary resource that was created.
Sending a `Location` header on any other 2xx response implies a resource was
created, yet the proper status code was not used. Likewise, a `201` response
without a `Location` header fails to provide the identifier of the newly
created resource.

This rule flags both situations so that implementers are encouraged to align
their responses with the semantics defined in RFC 9110 §9.3.3 and §10.2.2.

## Specifications

* [RFC 9110 §9.3.3 — POST](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3)
  describes the semantics for `POST` responses and notes that
  "If one or more resources has been created on the origin server as a result
  of successfully processing a POST request, the origin server **SHOULD** send a
  201 (Created) response containing a Location header field that provides an
  identifier for the primary resource created."
* [RFC 9110 §10.2.2 — Location](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2)
  specifies that for `201 (Created)` responses the `Location` value refers to
  the primary resource created by the request.

## Configuration

```toml
[rules.semantic_post_creates_resource]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 20

{"name":"fidget"}

HTTP/1.1 201 Created
Location: /widgets/123
Content-Type: application/json

{"id":123}
```

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 20

{"name":"fidget"}

HTTP/1.1 200 OK

{"status":"ok"}
```

### ❌ Bad

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 20

{"name":"fidget"}

HTTP/1.1 201 Created
Content-Type: application/json

{"id":123}
```

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 20

{"name":"fidget"}

HTTP/1.1 200 OK
Location: /widgets/123
Content-Type: application/json

{"status":"ok"}
```