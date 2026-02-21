<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_request_version_method_validity

## Description

Clients SHOULD use request methods whose semantics align with the message
content they are sending.  Some methods either forbid or have no defined
semantics for a request body; sending content with those methods can lead to
interoperability problems or security risks (e.g. request smuggling).  This
rule flags any request that claims a non-zero body when the method's
semantics do not allow it.

The most obvious examples are GET and HEAD (which have no defined request
payload semantics) but the same guidance applies to DELETE, TRACE, and
CONNECT.  By enforcing this rule, users are encouraged to choose methods like
POST, PUT, PATCH, or OPTIONS when content is required.

## Specifications

- RFC 9110 §9.3.1 (GET) – ‘‘A client **SHOULD NOT** generate content in a GET
  request ...’’
- RFC 9110 §9.3.2 (HEAD) – ‘‘A client **SHOULD NOT** generate content in a HEAD
  request ...’’
- RFC 9110 §9.3.5 (DELETE) – ‘‘content received in a DELETE request has no
  generally defined semantics ... A client **SHOULD NOT** generate content in a
  DELETE request ...’’
- RFC 9110 §9.3.6 (CONNECT) – ‘‘A CONNECT request message **does not have
  content**.’'
- RFC 9110 §9.3.8 (TRACE) – ‘‘A client **MUST NOT** send content in a TRACE
  request.’'

## Configuration

```toml
[rules.client_request_version_method_validity]
enabled = true
severity = "error"
```

## Examples

✅ Good
```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 123

<binary data>
```

✅ Good (DELETE with no body)
```http
DELETE /resource/42 HTTP/1.1
Host: example.com
```

❌ Bad (GET with a body)
```http
GET /search HTTP/1.1
Host: example.com
Content-Length: 5

hello
```

❌ Bad (TRACE with content)
```http
TRACE / HTTP/1.1
Host: example.com
Content-Length: 1

x
```
