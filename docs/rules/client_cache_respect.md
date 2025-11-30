# Client Cache Respect

## Description
This rule checks if the client correctly uses conditional headers (`If-None-Match` or `If-Modified-Since`) when re-requesting a resource it has previously fetched.

If a server provides validators (like `ETag` or `Last-Modified`) in a response, a well-behaved client should use them in subsequent requests for the same resource to allow the server to return a `304 Not Modified` response, saving bandwidth and processing time.

## Specifications
- [RFC 7232, Section 3.2: If-None-Match](https://tools.ietf.org/html/rfc7232#section-3.2)
- [RFC 7232, Section 3.3: If-Modified-Since](https://tools.ietf.org/html/rfc7232#section-3.3)

## Examples

### ✅ Good Request Flow
**First Request:**
```http
GET /image.png HTTP/1.1
Host: example.com
```
**Response:**
```http
HTTP/1.1 200 OK
ETag: "abcdef12345"
Content-Length: 1024
```

**Second Request (Correct):**
```http
GET /image.png HTTP/1.1
Host: example.com
If-None-Match: "abcdef12345"
```

### ❌ Bad Request Flow
**First Request:**
```http
GET /image.png HTTP/1.1
Host: example.com
```
**Response:**
```http
HTTP/1.1 200 OK
ETag: "abcdef12345"
```

**Second Request (Incorrect):**
```http
GET /image.png HTTP/1.1
Host: example.com
# Missing If-None-Match header!
```
