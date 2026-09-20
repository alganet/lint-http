<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Connect Response Framing Valid

## Description

Reports a `2xx` response to a `CONNECT` request that carries `Transfer-Encoding` or `Content-Length`.

**RFC 9110 §9.3.6 states it as a MUST NOT on the server**: *"A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT."* What the fields would be framing is the tunnel — a successful CONNECT response ends at its header section and everything after it belongs to the tunnelled connection — so a recipient that honours a `Content-Length` here reads that many octets of another protocol as content, and whatever follows as the start of a new message. The prohibition is on presence and not on a wrong value: there is no length the number could correctly state.

**The next sentence is the repair, not a licence.** §9.3.6 goes on to have a client *ignore* either field received in a successful response to CONNECT, and RFC 9112 §6.3 says the same in its own list of ways a message body length is determined. That is why a length disagreement on this shape is unmeasurable, and why `response_body_length_accuracy` declines on exactly it — a recipient told to ignore something is not a sender permitted to send it, and the sender's sentence is the one this rule reports.

**`2xx` is the whole of the antecedent.** A CONNECT refused with a `4xx` or a `5xx` establishes no tunnel, so its framing is ordinary and the content explaining the refusal needs a length like any other. The sentence says `2xx` and the reading stops there.

**One finding per field.** A response carrying both has two lines to delete, and the message names which field it saw; the entry is one because the sentence is one, where the bodyless statuses' `Content-Length` and `Transfer-Encoding` entries are two because they rest on two sentences in two documents.

**The request half of the same section is a different rule's.** §9.3.6 also says a CONNECT request message does not have content, which `request_version_method_valid` reports as `method_connect_content_forbidden` — that finding is the client's and this one is the server's, which is why they are not one rule.

Scope: this rule reads a response's header section, and it reads it whatever protocol version carried the exchange. §9.3.6 states the requirement once for HTTP as a whole and each version document points back at it; over HTTP/2 and HTTP/3 a `Transfer-Encoding` is additionally forbidden outright by those versions' own sentences, which `no_connection_specific_fields` reports. Presence is the whole test, so no value is parsed here and the field's own syntax stays `content_length_valid`'s and `transfer_encoding_valid`'s.

## Violations

- [method_connect_framing_forbidden](../violations/method_connect_framing_forbidden.md) — A successful response to CONNECT frames a body the tunnel leaves no room for

## Specifications

- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the request message does not have content, and the interpretation of anything after its header section is specific to the version of HTTP in use
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length, item 2 — a successful response to CONNECT is followed by the tunnel, so its body length is not determined by either framing field

## Configuration

```toml
[rules.connect_response_framing_valid]
enabled = true
# Nothing to configure. The sentence names the two fields and the status class,
# and neither is a deployment's choice.
```

## Examples

### ✅ Good A tunnel established, and nothing claiming to frame it

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443

HTTP/1.1 200 Connection Established
```

### ❌ Bad The zero is not an exception: the field is what is forbidden

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443

HTTP/1.1 200 Connection Established
Content-Length: 0
```

### ❌ Bad Both fields are two lines to remove, and draw the entry twice

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443

HTTP/1.1 200 Connection Established
Transfer-Encoding: chunked
Content-Length: 5
```

### ✅ Good A refused CONNECT establishes no tunnel, so its content is framed like any other

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443

HTTP/1.1 403 Forbidden
Content-Length: 9

no tunnel
```
