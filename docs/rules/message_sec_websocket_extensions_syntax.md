<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Sec Websocket Extensions Syntax

## Description

Parses `Sec-WebSocket-Extensions` — a request's and a response's — against the grammar RFC 6455 §9.1 prints: `extension-list = 1#extension`, `extension = extension-token *( ";" extension-param )`, `extension-token = registered-token = token`, and `extension-param = token [ "=" (token | quoted-string) ]`. §9.1 is also what makes a malformed value a finding rather than a note: *If a value is received by either the client or the server during negotiation that does not conform to the ABNF below, the recipient of such malformed data MUST immediately _Fail the WebSocket Connection_.*

**The notation is RFC 2616's, and that changes two answers.** §9.1 says so in as many words — *this section is using ABNF syntax/rules from [RFC2616], including the "implied *LWS rule"* — and the current specification naming the obsolete one is what makes citing it right rather than stale.

- **Null list elements are allowed.** RFC 2616 §2.1: *Wherever this construct is used, null elements are allowed, but do not contribute to the count of elements present.* So `foo,,bar` is two extensions and conforms — where RFC 9110 §5.6.1.1 makes an empty member a sender's MUST NOT for every other list-based field in this catalogue. What `1#` does require is that *at least one non-null element MUST be present*, so a value that is nothing but commas and whitespace is the finding instead. Reading this field from RFC 9110's list rules would report a conforming value and pass a malformed one, in that order.
- **Whitespace may sit beside the delimiters.** Implied `*LWS` puts it *between any two adjacent words … and between adjacent words and separators*, so `permessage-deflate ; client_max_window_bits = 15` conforms. RFC 9110 §5.6.6's Note forbids exactly that around a parameter's `=`, which is why this rule writes its own parameter walk instead of calling the shared one — the same reasoning as `Keep-Alive`, the other field in this tree whose parameters come out of a 1997 document, reached in the opposite direction.

**What a member is measured for.** Its `extension-token` is a token of at least one character; each `;` is followed by a parameter whose name is a token; a parameter's value is optional, and when present is a token or a quoted-string. A quoted-string value carries the production's own trailing requirement — *When using the quoted-string syntax variant, the value after quoted-string unescaping MUST conform to the 'token' ABNF* — so `x="a b"` is reported for the space it unescapes to, and `x=""` for unescaping to nothing.

**Not reported: whether the extension-token is registered.** §9.1 says *Any extension-token used MUST be a registered token (see Section 11.4)*, and §11.4's policy is First Come First Served — a name registered tomorrow conforms today, so an allowlist would report senders for the registry's latency and a config key would ask an operator to maintain one. Nor is *The parameters supplied with any given extension MUST be defined for that extension* enforced: which parameters `permessage-deflate` defines is RFC 7692's question, and answering it here would mean this rule reading that document for this one.

**Not reported: whether the response's extensions were offered.** That comparison is `websocket_handshake_valid`'s, which needs both halves of one exchange; this rule measures each field section on its own. The value also decides `websocket_frame_rsv_bits`'s verdicts, since a `101` accepting an extension is what licenses a non-zero reserved bit — which is a reason to measure this field, not a claim that the frame rule reads it twice.

Scope: this rule reads header sections — a request's and a response's — and each finding names which. Where the field appears on several lines in one section they are one value (§5.2), which §9.1 states for this field by name and demonstrates with a worked example. A value carrying an octet outside US-ASCII is measured rather than skipped: it reaches the production that excludes it and is reported there. The member split is quote-aware, because a `quoted-string` parameter value may hold a comma; a value whose quoting never closes is reported as that, before any member is judged, since every separator after an unclosed quote is data.

## Specifications

- [RFC 6455 §9.1](https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1): Negotiating Extensions — the grammar, the MUST that makes a non-conforming value a failure of the connection, the note that the notation is RFC 2616's, and the requirement on a quoted-string value after unescaping
- [RFC 2616 §2.1](https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1): Augmented BNF — the notation §9.1 imports by name: the `#rule` whose null elements are allowed (RFC 9110 §5.6.1.1 forbids them) and the implied *LWS rule that permits whitespace beside the separators. Obsolete and correct: the current document is what sends the reader here
- [RFC 6455 §11.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.4): WebSocket Extension Name Registry — First Come First Served, which is why no extension-token is compared against a list here

## Configuration

```toml
[rules.message_sec_websocket_extensions_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good §9.1's own worked example, on the two lines it prints it as

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: foo
Sec-WebSocket-Extensions: bar; baz=2
```

### ✅ Good Implied *LWS: whitespace beside the separators changes nothing

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: permessage-deflate ; client_max_window_bits = 15
```

### ✅ Good A null element — RFC 2616's list construct allows it

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: foo,,bar
```

### ❌ Bad `1#extension` needs one element that is not null

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: ,
```

### ❌ Bad `/` is a separator, so the extension-token is not a token

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: foo/bar
```

### ❌ Bad The value after unescaping must conform to the token ABNF

```http
GET /chat HTTP/1.1
Host: example.com
Sec-WebSocket-Extensions: foo; bar="a b"
```
