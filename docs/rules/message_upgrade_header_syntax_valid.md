<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Upgrade Header Syntax Valid

## Description

Parses the `Upgrade` header field of a request and of a response — every field line of one section joined into the single list they are — against RFC 9110 §7.8's grammar: `Upgrade = #protocol`, where `protocol = protocol-name ["/" protocol-version]` and both halves are `token`.

So a member is one token, or two tokens with a single `/` between them: `websocket`, `h2c`, `HTTP/1.1`, `IRC/6.9`. `Upgrade: web socket` names no protocol, because the production writes no whitespace inside a member and only a comma separates members; `Upgrade: /1.1` begins with the slash of a version and names none either, since the *name* is the half that is not optional; `Upgrade: HTTP/` ends on its slash, and a `protocol-version` is at least one character; `Upgrade: HTTP/1.1/2` has a version holding a `/`, which no token admits.

**Empty member and empty value are different things.** `Upgrade: websocket,,h2c` is a list a sender MUST NOT generate (§5.6.1.1) and is reported, after any member that is present, as the list's defect rather than the element's — there is no such thing as an empty `protocol`. `Upgrade:` is not reported at all: the field is `#protocol` and not `1#protocol`, so a list of no protocols is a list this production generates. That such a field still owes an `upgrade` connection option is `message_connection_upgrade`'s finding, not this rule's.

**The grammar is the whole requirement, and §7.8 states it with no keyword of its own.** The section's thirteen BCP 14 keywords are about who may send the field, what must accompany it, what a server does with one it receives, and which protocol it may switch to — none of them says a value must derive from the production. What does is §5.5: *HTTP field values consist of a sequence of characters in a format defined by the field's grammar.* The one modal this rule carries is §5.6.1.1's MUST NOT, for the empty member.

**No name is compared against a registry, and that is a decision rather than an omission.** RFC 9110 §16.7 creates the *Hypertext Transfer Protocol (HTTP) Upgrade Token Registry* for exactly these tokens, and §7.8 says additional protocol names *ought to be registered* — advice, not a requirement, in a registry whose policy is First Come First Served. A protocol registered tomorrow is conforming today, so an allowlist would report senders for the registry's latency and a config key would ask an operator to maintain one. Case is left alone for the same kind of reason: the preferred case is a property of the *registration*, and §7.8 asks recipients to compare case-insensitively.

**Four of the section's requirements are declined, each because a capture cannot answer it.** That the protocols are listed *in order of descending preference* is what a sender means by the order, and nothing in the message says what it preferred. That a `101` switching several layers lists them *in layer-ascending order* needs the layer each protocol sits at, which no field carries. That a server *MUST NOT switch protocols unless the received message semantics can be honored* is a fact about the new protocol, not about these octets. And the MUST to answer an `Upgrade` carrying a `100-continue` expectation with a `100 (Continue)` *before* the `101` is about a message the capture has no slot for: a transaction holds one response and it is the final one, so an interim `100` recorded there would be the answer the exchange ended on rather than the interim it was.

**Every version is measured, and the neighbours are why.** Over HTTP/2 and HTTP/3 the field's *presence* is already a finding — `message_no_connection_specific_fields` reports it with each version's own sentence, and reads no value, because whether a value derives from its field's own production is that field's rule's question. This is that rule; declining the value there and here would leave it asked by nobody. `message_connection_header_tokens_valid` reads `Connection` the same way for the same reason. What each transport does to a connection-specific field before it reaches a capture — which decides whether these findings are live on proxied traffic or only on captures written elsewhere — is published there as well, and it differs by version.

**What the neighbours own.** Whether an `Upgrade` field is named by an `upgrade` connection option is `message_connection_upgrade`'s. Whether a `101` response carries the field at all, and whether the protocol it names was one the client offered, is `stateful_101_switching_protocols`'s — it reads the members of both values through the *recipient's* list reader and compares them, which is a different question from whether the sender generated them; a `101` exchange whose `Upgrade` is `, ,` draws a finding from both rules, each naming its own sentence. That a `426 (Upgrade Required)` response must carry the field is §7.8's and §15.5.22's, and is reported by nothing in this catalogue.

Scope: this rule reads header sections — a request's and a response's — and each finding names which. Where the field appears on several lines in one section they are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped: `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a protocol, which is what is wrong with it. The members are split on commas without regard to quoting, because a `protocol` admits no `quoted-string` anywhere inside it — a DQUOTE here is a character no member may hold. Whether `Upgrade` may appear in a *trailer* section is §6.5.1's question and `message_trailer_fields_validity`'s, which holds the table `Upgrade` is listed in.

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the field's own section, where `protocol`, `protocol-name` and `protocol-version` are printed, both directions are licensed to carry the field, and the registry is named as advice
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Field Values — that a value is in the format its field's grammar defines, which is what makes a malformed member a finding at all, and that the value's own ends carry no whitespace
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The sender's half of the list construct: the empty member is its MUST NOT, and the `#element` expansion is why an empty value is not
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token` and `tchar`: what both halves of a protocol are made of, and the delimiters they exclude
- [RFC 9110 §16.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.7): The Upgrade Token Registry — First Come First Served, which is why no protocol name is compared against a list here
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Upgrade` lines in one field section are one field value, so the members are counted after the lines are joined

## Configuration

```toml
[rules.message_upgrade_header_syntax_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The section's own hypothetical request

```http
GET /hello HTTP/1.1
Host: www.example.com
Connection: upgrade
Upgrade: websocket, IRC/6.9, RTA/x11
```

### ✅ Good A list of no protocols is a list; the field is `#protocol`

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade:
```

### ❌ Bad An empty member — the list construct's sender requirement

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade: websocket,,h2c
```

### ❌ Bad The name is the half that is not optional

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade: /1.1
```

### ❌ Bad A protocol-version is at least one character

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade: HTTP/
```

### ❌ Bad No whitespace appears inside a member, and only a comma separates two

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade: web socket
```
