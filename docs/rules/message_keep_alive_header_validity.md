<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Keep Alive Header Validity

## Description

Parses the `Keep-Alive` field of a request and of a response — every field line of one section joined into the single list they are — against the grammar that defines it: `Keep-Alive-header = "Keep-Alive" ":" 0# keepalive-param`, where `keepalive-param = param-name "=" value` and `value = token | quoted-string`. It also reports the field's one requirement on a sender: a `Keep-Alive` written without the matching `keep-alive` connection option in `Connection`.

**The document is RFC 2068, and the current specification is what says so.** RFC 9110 §7.6.1 lists the fields an intermediary should remove before forwarding and names each one's source; against `Keep-Alive` it writes *Section 19.7.1 of [RFC2068]*. RFC 2616 removed the grammar rather than restating it and pointed back the same way, and the IANA HTTP Field Name Registry registers the field `permanent` with RFC 2068 as its only reference. So this is not a field nothing specifies — it is a field whose specification is an obsoleted document that the current one still names, and both are named here.

Reading it from that document rather than from RFC 9110 changes three answers.

- **Whitespace around the `=` is conforming.** RFC 2068 §2.1's `implied *LWS` rule lets linear whitespace sit between any token and any delimiter, so `timeout = 30` is the same parameter as `timeout=30`. A field whose grammar RFC 9110 writes would need `BWS` printed in the production for that, and a sender writing it there would be the finding.
- **An empty member is not a finding.** RFC 2068 §2.1's `#rule` says null elements are allowed, where RFC 9110 §5.6.1.1 makes one a sender's MUST NOT. `Keep-Alive: timeout=30,,max=100` is reported by nothing here.
- **An empty field value is not a finding either.** The list is `0#`, with no minimum, so `Keep-Alive:` declares no parameter rather than declaring one badly.

**`timeout` is named by no document that is in force.** RFC 2068 writes the field's grammar and then says *"HTTP/1.1 does not define any parameters."* The only document that ever gave `timeout` a value grammar and a meaning is draft-thomson-hybi-http-timeout-03, an individual Internet-Draft that expired in January 2013, and its `"timeout" "=" delta-seconds` is quoted here as the only published reading of a value servers send anyway — not as a requirement. What that costs is worth being explicit about: a `timeout` whose value is a well-formed `token` or `quoted-string` satisfies RFC 2068's `keepalive-param` no matter what it holds, so `timeout="60"` and `timeout=+30` are reported against the draft's grammar alone. The draft would also have made the `=` optional (`keep-alive-extension = token [ "=" ( token / quoted-string ) ]`); RFC 2068 writes it into the production, and the document in force is what decides, so `Keep-Alive: max` is reported and the finding says which reading it comes from.

**`max_timeout_seconds` is this deployment's policy and not a requirement.** No document states any maximum for the parameter. The bound is required rather than defaulted so that the number in a finding is one an operator chose, and the finding names the config key rather than advising a smaller value. A configuration this rule cannot read stops the whole rule, grammar checks included.

**What this rule does not decide.**

- **What a `param-name` may hold.** `keepalive-param = param-name "=" value` is the only place RFC 2068 writes the name `param-name`, and the document defines it nowhere. There is no production to measure a name against, so no name is reported for its spelling — only for being absent, or for having no `=` and no value after it.
- **Whether `max` should have been sent.** The expired draft deprecates it. Deprecation there is a sentence in a document that is not in force, and RFC 2068 forbids no parameter name at all.
- **`timeout=0`.** `delta-seconds` is `1*DIGIT` and generates it, and a host announcing that it will close an idle connection immediately has said something true about itself. No sentence makes it a defect.
- **The field over HTTP/2 and HTTP/3.** Both versions forbid connection-specific fields outright, which is a different finding from a malformed value and belongs to the rules that own the version. `message_no_connection_specific_fields` reports both halves, each against the version that carried the field section it is in. The connection-option requirement here is gated to HTTP/1.x for the same reason — demanding `Connection: keep-alive` of an HTTP/2 message would be advice to violate RFC 9113 §8.2.2.
- **Whether the timeout was honoured.** The draft's own sentence about it is a MAY paired with a SHOULD about a host's future behaviour, which no capture records.

## Specifications

- [RFC 2068 §19.7.1.1](https://www.rfc-editor.org/rfc/rfc2068.html#section-19.7.1.1): The `Keep-Alive` grammar, the sentence saying HTTP/1.1 defines no parameters for it, and the field's one requirement on a sender — the matching connection token. Obsoleted, and still the document RFC 9110 §7.6.1 names for this field, so this is where the productions are read from. The reference here used to be RFC 7230 §6.7, which is `Upgrade`
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): The current specification's own pointer: `Keep-Alive` appears in the list of fields an intermediary should remove before forwarding, annotated *Section 19.7.1 of [RFC2068]*. It is also what makes the field connection-specific, and therefore hop-by-hop
- [RFC 2068 §2.1](https://www.rfc-editor.org/rfc/rfc2068.html#section-2.1): The two notation rules that make this field's list read differently from a field RFC 9110 defines: `#rule` permits null elements, and `implied *LWS` permits whitespace between a token and a delimiter — which is what makes `timeout = 30` conforming rather than a `BWS` defect
- [RFC 2068 §2.2](https://www.rfc-editor.org/rfc/rfc2068.html#section-2.2): `token`, `tspecials`, `LWS` and `quoted-string`. This document's `token` admits exactly the characters RFC 9110 §5.6.2's `tchar` does — the seventeen `tspecials` are RFC 9110's delimiters and both alphabets stop at US-ASCII — so the shared helper is the same production under another name
- [RFC 2068 §3.7](https://www.rfc-editor.org/rfc/rfc2068.html#section-3.7): `value = token | quoted-string`, the right-hand half of `keepalive-param`. The rule name is defined once for the document and `keepalive-param` uses it, which is why a parameter value may be quoted at all
- [RFC 2068 §4.2](https://www.rfc-editor.org/rfc/rfc2068.html#section-4.2): This document's statement of the rule that makes repeated field lines one list — the same requirement RFC 9110 §5.2 states, which is what the shared line-joining helper cites
- [draft-thomson-hybi-http-timeout-03 §2](https://www.ietf.org/archive/id/draft-thomson-hybi-http-timeout-03.txt): The only document that ever gave `timeout` a grammar or a meaning. An individual Internet-Draft, never adopted, expired 2013-01-18 — quoted as the only published reading of the parameter and never as a requirement. Its §2.2.1 deprecates `max`; its §7.2 asks IANA for a registry that was never created, which is why this rule carries no list of parameter names
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT`, the production the draft's `timeout` value is. `1*DIGIT` is what a leading `+` fails, and a standard-library integer parser accepts
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT behind every grammar finding here: a value that derives from none of the productions is a protocol element matching no ABNF rule
- [RFC 2616 §19.6.2](https://www.rfc-editor.org/rfc/rfc2616.html#section-19.6.2): Where the grammar stopped being restated: RFC 2616 kept the compatibility discussion and sent the reader back to RFC 2068 for the field itself. The same shape as RFC 9111 §5.5 and `Warning`
- [IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-fields/http-fields.xhtml): `Keep-Alive` is registered `permanent`, with RFC 2068 as its only reference — not `obsoleted`, unlike `Warning`. Corroboration for reading an obsoleted document, not an authority this rule enforces

## Configuration

```toml
[rules.message_keep_alive_header_validity]
enabled = true
severity = "warn"
# No document states a maximum for the `timeout` parameter, so this bound is
# this deployment's policy rather than a requirement. It is required and has no
# default for that reason; a value the rule cannot read stops the whole rule.
max_timeout_seconds = 3600
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=30, max=100
```

### ✅ Good (whitespace around the "=" is implied *LWS)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout = 30
```

### ✅ Good (an empty member, which RFC 2068's #rule permits)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=30,,max=100
```

### ✅ Good (timeout=0 is a delta-seconds and says something true)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=0
```

### ✅ Good (an extension parameter whose quoted value holds a comma)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=30, note="a, b"
```

### ❌ Bad (no connection option naming the field)

```http
HTTP/1.1 200 OK
Keep-Alive: timeout=30
```

### ❌ Bad (a parameter with no "=" and no value)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=30, max
```

### ❌ Bad (a leading + is not a DIGIT)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=+30
```

### ❌ Bad (a quoted timeout is a keepalive-param and not a delta-seconds)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout="60"
```

### ❌ Bad (above the configured max_timeout_seconds)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=999999
```

### ❌ Bad (a value that is neither a token nor a quoted-string)

```http
HTTP/1.1 200 OK
Connection: keep-alive
Keep-Alive: timeout=30, note=a b
```
