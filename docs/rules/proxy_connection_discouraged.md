<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Proxy Connection Discouraged

## Description

Reports a request carrying a `Proxy-Connection` header field.

**This is advice, and the finding says so.** RFC 9112 Appendix C.2.2 is the only place in either core document that describes the field, and it contains **no BCP 14 keyword at all** — its modals are *might wish*, *are encouraged*, *ought to* and *ought not*. So no sentence makes sending `Proxy-Connection` a violation, and this rule's message is worded as the recommendation it is. What the section does supply is the reason: the field *was an attempted solution … targeted specifically at proxies*, introduced because some HTTP/1.0 proxies forwarded `Connection` they did not understand and hung the connection — and it *was also unworkable, because proxies are often deployed in multiple layers, bringing about the same problem discussed above*. A field invented to fix one layer of proxy reproduces the fault as soon as there are two.

**The field is connection-specific, and RFC 9110 §7.6.1 is where that is settled.** Its list of fields intermediaries are asked to remove before forwarding names `Proxy-Connection` and points at Appendix C.2.2 for the definition — so the current specification names the older text rather than replacing it, which is what makes citing an appendix titled *Changes from Previous RFCs* the right thing rather than a stale pointer.

**The two versions with a prohibition of their own are left to the rule that carries it.** Over HTTP/2 and HTTP/3 the field is not discouraged but forbidden outright, and any message carrying it is malformed — `no_connection_specific_fields` reports that with each version's own sentence, which is the stronger of the two readings. Reporting it here as well would be two findings for one field. The gate asks *is this one of those two*, not *is this HTTP/1.x*, so a request whose version derives from no production is still measured: the field is on the wire either way, and the advice does not turn on which digit the sender wrote.

**Two things this rule does not report, each because the sentence does not reach them.**

- **A response carrying `Proxy-Connection`.** The sentence this rule rests on takes a *client* as its subject and names the direction itself — *in any requests* — and nothing in the section asks anything of a responder. (Not every sentence there is about a client: two describe what HTTP/1.0 connections and HTTP/1.0 proxy servers do, and one names *clients and servers* together; those are the section's narrative rather than its advice.) §7.6.1's removal sentence is a SHOULD addressed to *intermediaries*, and it is about forwarding rather than about generating — a captured response holding the field could have been written by the origin or forwarded by a hop that did not strip it, and no field in the capture records which. So the direction is left alone rather than guessed at.
- **Whether the value is a well-formed connection-option list.** `Proxy-Connection` was written to be read the way `Connection` is, but no document gives it a grammar; there is nothing to measure a value against. It is printed in the finding rather than parsed, because what an operator diagnosing a hung connection wants to know is which persistence the client was reaching for.

Scope: this rule reads a request's header section. Where the field appears on several lines they are read as one value (§5.2), and a value carrying an octet outside US-ASCII is measured rather than skipped — reading it back through a UTF-8 decoder would turn a field the sender wrote into a request that has none. **Whether `Proxy-Connection` may appear in a *trailer* section is §6.5.1's question, and `message_trailer_fields_validity` answers it on the merits**: its table names the field among its connection-specific entries, so a `Proxy-Connection` trailer is reported there whatever this message's own `Connection` or `Trailer` fields say. (The field's absence from that table was recorded here when this rule was written, and repaired in its own iteration — RULECITES P46.)

## Specifications

- [RFC 9112 §C.2.2](https://www.rfc-editor.org/rfc/rfc9112.html#appendix-C.2.2): Keep-Alive Connections — the only description of the field in either core document, and it states no requirement: the section carries no BCP 14 keyword
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): Connection — lists the field among those intermediaries are asked to remove before forwarding, and names Appendix C.2.2 as its definition

## Configuration

```toml
[rules.proxy_connection_discouraged]
enabled = true
severity = "info"
# RFC 9112 Appendix C.2.2 carries no BCP 14 keyword at all, so the finding is
# advice and the severity says so. The comment sits *below* the severity line
# because `config_block_for` reads from a rule's header to the next `[`: a
# comment written above a header is documented against the rule before it.
```

## Examples

### ✅ Good The option the field was trying to imitate, written where it belongs

```http
GET / HTTP/1.1
Host: example.com
Connection: keep-alive
```

### ❌ Bad

```http
GET / HTTP/1.1
Host: example.com
Proxy-Connection: keep-alive
```

### ❌ Bad Beside the field it was meant to stand in for

```http
GET / HTTP/1.1
Host: example.com
Connection: keep-alive
Proxy-Connection: keep-alive
```
