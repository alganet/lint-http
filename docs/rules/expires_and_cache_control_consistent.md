<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Expires And Cache Control Consistent

## Description

If a response includes both an `Expires` header and a `Cache-Control` freshness directive
(such as `max-age`/`s-maxage`) they SHOULD not contradict each other. When both are
present, `Cache-Control` directives take precedence; clearly contradictory values
(e.g., `Cache-Control: no-cache` while `Expires` is in the future) likely indicate
misconfiguration and should be corrected.

The comparison is made against the instant the sender wrote, not the one a recipient
can read: a value refused only for its spelling — a zone token of `UTC`, a weekday that
is not the day its own date falls on — still names its instant, and naming the same
instant `Date` plus `max-age` names is agreement however it is spelled. That such a
value is unreadable is reported separately.

An `Expires` that names no instant at all counts as contradictory rather than as no
information: a cache is required to read it as already expired, so the common
`Expires: 0` paired with an unspent `max-age` is flagged.

The lifetime a directive advertises is compared after the age the response arrived
with is taken off it. A response served out of a cache has spent part of its
`max-age` already, and an origin behind such a cache commonly writes `Expires` as
the instant the lifetime actually runs out — `Date` plus `max-age` minus `Age` —
which is agreement, not contradiction. A `max-age` the `Age` has consumed entirely
is a response stale on arrival, exactly as `max-age=0` is, and is read that way in
both directions.

## Violations

- [expires_conflicting](../violations/expires_conflicting.md) — Expires and the Cache-Control freshness directives disagree

## Specifications

- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3): `Expires` — a recipient MUST ignore it when `max-age` is present and a shared cache when `s-maxage` is, an invalid date ("0" above all) MUST be read as already expired, and the field is only intended for recipients that have not implemented Cache-Control
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2): Freshness and age calculations using `max-age`, `s-maxage`, and `Expires`

## Configuration

```toml
[rules.expires_and_cache_control_consistent]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: max-age=3600
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: max-age=0
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: no-cache
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```

### ✅ Good Served from a cache: 3600 seconds of lifetime with 2805 spent, and an Expires 795 seconds out. Both populations stop at 07:41:15

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Age: 2805
Cache-Control: max-age=3600
Expires: Wed, 21 Oct 2015 07:41:15 GMT

<...>
```

### ❌ Bad An Age that has consumed the whole max-age is a response stale on arrival, so an Expires an hour out is freshness no cache has

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Age: 900
Cache-Control: max-age=600
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```
