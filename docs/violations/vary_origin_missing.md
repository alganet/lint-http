<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# vary_origin_missing

An Access-Control-Allow-Origin chosen from the Origin is not keyed on it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Fetch](https://fetch.spec.whatwg.org/#cors-protocol-and-http-caches): CORS protocol and HTTP caches (informative) — where Access-Control-Allow-Origin depends on the request's Origin, Vary is to be used, or a cached non-CORS response is handed to a later CORS request

## Configuration

```toml
[violations.vary_origin_missing]
# An Access-Control-Allow-Origin chosen from the Origin is not keyed on it
severity = "warn"
```

## Reported By

- [vary_and_cors_consistent](../rules/vary_and_cors_consistent.md)
