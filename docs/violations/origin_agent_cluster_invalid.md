<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_agent_cluster_invalid

Origin-Agent-Cluster states the boolean's false value

## Message

Origin-Agent-Cluster is `?0`, the false value of the boolean it carries: well-formed, and requesting what an absent header already gives, since only `?1` asks for an origin-keyed agent cluster

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster

## Configuration

```toml
[violations.origin_agent_cluster_invalid]
# Origin-Agent-Cluster states the boolean's false value
severity = "info"
```

## Reported By

- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
