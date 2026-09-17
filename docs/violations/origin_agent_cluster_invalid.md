<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_agent_cluster_invalid

Origin-Agent-Cluster states a value that is not `?1`

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster

## Configuration

```toml
[violations.origin_agent_cluster_invalid]
# Origin-Agent-Cluster states a value that is not `?1`
severity = "warn"
```

## Reported By

- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
