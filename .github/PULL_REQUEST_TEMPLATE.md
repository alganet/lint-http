## What this changes, and why

<!-- A sentence or two. If it changes what a finding says or when it fires,
     quote the specification sentence it rests on. -->

## Checklist

- [ ] `just check` passes (formatting, citations, clippy, rustdoc, tests, quotes).
- [ ] `just check-all` passes when the change touches dependencies, MSRV-sensitive code, or the proxy's transport.
- [ ] Generated files were regenerated where rule or defect metadata changed (`just gendocs`, `just genconfig`), not edited by hand.
- [ ] Every new or moved `// cite(…)` quote was copied from the document, not recalled.
- [ ] New files carry the SPDX header.
- [ ] Tests cover the case that fires and the case that stays quiet.
- [ ] Each commit builds green on its own.
