---
name: Bug report
about: Something crashed, hung, misbehaved, or reported the wrong thing about a run
title: ''
labels: bug
assignees: ''
---

**What happened**

<!-- What you saw. Paste the report or the error, ideally with `-v` or
     `RUST_LOG=debug` if that adds anything. -->

**What you expected**

**How to reproduce**

```bash
lint-http run -- curl https://example.com   # the exact command line
```

<!-- If it involves a capture file, attach the smallest capture that shows
     it. If it involves a config, attach the `[general]` and `[tls]` sections
     and the rule tables that matter. -->

**Environment**

- `lint-http --version`:
- OS and version:
- The client or tool being proxied, and its version (`curl --version`, browser build, …):
- How lint-http was installed (source checkout, `cargo install`, …):
