<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Security Policy

## What lint-http is

lint-http is a development and testing tool. It decrypts HTTPS by acting as a
certificate authority the client is told to trust, and it parses every byte an
origin or a client sends it. Both are reasons to keep it on loopback and on
machines you trust, which is how it is configured out of the box, and neither
makes it suitable for production traffic.

## In scope

- The CA and its private key: how they are generated, stored, and cleaned up.
- The proxy accepting traffic from an untrusted client or origin: parsers,
  framing, resource bounds, and the `/_lint_http/` endpoints.
- The tool drivers behind `use`: anything that lets a tool's own arguments
  change what lint-http does with the session.
- A finding that is *missing* where a specification sentence was broken is a
  bug, not a vulnerability. Please file it as a bug or a false negative.

## Reporting

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting on this repository (**Security → Report a
vulnerability**), or email alganet@gmail.com. Include the version
(`lint-http --version`), the platform, and a way to reproduce.

You will get an acknowledgement, and a fix and disclosure timeline agreed with
you before anything is published. Fixes ship in the next release; the latest
release is the only supported version.
