// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Helper utilities shared across multiple lint rules.
//!
//! This module groups reusable helpers for validating HTTP common structures.
//!
//! **Every module below is named for a question, and none for a document.**
//! Read the list: each name is something a value can *be*, never the
//! specification that defines it — which is why one module holds productions
//! from several documents, and why two productions printed on the same page can
//! live apart. That is the shelving rule, and it is the answer to the periodic
//! suggestion of a module named for a publisher: a `microsyntax.rs` collecting
//! the WHATWG transcriptions would be the first module here named for a table of
//! contents.
//!
//! Counted by *what transcribes a production into code* — not by what cites a
//! WHATWG document, which `link_header_valid` also does, for three
//! algorithm steps that license a gate and transcribe nothing — the tree holds
//! **six** such transcriptions, in two rules, from four documents: the URL
//! Standard's *URL code points* and *URL units*, Infra's *ASCII whitespace*,
//! HTML's *valid non-negative integer* and its two-form authoring requirement
//! for `Refresh`, and HTML's *valid floating-point number* in
//! `server_timing_header_syntax`. Two character-class sets, a whitespace
//! set, two number productions and a prose shape; not one is a subroutine of
//! another, and each has exactly one caller. **The rule for arriving here is
//! unchanged and is what decides it: a shared answer moves on the second caller,
//! and that caller has to be asking the same question, not merely reading the
//! same publisher.**
//!
//! **And the second caller can be a caller of one *ingredient* rather than of
//! the function.** `first_non_pchar` in `well_known_uri_syntax` had one
//! caller and stayed there, while the two sets it is composed of —
//! `uri::is_unreserved` and `uri::is_sub_delim` — had five readers and four,
//! written out character for character each time. A grammar that builds its component rules
//! by naming one set and adding to it will produce that shape every time, so the
//! count that decides the move is the count of the *smallest thing two sites
//! share*, not of the function one of them happens to have wrapped it in.

pub mod accept_ranges;
pub mod auth;
pub mod cache_control;
pub mod comment;
pub mod content_range;
pub mod cookie;
pub mod domain;
pub mod forwarded_node;
pub mod headers;
pub mod ipv6;
pub mod language;
pub mod mailbox;
pub mod product;
pub mod rule_config;
pub mod status;
pub mod structured_fields;
pub mod token;
pub mod uri;
pub mod websocket;
