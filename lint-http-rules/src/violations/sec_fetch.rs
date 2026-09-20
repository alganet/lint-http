// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Fetch Metadata defects — what the five `Sec-Fetch-*` request headers may
//! carry.
//!
//! **One family, five fields, two documents**, and the shape is the same in
//! every one: a Structured Field whose value is a token (or, for
//! `Sec-Fetch-User`, a boolean), drawn from a closed set the field's own
//! section names. So the syntax half is shared across the family and the value
//! half is each field's, which is exactly how the ids divide.
//!
//! **The document is not what bounds the family; the header prefix is.** Four
//! of the five are Fetch Metadata's own § 2.1 — § 2.4. The fifth,
//! `Sec-Fetch-Storage-Access`, is defined by Storage Access Headers § 4.1 and
//! joins the family from there — § 5 of that document appends it "alongside
//! other Fetch Metadata headers", and the IANA registry gives it the same
//! Structured Type its siblings carry. Counting the family by its defining
//! document is what left it unread: the four sections were walked, and a fifth
//! field sending the same shape on real traffic was not in the block being
//! walked.
//!
//! **The token is RFC 9651's `sf-token` and not HTTP's `token`**, which is why
//! these values do not borrow [`token`](crate::violations::token)'s ids. The
//! two productions differ, this crate reads the wrong one on purpose — the
//! shared predicate is what it has, and it refuses everything the right one
//! would — and an id naming § 5.6.2 would cite a production the field does not
//! use. *The refusal is of the id; the octet was always a reader question.*
//!
//! **The two shared entries name no sentence, and the reason is structural
//! rather than a gap.** Each field states its own type in its own section —
//! Fetch Metadata § 2.1, § 2.2, § 2.3, § 2.4 and Storage Access Headers § 4.1 —
//! so a single entry declared by all five rules could only cite a sentence
//! *every* declarer states, and no rule here states another field's section.
//! The fifth declarer strengthens this rather than complicating it: the
//! sections are now in two different documents, so there is not even a shared
//! document to fall back on. That is the fourth reason an entry carries no
//! reference: the slice answers a def whose sections are all stated by one
//! rule, and cannot answer one whose sections are stated one per rule.
//!
//! **Nothing here reports an unknown value as a protocol error on the
//! recipient's side.** Every section tells a server to ignore a value it does
//! not know, for forward compatibility — Storage Access Headers § 4.1 writes
//! the sentence in the same words its four siblings do; these entries lint the
//! *sender*, where an unrecognised value means the header came from something
//! that is not implementing the document.

use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::defects;

/// `Sec-Fetch-Dest`: the type, and the destination set it defers to Fetch for.
pub const FETCH_METADATA_2_1: SpecRef = SpecRef {
    spec: "Fetch Metadata",
    section: Some("2.1"),
    url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-dest-header",
    note: "Fetch Metadata (W3C) — `Sec-Fetch-Dest`: an sf-token whose valid values are Fetch's request destinations",
};

/// `Sec-Fetch-Mode`: the type, and the five request modes.
pub const FETCH_METADATA_2_2: SpecRef = SpecRef {
    spec: "Fetch Metadata",
    section: Some("2.2"),
    url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-mode-header",
    note: "Fetch Metadata (W3C) — `Sec-Fetch-Mode`: an sf-token whose valid values are the five request modes",
};

/// `Sec-Fetch-Site`: the type, and the four initiator/target relationships.
pub const FETCH_METADATA_2_3: SpecRef = SpecRef {
    spec: "Fetch Metadata",
    section: Some("2.3"),
    url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-site-header",
    note: "Fetch Metadata (W3C) — `Sec-Fetch-Site`: an sf-token whose valid values are the four initiator/target relationships",
};

/// `Sec-Fetch-User`: a boolean, and the note that it is sent only when true.
pub const FETCH_METADATA_2_4: SpecRef = SpecRef {
    spec: "Fetch Metadata",
    section: Some("2.4"),
    url: "https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header",
    note: "Fetch Metadata (W3C) — `Sec-Fetch-User`: a boolean, delivered only for navigation requests and only when its value is true",
};

/// `Sec-Fetch-Storage-Access`: the type, and the three storage access statuses.
///
/// The one reference in this subject that is not Fetch Metadata's, because the
/// fifth member of the family is defined elsewhere and says so.
pub const STORAGE_ACCESS_HEADERS_4_1: SpecRef = SpecRef {
    spec: "Storage Access Headers",
    section: Some("4.1"),
    url: "https://privacycg.github.io/storage-access-headers/#sec-fetch-storage-access-header",
    note: "Storage Access Headers (Privacy CG) — `Sec-Fetch-Storage-Access`: an sf-token whose valid values are the three storage access statuses",
};

defects! {
    /// A `Sec-Fetch-*` field written with nothing on it.
    ///
    /// Shared by all four, because an empty value is neither a token nor a
    /// boolean and the repair is the same wherever it happens: send the value,
    /// or send no field. A recipient is left where the field's absence would
    /// have left it, except that something claimed to be telling it more.
    ///
    /// **Uncited, and the subject's docs carry the reason**: four rules declare
    /// this and each states a different section of one document, so there is no
    /// sentence every declarer names.
    ///
    /// `warn`. The request is answerable and what is lost is one signal about
    /// where it came from.
    SEC_FETCH_VALUE_EMPTY = {
        id: "sec_fetch_value_empty",
        title: "A Sec-Fetch-* field is written with no value on it",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// An octet in a `Sec-Fetch-*` value that no token admits.
    ///
    /// **Not [`token_character_forbidden`](crate::violations::token)**, and the
    /// distinction is the whole reason this subject exists: these fields are
    /// Structured Fields, so the production is RFC 9651's `sf-token` and not
    /// RFC 9110 § 5.6.2's `token`. This crate reads the HTTP one because that
    /// is the reader it has; borrowing the id would put § 5.6.2's sentence
    /// behind a value written under a different grammar.
    ///
    /// Uncited for the family reason above. Shared by the three token-valued
    /// fields; `Sec-Fetch-User` is a boolean and its own entry covers
    /// everything that is not `?1`.
    ///
    /// `warn`, with the rest.
    SEC_FETCH_VALUE_MALFORMED = {
        id: "sec_fetch_value_malformed",
        title: "A Sec-Fetch-* value holds a character no token admits",
        message: "",
        default_severity: Severity::Warn,
        spec: &[],
    }

    /// A `Sec-Fetch-Site` that is none of `cross-site`, `same-origin`,
    /// `same-site` and `none`.
    ///
    /// The four are lowercase tokens and a Structured Field token carries no
    /// case folding, so `Same-Origin` is one of these findings rather than a
    /// spelling of the value beside it.
    ///
    /// `_invalid`: the value derives from the token production and is refused
    /// by the closed set written past it.
    ///
    // cite(Fetch Metadata § 2.3): "Valid Sec-Fetch-Site values include "cross-site", "same-origin", "same-site", and "none"."
    SEC_FETCH_SITE_VALUE_INVALID = {
        id: "sec_fetch_site_value_invalid",
        title: "Sec-Fetch-Site names no relationship the document defines",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_METADATA_2_3],
    }

    /// A `Sec-Fetch-Mode` that is none of `cors`, `navigate`, `no-cors`,
    /// `same-origin` and `websocket`.
    ///
    // cite(Fetch Metadata § 2.2): "Valid Sec-Fetch-Mode values include "cors", "navigate", "no-cors", "same-origin", and "websocket"."
    SEC_FETCH_MODE_VALUE_INVALID = {
        id: "sec_fetch_mode_value_invalid",
        title: "Sec-Fetch-Mode names no request mode the document defines",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_METADATA_2_2],
    }

    /// A `Sec-Fetch-Dest` that is none of Fetch's request destinations.
    ///
    /// **The one entry here whose value set lives in another document**, and it
    /// grows: § 2.1 defers to Fetch's destination list, which gained `"text"`
    /// after this rule's arm was first written. That growth is also why the
    /// section tells servers to ignore an unknown value — and why this entry
    /// reports the *sender* anyway, where an unrecognised destination means the
    /// header came from something that is not implementing Fetch.
    ///
    // cite(Fetch Metadata § 2.1): "Valid Sec-Fetch-Dest values include the set of valid request destinations defined by [Fetch]."
    SEC_FETCH_DEST_VALUE_INVALID = {
        id: "sec_fetch_dest_value_invalid",
        title: "Sec-Fetch-Dest names no request destination Fetch defines",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_METADATA_2_1],
    }

    /// A `Sec-Fetch-User` that is anything other than `?1`.
    ///
    /// **One entry for two shapes, because the field is only ever sent one
    /// way.** `?0` is a perfectly good boolean and `yes` is not a boolean at
    /// all, and neither can appear here: the header is delivered only for
    /// navigation requests and only when its value is true, so its presence
    /// carrying anything else is the same mistake — a sender writing the field
    /// where the document does not write it. The message names the value.
    ///
    /// `_invalid` for that reason rather than `_malformed`: what refuses `?0`
    /// is not the boolean production.
    ///
    // cite(Fetch Metadata § 2.4): "HTTP request header exposes whether or not a navigation request was triggered by user activation."
    SEC_FETCH_USER_VALUE_INVALID = {
        id: "sec_fetch_user_value_invalid",
        title: "Sec-Fetch-User carries something other than the boolean true",
        message: "",
        default_severity: Severity::Warn,
        spec: &[FETCH_METADATA_2_4],
    }

    /// A `Sec-Fetch-Storage-Access` that is none of `none`, `inactive` and
    /// `active`.
    ///
    /// The three are lowercase tokens and a Structured Field token carries no
    /// case folding, so `Active` is one of these findings rather than a
    /// spelling of the value beside it — `Sec-Fetch-Site`'s reading exactly,
    /// one document over.
    ///
    /// **The value is a status the user agent computed, not a preference the
    /// sender chose**, which is what the sentence is worth saying: a recipient
    /// deciding whether to answer with `Activate-Storage-Access` reads this
    /// field to learn whether the request already carries unpartitioned
    /// cookies, and a value outside the three tells it nothing it can act on.
    ///
    /// `_invalid`: the value derives from the token production and is refused
    /// by the closed set written past it.
    ///
    /// `warn`, with the rest of the family.
    ///
    // cite(Storage Access Headers § 4.1): "Valid Sec-Fetch-Storage-Access values include "none", "inactive", and "active"."
    SEC_FETCH_STORAGE_ACCESS_VALUE_INVALID = {
        id: "sec_fetch_storage_access_value_invalid",
        title: "Sec-Fetch-Storage-Access names no storage access status the document defines",
        message: "",
        default_severity: Severity::Warn,
        spec: &[STORAGE_ACCESS_HEADERS_4_1],
    }
}
