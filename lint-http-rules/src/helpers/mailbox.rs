// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! RFC 5322's `mailbox` — one address, not a list of them.
//!
//! RFC 9110 § 10.1.2 gives `From` a value of `mailbox` and imports the
//! production by reference, so the grammar this module walks belongs to a
//! different document than the field that uses it. That matters twice over.
//!
//! It is `mailbox` and not `mailbox-list`. RFC 5322 § 3.4 writes both, one under
//! the other, and only the first is imported: a comma at the top level of a
//! `From` value is the separator of a production this field does not have.
//!
//! And the whitespace rules are RFC 5322's. `CFWS` — folding whitespace and
//! parenthesised comments — may sit around nearly every token here, which is why
//! this is a parser rather than a scan for delimiters. HTTP's own `comment`
//! (RFC 9110 § 5.6.5, transcribed at [`crate::helpers::comment`]) looks like the
//! same production and is not: it admits `obs-text` and RFC 5322's `ctext` stops
//! at %x7E, so reusing the HTTP scanner would accept `(caf\xE9)` in a field
//! whose grammar is written in US-ASCII. The tell is the same one that kept
//! `keepalive-param` out of `parse_token_bws_word` — check the terminals before
//! reusing a lookalike.
//!
//! `FWS` prints a `CRLF` and none is reachable here: an HTTP field value is
//! `*field-content` over `field-vchar = VCHAR / obs-text`, so the folding half of
//! the production cannot appear and `FWS` reduces to `1*WSP`.
//!
//! Only § 3's grammar is accepted. Every `obs-` alternative is refused, and the
//! sentence licensing that is § 4's, which forbids *generating* them while
//! requiring a receiver to parse them — this crate reports on senders.
//!
// cite(RFC 9110 § 10.1.2): "mailbox = <mailbox, see [RFC5322], Section 3.4>"
// cite(RFC 5322 § 3.4): "mailbox = name-addr / addr-spec"
// cite(RFC 5322 § 3.4): "mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list"
// cite(RFC 5322 § 3.2.2): "FWS = ([*WSP CRLF] 1*WSP) / obs-FWS"
// cite(RFC 5322 § 4): "Though these syntactic forms MUST NOT be generated according to the grammar in section 3, they MUST be accepted and parsed by a conformant receiver."

use crate::helpers::shown::describe_char;

/// What a `From` value turned out to be, for the checks that only apply to one
/// of the alternatives.
pub struct Mailbox {
    /// The `domain` half of the `addr-spec`, when the sender wrote it as a
    /// `dot-atom` rather than a `domain-literal`.
    ///
    /// Returned rather than judged here, because the two forms are answerable by
    /// different documents: a `dot-atom` domain is *"interpreted as an Internet
    /// domain name"* and so has a host-name syntax behind it as well as this
    /// one, and a bracketed literal has an address inside it instead.
    ///
    // cite(RFC 5322 § 3.4.1): "In the dot-atom form, this is interpreted as an Internet domain name (either a host name or a mail exchanger name) as described in [RFC1034], [RFC1035], and [RFC1123]."
    pub domain_name: Option<String>,
}

/// Why a value is not a `mailbox`.
pub enum MailboxDefect {
    /// A comma outside every `quoted-string`, `comment` and `angle-addr`.
    ///
    /// **Found by the reader below and not by a splitter, and that is why there
    /// is no shared bracket-aware splitter in `helpers::headers`.** The one
    /// other bracketed member list in the tree — `Link`'s
    /// `link-value = "<" URI-Reference ">" …` — has a flat, private one, and the
    /// two cannot be the same function: `comment` names itself, so what a comma
    /// can hide inside here is balanced and recursive. A flat scanner would
    /// report `Alice (a, b) <alice@example.com>`, which is one conforming
    /// mailbox.
    ///
    /// Kept apart from every other syntax defect because it is the one whose
    /// answer is a *neighbouring production*: the value derives from
    /// `mailbox-list`, which is defined two lines below `mailbox` in the same
    /// section and is not what this field imports. A caller that flattened it
    /// into "malformed" would be telling an operator to fix a comma, when what
    /// happened is that a list was written where one address goes.
    ListSeparator,
    /// Any other departure from § 3's grammar, named by the production that
    /// refused the value.
    Syntax(MailboxSyntaxDefect),
}

/// Where § 3's grammar stopped, and in which production.
///
/// Typed rather than rendered, for the reason the whole catalogue is being
/// split: a caller that receives a sentence can only report one thing about a
/// value, and these are seventeen things — a `ctext` refusing an octet nobody
/// typed, an atom with a doubled dot, a comment nobody closed. The sentence
/// each of them is answered by is a different line of RFC 5322, and an operator
/// tuning one is not tuning the others.
///
/// The wording of every one is [`MailboxSyntaxDefect::message`]'s, so a caller
/// embedding it says what this reader found and not what it guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxSyntaxDefect {
    /// An octet inside a `comment` that `ctext` does not admit.
    CommentCharacter(char),
    /// A `comment` opened and never closed.
    CommentUnterminated,
    /// An octet inside a `quoted-string` that `qtext` does not admit.
    QuotedStringCharacter(char),
    /// A `quoted-string` opened and never closed.
    QuotedStringUnterminated,
    /// An octet inside a `domain-literal` that `dtext` does not admit.
    DomainLiteralCharacter(char),
    /// A `domain-literal` opened and never closed.
    DomainLiteralUnterminated,
    /// A backslash with nothing after it to quote, in the named construct.
    QuotedPairAtEnd {
        /// The construct holding the backslash — `comment` or `quoted-string`.
        inside: &'static str,
    },
    /// A backslash quoting an octet that is neither `VCHAR` nor `WSP`.
    QuotedPairCharacter {
        /// The construct holding the pair — `comment` or `quoted-string`.
        inside: &'static str,
        /// What it tried to quote.
        character: char,
    },
    /// An octet in a `dot-atom` that `atext` does not admit.
    AtomCharacter {
        /// Which `dot-atom` — `local-part` or `domain`.
        what: &'static str,
        /// The octet.
        character: char,
    },
    /// A `.` in a `dot-atom` with no `atext` after it: a trailing or a doubled
    /// one, either way an atom the `1*atext` floor has nothing to fill.
    AtomEmpty {
        /// Which `dot-atom` — `local-part` or `domain`.
        what: &'static str,
    },
    /// The value ends where the `addr-spec` has its `local-part`.
    LocalPartMissing,
    /// The `addr-spec`'s `"@"` is not where the production puts it.
    AtSignMissing(Option<char>),
    /// The value ends where the `addr-spec` has its `domain`.
    DomainMissing,
    /// The `angle-addr`'s `"<"` is not where the `name-addr` puts it — which
    /// is what an `obs-phrase`'s bare `.` in a display-name comes to.
    AngleAddrMissing(Option<char>),
    /// The `angle-addr`'s closing `">"` is not where the production puts it.
    AngleAddrUnterminated(Option<char>),
    /// A display-name was opened and holds no `word`.
    DisplayNameWordMissing(Option<char>),
    /// A complete `mailbox` with something after it.
    TrailingCharacter(char),
}

impl MailboxSyntaxDefect {
    /// The finding fragment. Every caller embeds this after naming the field
    /// the value came out of.
    pub fn message(self) -> String {
        match self {
            Self::CommentCharacter(c) => format!(
                "a comment holds {}, which no ctext admits",
                describe_char(c)
            ),
            Self::CommentUnterminated => "a comment is opened and never closed".to_string(),
            Self::QuotedStringCharacter(c) => format!(
                "a quoted-string holds {}, which no qtext admits",
                describe_char(c)
            ),
            Self::QuotedStringUnterminated => {
                "a quoted-string is opened and never closed".to_string()
            }
            Self::DomainLiteralCharacter(c) => format!(
                "a domain-literal holds {}, which no dtext admits",
                describe_char(c)
            ),
            Self::DomainLiteralUnterminated => {
                "a domain-literal is opened and never closed".to_string()
            }
            Self::QuotedPairAtEnd { inside } => {
                format!("a {inside} ends on a backslash with nothing after it to quote")
            }
            Self::QuotedPairCharacter { inside, character } => format!(
                "a {inside} quotes {}, where quoted-pair admits only VCHAR and WSP",
                describe_char(character)
            ),
            Self::AtomCharacter { what, character } => format!(
                "the {what} holds {}, which no atext admits",
                describe_char(character)
            ),
            Self::AtomEmpty { what } => {
                format!("the {what} has a \".\" with no atext after it")
            }
            Self::LocalPartMissing => {
                "the value ends where the addr-spec has a local-part".to_string()
            }
            Self::AtSignMissing(at) => {
                format!("{} where the addr-spec has its \"@\"", stopped_at(at))
            }
            Self::DomainMissing => "the value ends where the addr-spec has a domain".to_string(),
            Self::AngleAddrMissing(at) => format!(
                "{} where the mailbox has the \"<\" of its angle-addr",
                stopped_at(at)
            ),
            Self::AngleAddrUnterminated(at) => {
                format!("{} where the angle-addr has its \">\"", stopped_at(at))
            }
            Self::DisplayNameWordMissing(at) => {
                format!("{} where the display-name has a word", stopped_at(at))
            }
            Self::TrailingCharacter(c) => {
                format!("{} follows a complete mailbox", describe_char(c))
            }
        }
    }
}

/// What a construct stopped at, as the subject of a finding's sentence.
///
/// One rendering for both endings — a character the grammar has no room for,
/// and the value running out — so the four defects that carry a position state
/// what they wanted once each instead of twice.
fn stopped_at(at: Option<char>) -> String {
    match at {
        Some(c) => describe_char(c),
        None => "the value ends".to_string(),
    }
}

/// Parse one `mailbox`.
///
/// The input is a field value read one `char` per octet — the octets a sender
/// wrote, not a decoded string — so every character class below is an octet
/// range and an octet outside it is named as one.
pub fn parse_mailbox(value: &str) -> Result<Mailbox, MailboxDefect> {
    let chars: Vec<char> = value.chars().collect();

    // `name-addr` is the alternative that carries an `angle-addr`, and `<` is a
    // `special`: it appears in no `atext`, so nothing in an `addr-spec` or a
    // display-name's atoms can produce one. It *can* appear inside a
    // `quoted-string` (`qtext` runs %d35-91) and inside a `comment` (`ctext` runs
    // %d42-91), which is why choosing the alternative means stepping over both
    // rather than searching the value for the character.
    //
    // cite(RFC 5322 § 3.4): "name-addr = [display-name] angle-addr"
    // cite(RFC 5322 § 3.4): "angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr"
    // cite(RFC 5322 § 3.2.3): "specials = "(" / ")" / ; Special characters that do "<" / ">" / ; not appear in atext "[" / "]" / ":" / ";" / "@" / "\" / "," / "." / DQUOTE"
    let is_name_addr = Reader { c: &chars, i: 0 }.has_top_level_angle();

    let mut r = Reader { c: &chars, i: 0 };
    let parsed = if is_name_addr {
        r.name_addr()
    } else {
        r.addr_spec().map(|domain_name| Mailbox { domain_name })
    };
    let parsed = parsed.map_err(MailboxDefect::Syntax)?;

    match r.peek() {
        None => Ok(parsed),
        Some(',') => Err(MailboxDefect::ListSeparator),
        Some(c) => Err(MailboxDefect::Syntax(
            MailboxSyntaxDefect::TrailingCharacter(c),
        )),
    }
}

/// cite(RFC 5322 § 3.2.3): "atext = ALPHA / DIGIT / ; Printable US-ASCII "!" / "#" / ; characters not including "$" / "%" / ; specials. Used for atoms. "&" / "'" / "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~""
fn is_atext(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
        )
}

/// cite(RFC 5322 § 3.2.4): "qtext = %d33 / ; Printable US-ASCII %d35-91 / ; characters not including %d93-126 / ; "\" or the quote character obs-qtext"
fn is_qtext(c: char) -> bool {
    let b = c as u32;
    b == 33 || (35..=91).contains(&b) || (93..=126).contains(&b)
}

/// cite(RFC 5322 § 3.2.2): "ctext = %d33-39 / ; Printable US-ASCII %d42-91 / ; characters not including %d93-126 / ; "(", ")", or "\" obs-ctext"
fn is_ctext(c: char) -> bool {
    let b = c as u32;
    (33..=39).contains(&b) || (42..=91).contains(&b) || (93..=126).contains(&b)
}

/// cite(RFC 5322 § 3.4.1): "dtext = %d33-90 / ; Printable US-ASCII %d94-126 / ; characters not including obs-dtext ; "[", "]", or "\""
fn is_dtext(c: char) -> bool {
    let b = c as u32;
    (33..=90).contains(&b) || (94..=126).contains(&b)
}

/// The octet a backslash may quote.
///
/// cite(RFC 5322 § 3.2.1): "quoted-pair = ("\" (VCHAR / WSP)) / obs-qp"
fn is_quotable(c: char) -> bool {
    let b = c as u32;
    (0x21..=0x7e).contains(&b) || c == ' ' || c == '\t'
}

/// `WSP` — `FWS` as an HTTP field value can spell it, the `CRLF` half being
/// unreachable.
///
/// The one terminal set in this file that is honestly the same two octets as an
/// HTTP one: `WSP` is a core rule both documents include by reference, so this
/// admits exactly what [`crate::helpers::headers::trim_ows`] trims. It is still
/// written here rather than borrowed, because the four classes above it look
/// just as alike and are not — and a reader checking one has to be able to
/// check them all in the same place.
///
/// cite(RFC 5234 § B.1): "WSP            =  SP / HTAB ; white space"
fn is_wsp(c: char) -> bool {
    c == ' ' || c == '\t'
}

struct Reader<'a> {
    c: &'a [char],
    i: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let next = self.peek();
        if next.is_some() {
            self.i += 1;
        }
        next
    }

    /// Whether a `<` appears where `angle-addr` would put one.
    ///
    /// Walks with the same three methods the real parse uses rather than a
    /// second scanner of its own: `quoted-pair`, comment nesting and the
    /// bracketed run are each written once, so a correction to one of them
    /// cannot reach the parse and miss the dispatch. The bracketed arm is the
    /// one that is easy to leave out and is not optional — `dtext` runs %d33-90,
    /// so a `domain-literal` may hold a `<`, and `alice@[a<b]` is a whole
    /// `addr-spec` that a scan without it reads as a display-name followed by an
    /// angle-addr.
    ///
    /// Every error is discarded: an unterminated construct answers "no
    /// angle-addr", which sends the value down the `addr-spec` path where the
    /// same defect is reported against the production it belongs to. Choosing an
    /// alternative is not the place to report anything.
    fn has_top_level_angle(&mut self) -> bool {
        while let Some(c) = self.peek() {
            let stepped = match c {
                '<' => return true,
                '"' => self.quoted_string().is_ok(),
                '(' => self.comment().is_ok(),
                '[' => self.domain_literal().is_ok(),
                _ => {
                    self.i += 1;
                    true
                }
            };
            if !stepped {
                return false;
            }
        }
        false
    }

    /// Consume `[CFWS]`.
    ///
    /// cite(RFC 5322 § 3.2.2): "CFWS = (1*([FWS] comment) [FWS]) / FWS"
    fn skip_cfws(&mut self) -> Result<(), MailboxSyntaxDefect> {
        loop {
            while matches!(self.peek(), Some(c) if is_wsp(c)) {
                self.i += 1;
            }
            if self.peek() != Some('(') {
                return Ok(());
            }
            self.comment()?;
        }
    }

    /// cite(RFC 5322 § 3.2.2): "comment = "(" *([FWS] ccontent) [FWS] ")""
    /// cite(RFC 5322 § 3.2.2): "ccontent = ctext / quoted-pair / comment"
    fn comment(&mut self) -> Result<(), MailboxSyntaxDefect> {
        self.i += 1;
        // `comment` names itself, so the count is the production and not a
        // convenience: `(a (b) c)` ends at the last parenthesis and a single
        // "seen an open paren" flag would end it at the first.
        let mut depth = 1usize;
        while let Some(ch) = self.bump() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                '\\' => {
                    self.quoted_pair("comment")?;
                }
                c if is_ctext(c) || is_wsp(c) => {}
                c => return Err(MailboxSyntaxDefect::CommentCharacter(c)),
            }
        }
        Err(MailboxSyntaxDefect::CommentUnterminated)
    }

    /// The octet after a backslash, in whichever construct is quoting it.
    fn quoted_pair(&mut self, inside: &'static str) -> Result<char, MailboxSyntaxDefect> {
        match self.bump() {
            None => Err(MailboxSyntaxDefect::QuotedPairAtEnd { inside }),
            Some(c) if is_quotable(c) => Ok(c),
            Some(c) => Err(MailboxSyntaxDefect::QuotedPairCharacter {
                inside,
                character: c,
            }),
        }
    }

    /// cite(RFC 5322 § 3.2.4): "quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]"
    /// cite(RFC 5322 § 3.2.4): "qcontent = qtext / quoted-pair"
    fn quoted_string(&mut self) -> Result<(), MailboxSyntaxDefect> {
        self.i += 1;
        while let Some(ch) = self.bump() {
            match ch {
                '"' => return Ok(()),
                '\\' => {
                    self.quoted_pair("quoted-string")?;
                }
                c if is_qtext(c) || is_wsp(c) => {}
                c => return Err(MailboxSyntaxDefect::QuotedStringCharacter(c)),
            }
        }
        Err(MailboxSyntaxDefect::QuotedStringUnterminated)
    }

    /// cite(RFC 5322 § 3.2.3): "dot-atom = [CFWS] dot-atom-text [CFWS]"
    /// cite(RFC 5322 § 3.2.3): "dot-atom-text = 1*atext *("." 1*atext)"
    /// Returns the characters consumed. Borrowed rather than collected: only
    /// the `domain` caller keeps the text, and the local-part — which every
    /// well-formed `From` has — would otherwise pay for a string it drops on
    /// the next statement.
    fn dot_atom_text(&mut self, what: &'static str) -> Result<&'a [char], MailboxSyntaxDefect> {
        let start = self.i;
        let mut after_dot = false;
        loop {
            let run = self.i;
            while matches!(self.peek(), Some(c) if is_atext(c)) {
                self.i += 1;
            }
            // Both `1*atext` floors, read as one branch: the one before the first
            // dot and the one after every later dot. A character-class scan would
            // pass an empty run at either, which is how a leading, trailing or
            // doubled `.` derives from nothing and reads as clean.
            if self.i == run {
                return Err(match self.peek() {
                    Some(c) if !after_dot => {
                        MailboxSyntaxDefect::AtomCharacter { what, character: c }
                    }
                    // The value running out on the *first* pass is unreachable:
                    // both callers test for the end before entering the
                    // production. So a `None` here has always just followed the
                    // `.` this loop consumed, and reads as that arm does.
                    _ => MailboxSyntaxDefect::AtomEmpty { what },
                });
            }
            if self.peek() == Some('.') {
                self.i += 1;
                after_dot = true;
                continue;
            }
            return Ok(&self.c[start..self.i]);
        }
    }

    /// cite(RFC 5322 § 3.4.1): "domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]"
    fn domain_literal(&mut self) -> Result<(), MailboxSyntaxDefect> {
        self.i += 1;
        while let Some(ch) = self.bump() {
            match ch {
                ']' => return Ok(()),
                c if is_dtext(c) || is_wsp(c) => {}
                c => return Err(MailboxSyntaxDefect::DomainLiteralCharacter(c)),
            }
        }
        Err(MailboxSyntaxDefect::DomainLiteralUnterminated)
    }

    /// cite(RFC 5322 § 3.4.1): "addr-spec = local-part "@" domain"
    /// cite(RFC 5322 § 3.4.1): "local-part = dot-atom / quoted-string / obs-local-part"
    /// cite(RFC 5322 § 3.4.1): "domain = dot-atom / domain-literal / obs-domain"
    fn addr_spec(&mut self) -> Result<Option<String>, MailboxSyntaxDefect> {
        self.skip_cfws()?;
        // The alternation is decided by one character, and the sentence beside
        // the grammar says which: a quoted-string can only open on a DQUOTE, and
        // no `atext` is one.
        //
        // cite(RFC 5322 § 3.4.1): "The locally interpreted string is either a quoted-string or a dot-atom."
        match self.peek() {
            Some('"') => self.quoted_string()?,
            Some(_) => {
                self.dot_atom_text("local-part")?;
            }
            None => return Err(MailboxSyntaxDefect::LocalPartMissing),
        }

        self.skip_cfws()?;
        // cite(RFC 5322 § 3.4.1): "An addr-spec is a specific Internet identifier that contains a locally interpreted string followed by the at-sign character ("@", ASCII value 64) followed by an Internet domain."
        if self.peek() != Some('@') {
            return Err(MailboxSyntaxDefect::AtSignMissing(self.peek()));
        }
        self.i += 1;

        self.skip_cfws()?;
        let domain_name = match self.peek() {
            Some('[') => {
                self.domain_literal()?;
                None
            }
            Some(_) => Some(self.dot_atom_text("domain")?.iter().collect()),
            None => return Err(MailboxSyntaxDefect::DomainMissing),
        };
        self.skip_cfws()?;
        Ok(domain_name)
    }

    fn name_addr(&mut self) -> Result<Mailbox, MailboxSyntaxDefect> {
        self.skip_cfws()?;
        // The display-name is optional, so `<user@example.com>` is a whole
        // `name-addr` and the branch below is not entered for it.
        if self.peek() != Some('<') {
            self.display_name()?;
        }
        // The value cannot run out here — `has_top_level_angle` found a `<`
        // outside every quoted-string, comment and domain-literal, and nothing
        // above consumes one — but the ending is rendered rather than asserted,
        // because a parser that panics on its own invariant is worse than one
        // that reports a sentence nobody reads.
        if self.peek() != Some('<') {
            return Err(MailboxSyntaxDefect::AngleAddrMissing(self.peek()));
        }
        self.i += 1;

        let domain_name = self.addr_spec()?;

        if self.peek() != Some('>') {
            return Err(MailboxSyntaxDefect::AngleAddrUnterminated(self.peek()));
        }
        self.i += 1;
        self.skip_cfws()?;
        Ok(Mailbox { domain_name })
    }

    /// cite(RFC 5322 § 3.4): "display-name = phrase"
    /// cite(RFC 5322 § 3.2.5): "phrase = 1*word / obs-phrase"
    /// cite(RFC 5322 § 3.2.5): "word = atom / quoted-string"
    /// cite(RFC 5322 § 3.2.3): "atom = [CFWS] 1*atext [CFWS]"
    fn display_name(&mut self) -> Result<(), MailboxSyntaxDefect> {
        let mut saw_a_word = false;
        loop {
            self.skip_cfws()?;
            match self.peek() {
                Some('"') => {
                    self.quoted_string()?;
                    saw_a_word = true;
                }
                Some(c) if is_atext(c) => {
                    while matches!(self.peek(), Some(c) if is_atext(c)) {
                        self.i += 1;
                    }
                    saw_a_word = true;
                }
                _ => break,
            }
        }
        if !saw_a_word {
            return Err(MailboxSyntaxDefect::DisplayNameWordMissing(self.peek()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn ok(v: &str) -> Mailbox {
        match parse_mailbox(v) {
            Ok(m) => m,
            Err(MailboxDefect::ListSeparator) => panic!("{v:?} read as a mailbox-list"),
            Err(MailboxDefect::Syntax(e)) => panic!("{v:?} rejected: {}", e.message()),
        }
    }

    fn err(v: &str) -> String {
        match parse_mailbox(v) {
            Ok(_) => panic!("{v:?} accepted"),
            Err(MailboxDefect::ListSeparator) => "list separator".to_string(),
            Err(MailboxDefect::Syntax(e)) => e.message(),
        }
    }

    #[rstest]
    #[case("alice@example.com")]
    #[case("Alice <alice@example.com>")]
    #[case("<alice@example.com>")]
    #[case("\"Doe, John\" <john@example.com>")]
    #[case("\"a\\\"b\"@example.com")]
    #[case("alice@[192.0.2.1]")]
    #[case("alice+tag@example.com")]
    #[case("first.last@sub.example.com")]
    fn section_3_mailboxes_are_accepted(#[case] value: &str) {
        ok(value);
    }

    /// `dtext` admits `<`, so the pass that decides which of `mailbox`'s two
    /// alternatives this is has to step over a `domain-literal` as well as over
    /// the quoted and commented text. Without it this whole `addr-spec` reads as
    /// a display-name with an angle-addr after it.
    #[test]
    fn an_angle_bracket_inside_a_domain_literal_is_data() {
        assert_eq!(ok("alice@[a<b]").domain_name, None);
    }

    /// The comma is the whole premise of this module, so it is asserted as the
    /// distinct answer rather than as "some error".
    #[test]
    fn a_top_level_comma_is_a_mailbox_list_and_says_so() {
        assert_eq!(err("alice@example.com, bob@example.org"), "list separator");
        assert_eq!(
            err("Alice <alice@example.com>, bob@example.org"),
            "list separator"
        );
    }

    /// A comma inside a `quoted-string` is data, and inside a `comment` too.
    /// Both are `mailbox`es, and a splitter that counted commas would cut each in
    /// half.
    #[test]
    fn a_quoted_or_commented_comma_is_not_a_separator() {
        ok("\"Doe, John\" <john@example.com>");
        ok("john@example.com (Doe, John)");
    }

    /// `CFWS` is why this is a parser. Every one of these is a conforming
    /// `mailbox` that a delimiter scan reports.
    #[rstest]
    #[case("alice@example.com (Alice)")]
    #[case("(who) alice@example.com")]
    #[case("Alice (the robot) <alice@example.com>")]
    #[case("alice (a (nested) comment) @ example.com")]
    fn comments_and_folding_whitespace_are_part_of_the_grammar(#[case] value: &str) {
        ok(value);
    }

    #[rstest]
    #[case("", "ends where the addr-spec has a local-part")]
    #[case("not-an-email", "ends where the addr-spec has its \"@\"")]
    #[case("@example.com", "local-part holds '@'")]
    #[case("alice@", "ends where the addr-spec has a domain")]
    #[case(".alice@example.com", "local-part holds '.'")]
    #[case(
        "alice.@example.com",
        "the local-part has a \".\" with no atext after it"
    )]
    #[case(
        "al..ice@example.com",
        "the local-part has a \".\" with no atext after it"
    )]
    #[case("alice@example.com.", "the domain has a \".\" with no atext after it")]
    #[case("Alice <alice@example.com", "ends where the angle-addr has its \">\"")]
    #[case("alice@example.com>", "'>' follows a complete mailbox")]
    #[case("a@b.com (unclosed", "a comment is opened and never closed")]
    #[case("\"unclosed@example.com", "a quoted-string is opened and never closed")]
    #[case("alice@[192.0.2.1", "a domain-literal is opened and never closed")]
    #[case(
        "John Q. Public <jqp@example.com>",
        "'.' where the mailbox has the \"<\""
    )]
    #[case("Team: a@example.com;", "':' where the addr-spec has its \"@\"")]
    #[case("alice@exa mple.com", "'m' follows a complete mailbox")]
    // The four productions whose refusal nothing above reaches: `dtext`,
    // either half of a `quoted-pair`, and a display-name opened on something
    // that is no `word`. Each names a defect of its own, so each is worded
    // once and asserted here rather than trusted to the parse it shares.
    #[case("alice@[a\u{e9}b]", "a domain-literal holds 0xE9")]
    #[case(
        "a@example.com (x\\",
        "a comment ends on a backslash with nothing after it to quote"
    )]
    #[case(
        "\"a\\\u{e9}b\"@example.com",
        "a quoted-string quotes 0xE9, where quoted-pair admits only VCHAR and WSP"
    )]
    #[case(". <alice@example.com>", "'.' where the display-name has a word")]
    fn section_4_and_worse_is_refused(#[case] value: &str, #[case] expected: &str) {
        let e = err(value);
        assert!(e.contains(expected), "{value:?} was rejected as {e:?}");
    }

    /// An octet a US-ASCII grammar has no room for is named as an octet, not
    /// folded into "not valid UTF-8" — and the two places it is *not* a defect
    /// are the two the document writes as octet ranges stopping at %x7E.
    /// The pass that picks `mailbox`'s alternative walks with the same three
    /// parsers the real one does, and discards their errors. So a value whose
    /// quoted-string is defective *before* an otherwise well-formed angle-addr
    /// is read as an `addr-spec` — and the finding still names the defect, at
    /// the production that holds it.
    #[test]
    fn a_defective_construct_before_the_angle_bracket_still_names_itself() {
        assert!(err("\"alic\u{e9}\" <a@example.com>").contains("no qtext admits"));
        assert!(err("(caf\u{e9}) <a@example.com>").contains("no ctext admits"));
    }

    #[test]
    fn obs_text_is_named_at_the_production_that_excludes_it() {
        assert!(err("alic\u{e9}@example.com").contains("0xE9"));
        assert!(err("\"alic\u{e9}\"@example.com").contains("0xE9"));
        assert!(err("a@example.com (caf\u{e9})").contains("0xE9"));
    }

    /// The `domain` alternative the caller has to tell apart, because only one
    /// of the two has a host-name syntax behind it.
    #[test]
    fn only_a_dot_atom_domain_comes_back() {
        assert_eq!(
            ok("a@example.com").domain_name.as_deref(),
            Some("example.com")
        );
        assert_eq!(ok("a@[192.0.2.1]").domain_name, None);
        assert_eq!(
            ok("Alice <a@ex.example> (x)").domain_name.as_deref(),
            Some("ex.example")
        );
    }

    /// HTAB is `WSP`, so it is `FWS` and admitted wherever the grammar prints
    /// one — a check that refuses every non-visible octet reports a conforming
    /// value.
    #[test]
    fn htab_is_folding_whitespace() {
        ok("Alice\t<alice@example.com>");
    }
}
