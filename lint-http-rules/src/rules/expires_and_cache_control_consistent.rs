// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::expires::{EXPIRES_CONFLICTING, RFC_9111_5_3};
use crate::violations::ViolationDef;

/// One entry over four shapes of one disagreement.
///
/// An `Expires` naming no instant at all beside an unspent `max-age`, a future
/// one beside `no-cache` or a lifetime already spent, an already-past one beside
/// an unspent `max-age`, and a date that is neither instant `Date` and an
/// unspent `max-age` can name are all the same message read two ways: caches
/// that implement `Cache-Control` use the directive, caches that do not use the
/// field. Same sender, same repair, same loss — which of the four it was is the
/// message's to say.
///
/// **What "unspent" adds, and what every shape here answered without it: the
/// age the response arrived with.** `Date` plus `max-age` is where the directive
/// population stops calling a response fresh only when that response had spent
/// none of its lifetime yet. RFC 9111 § 4.2.3 floors `current_age` at the stated
/// `Age`, so an origin serving through a cache that stamps its own `Date` states
/// the lifetime that is *left*, and `Date` plus `max-age` minus `Age` is where
/// both populations meet. It is what a CDN in front of an origin ordinarily
/// writes — 3600 seconds of lifetime with 2805 of them already spent, and an
/// `Expires` 795 seconds out — and it was read as a response holding two
/// answers when it holds one. A lifetime the age had consumed entirely was read
/// the same way, as freshness no cache had.
///
/// **What no shape here is, and used to be: a value a recipient cannot read.**
/// The first shape was every `Expires` the parser refused, which put a spelling
/// in charge of the verdict. `Sun, 30 Aug 2026 00:27:20 UTC` beside `Date:
/// 00:17:20 GMT` and `max-age=600` is the same instant twice — spell the zone
/// `GMT` and this rule is silent — and it was reported as a response holding two
/// lifetimes. That the value is unreadable is true, and
/// [`EXPIRES_MALFORMED`](crate::violations::expires::EXPIRES_MALFORMED) is the
/// entry that says so. Whether the two fields *disagree* is a question about
/// what the sender wrote, and it is now asked of what the sender wrote.
static DECLARED: &[&ViolationDef] = &[&EXPIRES_CONFLICTING];
use chrono::{DateTime, Utc};

/// If `Expires` and `Cache-Control` are both present, their values should not contradict.
/// `Cache-Control: max-age` / `s-maxage` override `Expires` (RFC 9111 §5.3); this rule
/// flags clear contradictions (e.g., `max-age=0` with a future Expires, or `max-age>0`
/// while `Expires` is in the past relative to Date).
pub struct ExpiresAndCacheControlConsistent;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2",
    note: "Freshness and age calculations using `max-age`, `s-maxage`, and `Expires`",
};

impl RuleMeta for ExpiresAndCacheControlConsistent {
    fn id(&self) -> &'static str {
        "expires_and_cache_control_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "If a response includes both an `Expires` header and a `Cache-Control` freshness directive\n(such as `max-age`/`s-maxage`) they SHOULD not contradict each other. When both are\npresent, `Cache-Control` directives take precedence; clearly contradictory values\n(e.g., `Cache-Control: no-cache` while `Expires` is in the future) likely indicate\nmisconfiguration and should be corrected.\n\nThe comparison is made against the instant the sender wrote, not the one a recipient\ncan read: a value refused only for its spelling — a zone token of `UTC`, a weekday that\nis not the day its own date falls on — still names its instant, and naming the same\ninstant `Date` plus `max-age` names is agreement however it is spelled. That such a\nvalue is unreadable is reported separately.\n\nAn `Expires` that names no instant at all counts as contradictory rather than as no\ninformation: a cache is required to read it as already expired, so the common\n`Expires: 0` paired with an unspent `max-age` is flagged.\n\nThe lifetime a directive advertises is compared after the age the response arrived\nwith is taken off it. A response served out of a cache has spent part of its\n`max-age` already, and an origin behind such a cache commonly writes `Expires` as\nthe instant the lifetime actually runs out — `Date` plus `max-age` minus `Age` —\nwhich is agreement, not contradiction. A `max-age` the `Age` has consumed entirely\nis a response stale on arrival, exactly as `max-age=0` is, and is read that way in\nboth directions."
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[RFC_9111_5_3, RFC_9111_4_2]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: max-age=3600\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: max-age=0\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nCache-Control: no-cache\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "Served from a cache: 3600 seconds of lifetime with 2805 spent, and an Expires 795 seconds out. Both populations stop at 07:41:15",
                ),
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nAge: 2805\nCache-Control: max-age=3600\nExpires: Wed, 21 Oct 2015 07:41:15 GMT\n\n<...>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "An Age that has consumed the whole max-age is a response stale on arrival, so an Expires an hour out is freshness no cache has",
                ),
                snippet: "HTTP/1.1 200 OK\nDate: Wed, 21 Oct 2015 07:28:00 GMT\nAge: 900\nCache-Control: max-age=600\nExpires: Wed, 21 Oct 2015 08:28:00 GMT\n\n<...>",
            },
        ]
    }
}

impl Rule for ExpiresAndCacheControlConsistent {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            let resp = tx.response.as_ref()?;

            // Expires is an HTTP-date; the recipient parser owns the grammar.
            // cite(RFC 9111 § 5.3): "The Expires field value is an HTTP-date timestamp, as defined in Section 5.6.7 of [HTTP]."
            // An Expires that names no instant is not missing information: §5.3 assigns it a
            // meaning, so it is retained here (as already-expired) rather than returning early.
            // Reporting the *invalidity* itself still belongs to other rules; what this rule
            // does with it is compare the meaning against Cache-Control.
            let expires_raw =
                crate::helpers::headers::get_header_str(&resp.headers, "expires")?.trim();
            // Read twice, because two different questions are asked of the same
            // octets below. What a conforming recipient gets from the field is
            // what decides whether the message has to say the value is
            // unreadable; what the *sender* wrote is what decides whether the
            // two fields disagree, and this rule asks only the second. A zone
            // token spelled `UTC` is refused by every recipient and names its
            // instant to anyone reading it, so `Date` plus `max-age` landing on
            // that same instant is one lifetime written twice — and reporting
            // it as two was a verdict about the spelling.
            let readable_by_recipient: Option<DateTime<Utc>> =
                crate::http_date::header_timestamp(&resp.headers, "expires");
            let expires_meant: Option<DateTime<Utc>> =
                crate::http_date::intended_timestamp(expires_raw);

            // The Cache-Control directives this rule compares against Expires.
            // `max-age` is read directly rather than through
            // `get_cache_control_max_age`, which answers None when no-cache or
            // no-store is present alongside — right for a caller asking what
            // freshness was advertised, wrong for one asking what the two fields
            // *said*, which is the contradiction below.
            let mut cc_present = false;
            let mut cc_no_cache = false;
            let mut cc_no_store = false;
            let mut cc_max_age: Option<i64> = None;
            // The joined value is held here because a directive borrows the
            // member it was parsed from, and it is read as octets so a bad
            // one no longer hides the directives written beside it.
            let lines = crate::helpers::cache_control::field_lines(&resp.headers);
            for directive in crate::helpers::cache_control::directives_in(&lines) {
                cc_present = true;
                if directive.is("no-cache") {
                    cc_no_cache = true;
                } else if directive.is("no-store") {
                    cc_no_store = true;
                } else if directive.is("max-age") {
                    cc_max_age = directive.delta_seconds().or(cc_max_age);
                }
            }
            let cc_s_maxage =
                crate::helpers::cache_control::get_cache_control_s_maxage(&resp.headers);

            if !cc_present {
                return None;
            }

            // How much of the advertised lifetime the response had already
            // spent when it arrived. Every arm below asks whether the directive
            // population still calls this response fresh, and until this was
            // read every arm answered for a response that had spent none of it.
            // §4.2.3 floors `current_age` at the stated `Age`, so a lifetime at
            // or below that number is one no recipient has any of left — which
            // is `max-age=0` written in the other field, and the arms treat it
            // the same way.
            // cite(RFC 9111 § 4.2.3): "corrected_initial_age = max(apparent_age, corrected_age_value)"
            // cite(RFC 9111 § 4.2): "response_is_fresh = (freshness_lifetime > current_age)"
            let age = crate::helpers::cache_control::stated_age(&resp.headers);
            let remaining = |lifetime: Option<i64>| lifetime.is_some_and(|s| s > age);
            // Fresh to *some* cache: `s-maxage` answers only for a shared one,
            // and either being unspent is enough for the two fields to be able
            // to hold two answers.
            let cc_still_fresh = remaining(cc_max_age) || remaining(cc_s_maxage);
            // Not fresh to any of them. `max-age` is the arm's field here as it
            // was when the test was `== Some(0)`: a zero is a lifetime the age
            // has spent before it started, and the generalisation is the same
            // sentence with the age put back in.
            let cc_stale_on_arrival =
                cc_no_cache || cc_no_store || cc_max_age.is_some_and(|s| s <= age);

            // The recipient is required to read an Expires it cannot derive an instant from
            // — `0` above all, the classic anti-caching idiom — as a time already past. So it
            // contradicts a positive max-age/s-maxage exactly the way a stale date does, and the
            // disagreement is sharper than usual: §5.3 says Expires is "only intended for
            // recipients that have not yet implemented the Cache-Control header field", and
            // those are precisely the recipients that will act on the already-expired
            // reading while everyone else honours max-age. Same precedence-not-illegality
            // framing as the dated checks below; needs no reference time, since "already
            // expired" is true against any.
            // cite(RFC 9111 § 5.3): "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past (i.e., "already expired")."
            let Some(expires) = expires_meant else {
                if cc_still_fresh {
                    return Some(ctx.report_with(&EXPIRES_CONFLICTING, format!(
                            "Expires '{}' names no instant, so a cache MUST read it as already expired, but Cache-Control max-age/s-maxage says the response is still fresh — values are contradictory",
                            expires_raw
                        )));
                }
                return None;
            };

            // Where the instant came out of a spelling no recipient reads, the
            // messages below name an instant that nothing downstream will ever
            // act on, and a reader who greps the response for it finds nothing.
            // The octets go with it.
            let as_written = match readable_by_recipient {
                Some(_) => String::new(),
                None => format!(" — written '{expires_raw}', which no recipient parses"),
            };

            // The reference time is the origin's clock where it stated one, and
            // the time we saw the message where it did not.
            let date_ref =
                crate::http_date::header_timestamp(&resp.headers, "date").unwrap_or(tx.timestamp);

            // Expires and the Cache-Control freshness directives can disagree. The spec resolves
            // that by *precedence*, not by calling it an error — so flagging the disagreement is
            // this rule's misconfiguration heuristic, built on two facts: for max-age the
            // recipient MUST ignore Expires (§5.3), and the freshness calculation consults max-age
            // before Expires, stopping at the first match (§4.2.1). no-cache/no-store do not
            // "ignore Expires" — their contradiction with a future Expires is a pure heuristic
            // (recorded in the tracker).
            // cite(RFC 9111 § 5.3): "If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field."
            // cite(RFC 9111 § 4.2.1): "If the max-age response directive (Section 5.2.2.1) is present, use its value, or If the Expires response header field (Section 5.3) is present, use its value minus the value of the Date response header field"
            if cc_stale_on_arrival && expires > date_ref {
                let directives = if cc_no_cache {
                    "no-cache".to_string()
                } else if cc_no_store {
                    "no-store".to_string()
                } else if age > 0 {
                    format!("max-age={} beside Age: {age}", cc_max_age.unwrap_or(0))
                } else {
                    "max-age=0".to_string()
                };
                return Some(ctx.report_with(&EXPIRES_CONFLICTING, format!(
                        "Response contains Cache-Control directives {:?} that make it non-fresh, but Expires indicates freshness until {} — Cache-Control takes precedence (RFC 9111 §4.2.1){}",
                        directives, expires, as_written
                    )));
            }

            // Same misconfiguration heuristic, the other way round: a positive max-age (or, for a
            // shared cache, s-maxage) says "fresh" while Expires is already stale. Per §5.3/§4.2.1
            // the directive wins and Expires is ignored, so this is a consistency flag, not a spec
            // violation — the two values simply disagree.
            // cite(RFC 9111 § 5.3): "If a response includes a Cache-Control header field with the max-age directive (Section 5.2.2.1), a recipient MUST ignore the Expires header field."
            if cc_still_fresh && expires <= date_ref {
                return Some(ctx.report_with(&EXPIRES_CONFLICTING, format!(
                        "Response contains Cache-Control max-age/s-maxage but Expires {} is not in the future relative to Date {} — values are contradictory (RFC 9111 §4.2, §5.3){}",
                        expires, date_ref, as_written
                    )));
            }

            // Best-effort consistency: when Date is present, warn if Expires and Date+max-age
            // diverge by more than a second. No requirement makes Expires equal Date+max-age —
            // they are alternatives and max-age wins (§4.2.1/§5.3) — so this is a heuristic with a
            // 1-second formatting/rounding leeway, recorded in the tracker.
            //
            // `max_age > 0`, and the zero is not an oversight. What this entry reports is one
            // response holding two expiry answers sorted by the age of the cache reading it, and
            // `max-age=0` beside a past `Expires` holds one: the directive makes the response stale
            // on arrival for a cache that implements Cache-Control, and the date makes it stale on
            // arrival for the older cache the field is kept for. Reaching here with a zero already
            // means the date is at or before `Date` — a future one is the branch above — so the
            // only population this arm could take from a zero is the agreeing one. Distance between
            // the two instants is what is left, and distance is not disagreement when both lie in
            // the past; `Expires: 0` beside the same directive has always been silent, and
            // `Thu, 01 Jan 1970 00:00:00 GMT` is that instruction spelled so a recipient can read
            // it. The advice the message carries would also be wrong here, since dropping the field
            // is dropping the only expiry the HTTP/1.0 cache had.
            if resp.headers.contains_key("date") {
                if let Some(max_age) = cc_max_age {
                    if max_age > age {
                        // Two instants, because `Date` has two readings and the
                        // message does not say which one it was written under.
                        // Where `Date` is when the origin generated the
                        // response, the directive population goes stale at
                        // `Date + max-age` and the age is the time since. Where
                        // it is when the cache in front served this copy — which
                        // is what an `Age` beside a `Date` at the observed
                        // instant means — the lifetime left is what has not been
                        // spent, and the two populations meet at `Date + max-age
                        // - Age`. An `Expires` landing on either is one lifetime
                        // written twice, so only a value that lands on neither
                        // is two.
                        // cite(RFC 9111 § 4.2.3): "apparent_age = max(0, response_time - date_value)"
                        let expected = date_ref + chrono::Duration::seconds(max_age);
                        let expected_after_age =
                            date_ref + chrono::Duration::seconds(max_age - age);
                        // Allow a small leeway (1 second) for formatting/rounding differences
                        let diff = (expected - expires).num_seconds().abs();
                        let diff_after_age = (expected_after_age - expires).num_seconds().abs();
                        if diff > 1 && diff_after_age > 1 {
                            let spent = if age > 0 {
                                format!(
                                    ", or {expected_after_age} once the Age: {age} it arrived with is taken off"
                                )
                            } else {
                                String::new()
                            };
                            return Some(ctx.report_with(&EXPIRES_CONFLICTING, format!(
                                    "Cache-Control max-age={} suggests Expires should be {} (Date + max-age){}, but Expires is {} — prefer consistent values or omit Expires (RFC 9111 §5.3){}",
                                    max_age, expected, spent, expires, as_written
                                )));
                        }
                    }
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ExpiresAndCacheControlConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::make_test_transaction_with_response;
    use rstest::rstest;

    #[rstest]
    #[case(Some(("cache-control","max-age=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), false)]
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:29:00 GMT")), true)]
    #[case(Some(("cache-control","no-cache")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), true)]
    #[case(Some(("cache-control","max-age=60")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:27:00 GMT")), true)]
    // An invalid Expires means "already expired", so it contradicts a positive
    // max-age/s-maxage just as a past date does — `0` is the classic idiom.
    #[case(Some(("cache-control","max-age=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), true)]
    #[case(Some(("cache-control","s-maxage=3600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","not-a-date")), true)]
    // ... but agrees with directives that already deny reuse, so those stay quiet.
    #[case(Some(("cache-control","no-store")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), false)]
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","0")), false)]
    // The same agreement written so a recipient can read it. `max-age=0` says stale on arrival to
    // a cache that implements the directive and a date already past says stale on arrival to the
    // one that does not, however far back it is written, so the distance from `Date` + 0 is not a
    // second answer. The epoch is the idiom; the second row is the day before the message.
    #[case(Some(("cache-control","max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Thu, 01 Jan 1970 00:00:00 GMT")), false)]
    #[case(Some(("cache-control","no-cache, no-store, max-age=0")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Tue, 20 Oct 2015 07:28:00 GMT")), false)]
    // A positive max-age keeps the arm: here the two name different futures, and which one a cache
    // believes depends on whether it reads the directive.
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 GMT")), true)]
    // A spelling no recipient reads, naming the instant `Date` + `max-age` names. The
    // sender wrote one lifetime and misspelled the zone token; write `GMT` and the row
    // above it is the same response. Three spellings, one instant: the zone token in no
    // grammar at all, the mail production's own numeric offset, and a weekday that is not
    // the day its own date falls on (the twenty-first of October 2015 was a Wednesday).
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 07:38:00 UTC")), false)]
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 09:38:00 +0200")), false)]
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Tue, 21 Oct 2015 07:38:00 GMT")), false)]
    // Unreadable is not the verdict either way: the same zone token on an instant an hour
    // out is the disagreement the entry is for, and it is the hour that says so.
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","Wed, 21 Oct 2015 08:28:00 UTC")), true)]
    // What names no instant is untouched by any of it. `-1` is not a timestamp with a
    // misspelling in it, it is a sender asking for stale-on-arrival beside a directive
    // asking for ten minutes.
    #[case(Some(("cache-control","max-age=600")), Some(("date","Wed, 21 Oct 2015 07:28:00 GMT")), Some(("expires","-1")), true)]
    fn expires_and_cache_control_cases(
        #[case] cc: Option<(&str, &str)>,
        #[case] date: Option<(&str, &str)>,
        #[case] expires: Option<(&str, &str)>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let mut headers = Vec::new();
        if let Some(h) = cc {
            headers.push(h);
        }
        if let Some(d) = date {
            headers.push(d);
        }
        if let Some(e) = expires {
            headers.push(e);
        }

        let tx = make_test_transaction_with_response(200, &headers);
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for headers={:?}", headers);
        } else {
            assert!(
                v.is_none(),
                "unexpected violation: {:?} for headers={:?}",
                v,
                headers
            );
        }
        Ok(())
    }

    /// The age a response arrived with, in each arm that asks whether the
    /// directive population still calls it fresh.
    ///
    /// `Date` is the same instant in every row and `Age` is what moves, so a
    /// verdict that changes between two rows here changed because of the age
    /// and nothing else.
    #[rstest]
    // The lifetime is 3600 seconds and 2805 of them are spent, so a cache
    // reading the directive has 795 left and a cache reading the field is told
    // 795. One instant, named twice. Read off www.iana.org.
    #[case(&[("cache-control","public, max-age=3600"),("age","2805"),("date","Sun, 30 Aug 2026 00:03:31 GMT"),("expires","Sun, 30 Aug 2026 00:16:46 GMT")], false)]
    // The same response with no age behind it: now the directive says an hour
    // and the field says thirteen minutes, and they are two answers.
    #[case(&[("cache-control","public, max-age=3600"),("date","Sun, 30 Aug 2026 00:03:31 GMT"),("expires","Sun, 30 Aug 2026 00:16:46 GMT")], true)]
    // And the reading the age does not license: `Date` plus the whole lifetime
    // is still an instant the two can meet at, so a response served with an age
    // it has not spent is silent on the arithmetic it was already silent on.
    #[case(&[("cache-control","public, max-age=3600"),("age","2805"),("date","Sun, 30 Aug 2026 00:03:31 GMT"),("expires","Sun, 30 Aug 2026 01:03:31 GMT")], false)]
    // Neither instant. The lifetime is ten minutes however the age is read, and
    // the field names four hours. Read off www.rfc-editor.org.
    #[case(&[("cache-control","public, max-age=600"),("age","1012"),("date","Sun, 30 Aug 2026 01:20:10 GMT"),("expires","Sun, 30 Aug 2026 05:20:10 GMT")], true)]
    // A lifetime the age has spent entirely is a response stale on arrival to
    // every cache, which is what `max-age=0` says and is already silent beside
    // a past `Expires`. Distance between two past instants is not two answers.
    #[case(&[("cache-control","max-age=600"),("age","623"),("date","Sun, 30 Aug 2026 01:44:55 GMT"),("expires","Sat, 29 Aug 2026 22:10:03 GMT")], false)]
    // One second of it left, and the arm is back: the field says the response
    // went stale yesterday and the directive says it has not.
    #[case(&[("cache-control","max-age=600"),("age","599"),("date","Sun, 30 Aug 2026 01:44:55 GMT"),("expires","Sat, 29 Aug 2026 22:10:03 GMT")], true)]
    // A spent lifetime is not fresh, so a *future* `Expires` beside it is the
    // disagreement the non-fresh arm names — the arm that until now only knew
    // the lifetime written as a zero.
    #[case(&[("cache-control","max-age=600"),("age","900"),("date","Sun, 30 Aug 2026 01:20:10 GMT"),("expires","Sun, 30 Aug 2026 02:20:10 GMT")], true)]
    // An `Expires` naming no instant is already-expired, and a lifetime the age
    // has spent agrees with it. The same row with the age dropped is the `-1`
    // idiom this entry has always reported.
    #[case(&[("cache-control","max-age=600"),("age","900"),("date","Sun, 30 Aug 2026 01:20:10 GMT"),("expires","-1")], false)]
    #[case(&[("cache-control","max-age=600"),("date","Sun, 30 Aug 2026 01:20:10 GMT"),("expires","-1")], true)]
    // `s-maxage` answers for a shared cache and is unspent here, so one
    // population still holds a lifetime the field contradicts.
    #[case(&[("cache-control","max-age=600, s-maxage=7200"),("age","900"),("date","Sun, 30 Aug 2026 01:20:10 GMT"),("expires","-1")], true)]
    // An `Age` outside `delta-seconds` states nothing about elapsed time, so it
    // is read as no age rather than as some other number: the verdict is the
    // one the response would get with the field absent.
    #[case(&[("cache-control","public, max-age=3600"),("age","not-a-number"),("date","Sun, 30 Aug 2026 00:03:31 GMT"),("expires","Sun, 30 Aug 2026 00:16:46 GMT")], true)]
    fn age_is_part_of_the_lifetime_already_spent(
        #[case] headers: &[(&str, &str)],
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(200, headers);
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "headers={headers:?} gave {v:?}"
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "expires_and_cache_control_consistent");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn cache_control_s_maxage_positive_and_expires_in_past_reports_violation() -> anyhow::Result<()>
    {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "s-maxage=60"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 07:27:00 GMT"),
            ],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn invalid_expires_reads_as_already_expired_and_contradicts_max_age() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "max-age=60"), ("expires", "not-a-date")],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // Reporting the invalidity itself is another rule's job, but its *meaning*
        // is fixed by §5.3 — already expired — which max-age=60 contradicts.
        let v = v.expect("expected a contradiction violation");
        assert!(v.message.contains("already expired"));
        assert!(v.message.contains("not-a-date"));
        Ok(())
    }

    #[test]
    fn max_age_and_expires_within_leeway_is_ok() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=3600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:01 GMT"),
            ],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn non_utf8_cache_control_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("cache-control", bad);
        hm.insert(
            "expires",
            HeaderValue::from_static("Wed, 21 Oct 2015 08:28:00 GMT"),
        );
        tx.response.as_mut().unwrap().headers = hm;
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // non-UTF8 cache-control means cc_present stays false -> no violation
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn max_age_malformed_is_ignored_and_no_violation() -> anyhow::Result<()> {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=abc"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:00 GMT"),
            ],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn missing_date_header_uses_now_and_reports_violation_for_no_cache_future_expires(
    ) -> anyhow::Result<()> {
        use chrono::{TimeZone, Utc};
        // Use a far-future Expires so comparison with Utc::now() is predictable. Build the
        // RFC1123 string using chrono so weekday matches and parsing succeeds.
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "no-cache"), ("expires", &expires)],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some(), "got {:?}", v);
        Ok(())
    }

    #[test]
    fn needs_a_response() {
        let rule = ExpiresAndCacheControlConsistent;
        assert!(!rule.needs_response());
    }

    #[test]
    fn parse_far_future_expires_works() -> anyhow::Result<()> {
        use chrono::{Datelike, TimeZone, Utc};
        // Build a valid RFC1123 date far in the future so parsing is predictable
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let s = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let parsed = crate::http_date::parse_http_date_to_datetime(&s)?;
        assert_eq!(parsed.year(), 2125);
        Ok(())
    }

    #[test]
    fn max_age_and_expires_mismatch_reports_violation() -> anyhow::Result<()> {
        // Date 07:28:00, max-age=3600, Expires 08:27:50 (10 seconds off) => violation
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=3600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:27:50 GMT"),
            ],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn no_store_and_future_expires_reports_violation() -> anyhow::Result<()> {
        use chrono::{TimeZone, Utc};
        // Use far future to avoid flakiness
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let tx = make_test_transaction_with_response(
            200,
            &[("cache-control", "no-store"), ("expires", &expires)],
        );
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn multiple_cache_control_header_fields_combined_reports_violation() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[]);
        let mut hm = HeaderMap::new();
        // two cache-control header fields appended: one is no-cache which should trigger violation
        hm.append("cache-control", HeaderValue::from_static("public"));
        hm.append("cache-control", HeaderValue::from_static("no-cache"));
        use chrono::{TimeZone, Utc};
        let dt = Utc
            .with_ymd_and_hms(2125, 10, 21, 8, 28, 0)
            .single()
            .unwrap();
        let expires_s = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        hm.insert("expires", HeaderValue::from_str(&expires_s).unwrap());
        tx.response.as_mut().unwrap().headers = hm;
        // Sanity-check the headers we just built; ensure both cache-control header fields are present
        let hm_ref = &tx.response.as_ref().unwrap().headers;
        let cc_vals: Vec<_> = hm_ref
            .get_all("cache-control")
            .iter()
            .map(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .collect();
        assert_eq!(
            cc_vals.len(),
            2,
            "expected two cache-control header fields, got {:?}",
            cc_vals
        );
        // Expires should parse as a valid HTTP date
        assert!(hm_ref
            .get_all("expires")
            .iter()
            .next()
            .and_then(|hv| hv.to_str().ok())
            .is_some());

        // Re-parse Cache-Control here like the rule does and assert we detect `no-cache`
        let mut cc_no_cache = false;
        let mut cc_present = false;
        for hv in hm_ref.get_all("cache-control").iter() {
            if let Ok(s) = hv.to_str() {
                cc_present = true;
                for part in s.split(',') {
                    let p = part.trim();
                    if p.is_empty() {
                        continue;
                    }
                    let mut it = p.splitn(2, '=');
                    let name = it.next().unwrap().trim().to_ascii_lowercase();
                    if name.as_str() == "no-cache" {
                        cc_no_cache = true;
                    }
                }
            }
        }
        assert!(cc_present, "expected cache-control present");
        assert!(
            cc_no_cache,
            "expected to detect no-cache among cache-control values"
        );

        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    /// An instant recovered from a spelling nothing reads is not in the
    /// response, and a reader who searches the response for it finds nothing.
    /// The message carries the octets that are there.
    #[test]
    fn a_recovered_instant_is_reported_beside_the_octets_it_came_from() {
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:00 UTC"),
            ],
        );
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &ExpiresAndCacheControlConsistent,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert!(
            v.message.contains("'Wed, 21 Oct 2015 08:28:00 UTC'"),
            "{}",
            v.message
        );

        // A value the recipient does read needs no such note, and adding one
        // would say a readable field was unreadable.
        let readable = make_test_transaction_with_response(
            200,
            &[
                ("cache-control", "max-age=600"),
                ("date", "Wed, 21 Oct 2015 07:28:00 GMT"),
                ("expires", "Wed, 21 Oct 2015 08:28:00 GMT"),
            ],
        );
        let v = crate::test_helpers::run_rule(
            &ExpiresAndCacheControlConsistent,
            &readable,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("a finding");
        assert!(!v.message.contains("no recipient parses"), "{}", v.message);
    }

    #[test]
    fn non_utf8_expires_is_ignored() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;
        let mut tx = make_test_transaction_with_response(200, &[("cache-control", "max-age=3600")]);
        let mut hm = HeaderMap::new();
        hm.insert("cache-control", HeaderValue::from_static("max-age=3600"));
        let bad = HeaderValue::from_bytes(&[0xff]).unwrap();
        hm.insert("expires", bad);
        tx.response.as_mut().unwrap().headers = hm;
        let rule = ExpiresAndCacheControlConsistent;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "expires_and_cache_control_consistent",
        ]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // non-UTF8 expires means has_expires stays false -> no violation
        assert!(v.is_none());
        Ok(())
    }
}
