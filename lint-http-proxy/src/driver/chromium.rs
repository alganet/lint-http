// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The Chromium-family driver.
//!
//! A browser was the first tool this repository configured on its own command
//! line rather than through the environment, and it was a command of its own
//! before it was a driver — which is why [`crate::browser`] exists and why this
//! module is thin. That module answers *how is a browser found, and how is one
//! told to use this proxy without changing the machine it runs on*; this one
//! answers *what does lint-http do with the invocation*, which is the question
//! every driver answers and the reason they are separate files.

use anyhow::Result;

use super::{Driver, Invocation, Launch, Objection, Target, Tool};

/// Chromium, and the browsers built on it.
pub struct Chromium;

impl Driver for Chromium {
    /// Every name a user would type for "the browser".
    ///
    /// `browser` is in the list on purpose: it is the ergonomic front door, and
    /// it costs nothing to answer to the word for the category as well as to
    /// the binaries in it.
    fn names(&self) -> &'static [&'static str] {
        &[
            "chromium",
            "brave",
            "brave-browser",
            "browser",
            "chrome",
            "chromium-browser",
            "edge",
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "microsoft-edge-stable",
        ]
    }

    /// Somebody is sitting in front of this one.
    fn interactive(&self) -> bool {
        true
    }

    /// A browser has no stdout worth protecting, so a JSON report may have it —
    /// which is what `--format json > findings.json` has always done here.
    fn json_to_stdout(&self) -> bool {
        true
    }

    fn locate(&self, explicit: Option<&str>) -> Result<Tool> {
        let browser = crate::browser::discover(explicit)?;
        Ok(Tool {
            path: browser.path,
            name: browser.name,
        })
    }

    /// A browser is given a URL and switches; there is nothing else to read.
    ///
    /// No body is ever sent by the invocation — a page may post one, and that
    /// is the page's doing rather than the command line's — so `sends_body`
    /// stays false and body capture is left to the configuration.
    fn inspect(&self, args: &[String]) -> Invocation {
        Invocation {
            args: args.to_vec(),
            targets: args
                .iter()
                .filter(|arg| !arg.starts_with('-'))
                .cloned()
                .collect(),
            sends_body: false,
            objections: args.iter().filter_map(|arg| objection(arg)).collect(),
        }
    }

    fn command(&self, tool: &Tool, invocation: &Invocation, at: &Target<'_>) -> Result<Launch> {
        let browser = crate::browser::Browser {
            path: tool.path.clone(),
            name: tool.name.clone(),
        };
        // A profile of its own, inside the session directory, so it goes when
        // the session does.
        let profile = at.scratch.join("browser-profile");
        std::fs::create_dir_all(&profile)?;

        let mut objections = Vec::new();
        if at.spki_pin.is_none() {
            // Precise about what actually happens: interception is the proxy's
            // decision and it is still on, so HTTPS is *intercepted* — the
            // browser simply has no reason to trust the result. Saying
            // "tunnelled unlinted" here described a different failure and sent
            // the reader looking for the wrong thing.
            objections.push(Objection::Warn(
                "no certificate pin for this session; HTTPS pages will fail to verify \
                 (run with --show-child-stderr, or check that the CA could be written)"
                    .to_string(),
            ));
        }

        Ok(Launch {
            command: crate::browser::command(
                &browser,
                &profile,
                at.addr,
                at.spki_pin,
                &invocation.args,
            ),
            objections,
        })
    }
}

/// What one browser switch does to a report, when it does something.
///
/// Only the switches that change what a finding *means*. A browser has hundreds
/// and this file knows about three, which is the intended proportion: everything
/// else is passed through and is none of lint-http's business.
fn objection(arg: &str) -> Option<Objection> {
    // `--flag=value` and `--flag` are the same switch here; only the name is
    // being matched.
    let name = arg.split('=').next().unwrap_or(arg);
    match name {
        // The blunt instrument. Verification is off for every certificate, so
        // nothing the session says about TLS means anything — and the session
        // pins one key precisely so it does not have to do this.
        "--ignore-certificate-errors" => Some(Objection::Warn(
            "--ignore-certificate-errors turns verification off for every certificate; \
             TLS findings from this session mean nothing (the session already trusts its \
             own CA by public-key pin)"
                .to_string(),
        )),
        // There is one proxy this session can report on, and it is not that one.
        "--proxy-server" | "--proxy-pac-url" => Some(Objection::Refuse(format!(
            "{name} sends the browser somewhere other than this session's proxy, which \
             would leave nothing to report"
        ))),
        // Subtractive by default here (`<-loopback>`); a user list replaces it,
        // and whatever it names goes unseen.
        "--proxy-bypass-list" => Some(Objection::Warn(
            "--proxy-bypass-list replaces the session's own list, so traffic to the hosts \
             it names will not reach the proxy and will not be in the report"
                .to_string(),
        )),
        // The throwaway profile is what makes a session leave nothing behind,
        // and it is also what forces a new process rather than handing the URL
        // to a browser already running outside the proxy.
        "--user-data-dir" => Some(Objection::Warn(
            "--user-data-dir competes with the throwaway profile this session creates; \
             the session may join a browser already running outside the proxy"
                .to_string(),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(args: &[&str]) -> Invocation {
        Chromium.inspect(&args.iter().map(|a| (*a).to_string()).collect::<Vec<_>>())
    }

    /// The URL is the scope, and it is read rather than removed: what the user
    /// typed reaches the browser in the order they typed it.
    #[test]
    fn every_non_switch_is_a_target() {
        let invocation = inspect(&["--incognito", "https://example.com/app"]);
        assert_eq!(invocation.targets, ["https://example.com/app"]);
        assert_eq!(invocation.args, ["--incognito", "https://example.com/app"]);
    }

    #[test]
    fn a_session_on_no_url_has_no_target() {
        assert!(inspect(&[]).targets.is_empty());
        assert!(inspect(&["--incognito"]).targets.is_empty());
    }

    /// An unrecognized switch is opaque and reaches the browser unchanged.
    /// A driver that tried to know every Chromium flag would start rejecting
    /// valid ones, which is worse than not knowing about them.
    #[test]
    fn a_switch_this_does_not_know_is_passed_through_and_unremarked() {
        let invocation = inspect(&["--enable-features=SomethingNew", "--lang=pt-BR"]);
        assert_eq!(
            invocation.args,
            ["--enable-features=SomethingNew", "--lang=pt-BR"]
        );
        assert!(invocation.objections.is_empty());
    }

    /// The three that would make the report a lie, said before anything starts.
    #[test]
    fn the_switches_that_defeat_linting_are_objected_to() {
        assert!(matches!(
            inspect(&["--ignore-certificate-errors"]).objections[..],
            [Objection::Warn(_)]
        ));
        assert!(matches!(
            inspect(&["--proxy-server=http://someone-else:8080"]).objections[..],
            [Objection::Refuse(_)]
        ));
        assert!(matches!(
            inspect(&["--proxy-bypass-list=<-loopback>"]).objections[..],
            [Objection::Warn(_)]
        ));
        // `--flag value` and `--flag=value` are the same switch.
        assert_eq!(inspect(&["--proxy-server", "http://x"]).objections.len(), 1);
    }

    /// A session with no CA cannot verify anything, and the browser is the one
    /// that will show it — as a certificate error on every page.
    #[test]
    fn a_session_without_a_pin_says_so_at_launch() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("lint-http-driver-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let tool = Tool {
            path: std::path::PathBuf::from("/usr/bin/chromium"),
            name: "chromium".to_string(),
        };
        let at = Target {
            addr: "127.0.0.1:9111".parse()?,
            trust_bundle: None,
            spki_pin: None,
            scratch: &dir,
        };
        let launch = Chromium.command(&tool, &Invocation::default(), &at)?;
        assert!(matches!(launch.objections[..], [Objection::Warn(_)]));

        let pinned = Target {
            spki_pin: Some("abc="),
            ..at
        };
        assert!(Chromium
            .command(&tool, &Invocation::default(), &pinned)?
            .objections
            .is_empty());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
