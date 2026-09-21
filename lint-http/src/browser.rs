// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Finding a Chromium-family browser, and the flags that point one at this
//! proxy without changing anything about the machine it runs on.
//!
//! The question: *how is a browser told to use this proxy and accept its
//! certificates, in a way that ends when the browser does?* Every flag below is
//! there to keep some part of that promise, and the ones that look like
//! paranoia are the ones that stop a session from reporting a clean nothing.
//!
//! ## Why Chromium first, and why Firefox is not here
//!
//! Proxy settings are easy in both. Trust is not. Chromium takes a
//! command-line public-key pin, so a launch can trust one CA for its own
//! lifetime and touch nothing persistent. Firefox verifies through its own NSS
//! database, which has no equivalent flag: trusting a CA there means writing
//! into a profile's `cert9.db` with `certutil` — an external tool that is
//! usually not installed — or dropping an enterprise `policies.json` next to
//! the *installation*, which is neither per-profile nor per-run. Both are real
//! options and neither is this one, so Firefox is a separate piece of work
//! rather than a flag away.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// A browser this can drive.
#[derive(Debug, Clone)]
pub struct Browser {
    /// The executable.
    pub path: PathBuf,
    /// What to call it in messages — the file name, which is what the user
    /// typed or what was found on `PATH`.
    pub name: String,
}

/// Executables to look for on `PATH`, in preference order.
///
/// Chromium before Chrome because it is the one more likely to be a
/// developer's second browser rather than their signed-in daily one, and this
/// command opens a browser whose traffic is being recorded.
const PATH_CANDIDATES: &[&str] = &[
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
    "microsoft-edge",
    "microsoft-edge-stable",
];

/// Bundles to look for on macOS, where browsers are not on `PATH`.
#[cfg(target_os = "macos")]
const BUNDLE_CANDIDATES: &[&str] = &[
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
];

#[cfg(not(target_os = "macos"))]
const BUNDLE_CANDIDATES: &[&str] = &[];

/// Locate a browser, preferring one the caller named.
///
/// An explicit path is taken as given and not searched for: if it is wrong, the
/// error should name what the user asked for rather than silently opening
/// something else.
pub fn discover(explicit: Option<&str>) -> Result<Browser> {
    if let Some(given) = explicit {
        let path = PathBuf::from(given);
        // A bare name is looked up on PATH; anything with a separator is a path.
        let resolved = if path.components().count() > 1 {
            path.exists().then_some(path.clone())
        } else {
            crate::driver::which(given)
        };
        let path = resolved.with_context(|| format!("no such browser: {given}"))?;
        return Ok(Browser {
            name: file_name(&path),
            path,
        });
    }

    for candidate in PATH_CANDIDATES {
        if let Some(path) = crate::driver::which(candidate) {
            return Ok(Browser {
                name: (*candidate).to_string(),
                path,
            });
        }
    }
    for candidate in BUNDLE_CANDIDATES {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(Browser {
                name: file_name(&path),
                path,
            });
        }
    }

    anyhow::bail!(
        "no Chromium-family browser found (looked for {}); name one with --browser <PATH>",
        PATH_CANDIDATES.join(", ")
    )
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// The command line for one browsing session.
///
/// `profile` is a directory that exists only for this session, `pin` is the
/// CA's [`crate::ca::CertificateAuthority::spki_pin`], and `args` is whatever
/// the user gave the browser — a URL to open, switches of their own, or
/// nothing, in which case the browser opens its own start page and everything
/// it fetches is still linted.
///
/// The session's own switches go first and the user's arguments follow, in the
/// order they were typed. Both halves matter: a URL Chromium is to open must
/// come after every switch or it is read as a value, and an argument the user
/// wrote must reach the browser unchanged.
pub fn command(
    browser: &Browser,
    profile: &Path,
    addr: SocketAddr,
    pin: Option<&str>,
    args: &[String],
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(&browser.path);

    // A profile of its own, which is what makes the rest of this session-scoped
    // rather than a change to the user's browser. It also forces a *new*
    // process: a Chromium already running on the default profile would hand the
    // URL to that instance and exit, and the session would end before it began
    // — with the page loading outside the proxy.
    command.arg(format!("--user-data-dir={}", profile.display()));
    command.arg(format!("--proxy-server=http://{addr}"));

    // Chromium bypasses the proxy for loopback by default, so without this a
    // developer pointing `browse` at their own dev server would watch it load
    // perfectly and get a report about nothing. `<-loopback>` subtracts
    // loopback from the bypass list rather than adding to it.
    command.arg("--proxy-bypass-list=<-loopback>");

    if let Some(pin) = pin {
        // Trust for one key, for one launch. See `spki_pin` for why this rather
        // than installing the CA, and why not `--ignore-certificate-errors`.
        command.arg(format!("--ignore-certificate-errors-spki-list={pin}"));
    }

    // A fresh profile means first-run flows, and every one of them is traffic
    // the user did not ask for and will read findings about. These are the
    // switches that keep a session about the site under test.
    command.args([
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--disable-domain-reliability",
        "--disable-breakpad",
        "--no-service-autorun",
        "--propagate-iph-for-testing",
    ]);

    command.args(args);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:9111".parse().unwrap()
    }

    fn rendered(pin: Option<&str>, extra: &[&str]) -> Vec<String> {
        let browser = Browser {
            path: PathBuf::from("/usr/bin/chromium"),
            name: "chromium".into(),
        };
        let extra: Vec<String> = extra.iter().map(|a| (*a).to_string()).collect();
        let command = command(&browser, Path::new("/tmp/profile"), addr(), pin, &extra);
        command
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn the_session_gets_its_own_profile_and_the_proxy() {
        let args = rendered(None, &[]);
        assert!(args.contains(&"--user-data-dir=/tmp/profile".to_string()));
        assert!(args.contains(&"--proxy-server=http://127.0.0.1:9111".to_string()));
    }

    /// Without this, `browse http://localhost:3000` loads outside the proxy and
    /// reports nothing — the failure looks exactly like a clean site.
    #[test]
    fn loopback_is_not_bypassed() {
        assert!(rendered(None, &[]).contains(&"--proxy-bypass-list=<-loopback>".to_string()));
    }

    #[test]
    fn the_pin_is_passed_when_there_is_one() {
        let args = rendered(Some("abc="), &[]);
        assert!(args.contains(&"--ignore-certificate-errors-spki-list=abc=".to_string()));
        // And is simply absent otherwise, rather than empty.
        assert!(!rendered(None, &[])
            .iter()
            .any(|a| a.starts_with("--ignore-certificate-errors-spki-list")));
    }

    /// The blunt instrument turns verification off for every certificate, which
    /// would make the session worthless for judging TLS. It must never appear.
    #[test]
    fn verification_is_never_switched_off_wholesale() {
        for args in [rendered(None, &[]), rendered(Some("abc="), &["https://x"])] {
            assert!(
                !args.iter().any(|a| a == "--ignore-certificate-errors"),
                "blanket certificate-error suppression was passed"
            );
        }
    }

    /// The session's switches come first and the user's arguments follow, in
    /// order. A URL Chromium is to open has to be after every switch or it is
    /// read as a value — and a switch the user typed has to arrive as typed.
    #[test]
    fn the_session_switches_come_before_what_the_user_typed() {
        let args = rendered(Some("abc="), &["--incognito", "https://example.com"]);
        assert_eq!(
            &args[args.len() - 2..],
            ["--incognito", "https://example.com"]
        );
        let ours = args.iter().position(|a| a == "--incognito").unwrap();
        assert!(
            args[..ours]
                .iter()
                .any(|a| a.starts_with("--proxy-server=")),
            "the session's own switches were not first"
        );
    }

    #[test]
    fn an_explicit_browser_that_does_not_exist_names_itself() {
        let err = discover(Some("/nonexistent/browser-xyz")).expect_err("should fail");
        assert!(err.to_string().contains("browser-xyz"), "{err}");
    }
}
