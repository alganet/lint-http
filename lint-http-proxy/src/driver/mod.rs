// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Configuring a tool the way that tool documents, instead of hoping it reads
//! the environment.
//!
//! `run -- <anything>` is tool-blind on purpose. It exports `http_proxy` and
//! `SSL_CERT_FILE` and trusts the child to look; that is the right escape hatch
//! for a tool nothing here knows about, and the wrong default for a tool whose
//! own manual says how to point it at a proxy. `curl --proxy` and `--cacert`
//! are unambiguous where the environment is a precedence maze, and a `NO_PROXY`
//! exported three shells ago silently empties a run that then reports a clean
//! zero — a failure class [`crate::client_env`] can document and cannot
//! prevent.
//!
//! ## What a driver is
//!
//! One tool, five answers:
//!
//! 1. **Which executable** — [`Driver::locate`], which may search rather than
//!    take a name literally, because "a Chromium-family browser" is a set.
//! 2. **What the invocation asks for** — [`Driver::inspect`], which reads the
//!    tool's own arguments for the few that change what lint-http does, and
//!    for nothing else.
//! 3. **Where it is aimed** — the target URL, which becomes the default host
//!    scope, so a report is about the site under test rather than about every
//!    origin it reached.
//! 4. **What would make the report a lie** — [`Objection`]s, raised *before* a
//!    proxy is stood up. This is the whole point of parsing at all: the wrapper's
//!    characteristic failure is a clean report, not an error, and a flag that
//!    turns certificate verification off produces exactly that.
//! 5. **How to say it** — [`Driver::command`], which writes the session onto
//!    the tool's own command line.
//!
//! ## Scope discipline
//!
//! **A driver is not a parser for its tool.** It reads the flags that change
//! lint-http's behaviour, passes everything else through untouched, and treats
//! anything it does not recognize as opaque. A tool grows flags faster than
//! this file can, and a driver that tried to be complete would start rejecting
//! valid invocations — which is a worse failure than not knowing about one.
//!
//! **And static parsing cannot be complete anyway.** Tools read configuration
//! files: `curl` reads `~/.curlrc`, so `--insecure` can be in force with
//! nothing on the command line to show for it. A driver therefore *detects and
//! says so*; it never promises.

use anyhow::Result;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub mod chromium;

/// Every driver, in the order a name is searched for.
pub static DRIVERS: &[&dyn Driver] = &[&chromium::Chromium];

/// An executable a driver will run.
#[derive(Debug, Clone)]
pub struct Tool {
    /// The executable.
    pub path: PathBuf,
    /// What to call it in messages — the file name, which is what the user
    /// typed or what was found on `PATH`.
    pub name: String,
}

/// Something about an invocation that the report cannot survive being wrong
/// about.
///
/// Raised before a proxy exists, because the point is to say it while there is
/// still a decision to make. A session that stands everything up and *then*
/// reports zero findings has already answered the user's question, wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Objection {
    /// The session can run, but some part of its report will not mean what it
    /// says.
    Warn(String),
    /// The session cannot do what was asked at all.
    Refuse(String),
}

impl Objection {
    /// The line a user sees.
    pub fn message(&self) -> &str {
        match self {
            Objection::Warn(m) | Objection::Refuse(m) => m,
        }
    }
}

/// What a driver read out of one invocation.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// The tool's own arguments, **unchanged**. A driver adds its own switches
    /// in [`Driver::command`]; it does not rewrite, reorder or drop what the
    /// user typed, and an argument it does not recognize reaches the tool
    /// byte-identical.
    pub args: Vec<String>,
    /// The URL this invocation is aimed at, when the driver could tell. The
    /// default host scope comes from here.
    pub target: Option<String>,
    /// This invocation sends a request body, so the session should capture
    /// bodies — which is what makes the rules that read one worth having.
    pub sends_body: bool,
    /// What is wrong with it.
    pub objections: Vec<Objection>,
}

/// Where the session is, for a driver that has to write it onto a command line.
///
/// Everything a tool could need to reach this proxy and trust it, and nothing
/// about the proxy's internals: a driver is handed an address, two ways to
/// trust a certificate and somewhere to write, and cannot reach the session
/// itself.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// Where the proxy is listening.
    pub addr: SocketAddr,
    /// The session CA and the platform roots together, for a tool that trusts
    /// through a file. `None` when TLS interception is off.
    pub trust_bundle: Option<&'a Path>,
    /// The session CA's public-key pin, for a tool that trusts through one.
    /// `None` for the same reason.
    pub spki_pin: Option<&'a str>,
    /// A directory that exists for this session and is deleted with it, for a
    /// tool that needs somewhere to put a throwaway profile.
    pub scratch: &'a Path,
}

/// A tool, wired up and ready to start.
pub struct Launch {
    /// The process to run.
    pub command: tokio::process::Command,
    /// What the driver noticed while wiring it up — a missing pin, say, which
    /// is not known until the session exists.
    pub objections: Vec<Objection>,
}

/// A tool `lint-http` knows how to configure.
pub trait Driver: Sync {
    /// The names this driver answers to, canonical first. The canonical name is
    /// what messages call it; the rest are the executables and nicknames a user
    /// would reasonably type for the same thing.
    fn names(&self) -> &'static [&'static str];

    /// Whether this is a session someone sits in front of.
    ///
    /// Decides whether findings print as they commit. A browsing session lasts
    /// minutes and makes hundreds of requests, so holding the report until the
    /// window closes delivers it after the thing it describes is gone; a
    /// command that finishes in a second is better off not interleaving its
    /// findings with its own output.
    fn interactive(&self) -> bool;

    /// Whether a `--format json` document may go to stdout.
    ///
    /// Only for a tool that has no stdout worth protecting. Anything that
    /// writes a response body there owns the stream, and a report written
    /// alongside would corrupt what the user is redirecting.
    fn json_to_stdout(&self) -> bool;

    /// The executable to run. `explicit` is a path or a name the user gave in
    /// place of letting the driver search.
    fn locate(&self, explicit: Option<&str>) -> Result<Tool>;

    /// Read the invocation for what changes lint-http's behaviour.
    fn inspect(&self, args: &[String]) -> Invocation;

    /// The command that runs this tool through the session.
    fn command(&self, tool: &Tool, invocation: &Invocation, at: &Target<'_>) -> Result<Launch>;
}

/// The driver a name selects, if any.
///
/// A name with a path separator in it is a path, and its file stem chooses the
/// driver — `use /opt/chrome/chrome` is the Chromium driver pointed at that
/// binary. A bare name is matched against the table directly.
pub fn by_name(typed: &str) -> Option<&'static dyn Driver> {
    let stem = Path::new(typed)
        .file_stem()
        .map_or_else(|| typed.to_string(), |s| s.to_string_lossy().into_owned())
        .to_ascii_lowercase();
    DRIVERS
        .iter()
        .copied()
        .find(|driver| driver.names().iter().any(|name| *name == stem))
}

/// Resolve what the user typed into a driver and the executable to run.
///
/// Whether the name is *the tool* or *a family of tools* is decided by looking:
/// a name with a path separator is a path, and a bare name that is on `PATH` is
/// the binary the user meant. Anything else — `chrome` on a machine that ships
/// `chromium`, or the word `browser` — is a family, and the driver searches for
/// a member of it. Without that, `use chrome` fails on the many machines where
/// no file is called that.
pub fn resolve(typed: &str) -> Result<(&'static dyn Driver, Tool)> {
    let driver = by_name(typed).ok_or_else(|| {
        anyhow::anyhow!(
            "nothing here drives `{typed}` (known: {}). \
             `lint-http run -- {typed} ...` wraps it through the environment instead",
            known_names().join(", ")
        )
    })?;
    let names_a_file =
        typed.contains(std::path::MAIN_SEPARATOR) || crate::browser::which(typed).is_some();
    let tool = driver.locate(names_a_file.then_some(typed))?;
    Ok((driver, tool))
}

/// Every name any driver answers to, for an error message that can list them.
pub fn known_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DRIVERS
        .iter()
        .flat_map(|d| d.names().iter().copied())
        .collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_selects_its_driver() {
        assert_eq!(
            by_name("chromium").map(Driver::names),
            Some(chromium::Chromium.names())
        );
        assert!(by_name("chrome").is_some(), "an alias is a name too");
        assert!(by_name("CHROME").is_some(), "however it was typed");
    }

    /// A path names the executable and its stem names the driver, so pointing
    /// `use` at a binary that is not on `PATH` still configures it as what it is.
    #[test]
    fn a_path_selects_by_its_file_stem() {
        assert!(by_name("/opt/google/chrome/chrome").is_some());
        assert!(by_name("./brave-browser").is_some());
    }

    #[test]
    fn a_tool_nothing_drives_selects_nothing() {
        assert!(by_name("wget").is_none());
        assert!(by_name("/usr/bin/wget").is_none());
    }

    /// The error names the escape hatch, because there is one and it works.
    #[test]
    fn an_undriven_tool_is_told_where_to_go() {
        let Err(err) = resolve("wget") else {
            panic!("wget has no driver");
        };
        let message = err.to_string();
        assert!(message.contains("wget"), "{message}");
        assert!(message.contains("run --"), "{message}");
        assert!(message.contains("chromium"), "{message}");
    }

    #[test]
    fn every_name_is_listed_once_and_sorted() {
        let names = known_names();
        let mut unique = names.clone();
        unique.dedup();
        assert_eq!(names, unique, "a name answers for one driver");
        assert!(names.windows(2).all(|w| w[0] <= w[1]));
    }
}
