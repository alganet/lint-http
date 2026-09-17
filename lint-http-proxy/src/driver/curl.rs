// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The curl driver.
//!
//! curl is the tool this wrapper is put in front of more than any other, and it
//! is the one the environment serves worst. `run -- curl` exports `http_proxy`,
//! `https_proxy`, `all_proxy`, `SSL_CERT_FILE` and `CURL_CA_BUNDLE` and hopes;
//! curl's own manual, meanwhile, says `--proxy` and `--cacert`, which are two
//! options with no precedence to reason about.
//!
//! ## What that buys, precisely
//!
//! **`no_proxy` stops being able to silently empty a run.** An exported
//! `NO_PROXY` keeps curl away from the proxy, the session records nothing, and
//! the report says zero findings — the wrapper's signature failure, arriving
//! from a shell somebody configured months ago. `client_env` can only document
//! it. This driver ends it, on curl's own documented terms: `--noproxy ""`
//! overrides the variable.
//!
//! **The report knows what the command was aimed at**, so it is about the
//! target's hosts rather than about every origin the transfer touched.
//!
//! **A body that was asked for is a body a kept capture records.** This one is
//! smaller than it sounds and is written down so nobody claims otherwise: the
//! report already covers bodies, because it is the proxy's own live findings
//! and the live pass buffered them. What `-d @order.json` changes is the
//! JSONL, when `--captures` asked for one.
//!
//! ## What it deliberately does not buy
//!
//! **This does not neutralize a hostile `~/.curlrc`.** curl reads a default
//! config file "even when --config is used", and the manual states no
//! precedence between what that file says and what is on the command line — so
//! nothing here may claim that appending `--no-insecure` would undo an
//! `insecure` line in it. What this does instead is *look*: if a default config
//! file exists and names one of the settings that would change what a finding
//! means, the session says so before it starts. Detect and say; never promise.

use anyhow::Result;
use std::path::{Path, PathBuf};

use super::{Driver, Invocation, Launch, Objection, Target, Tool};

/// curl.
pub struct Curl;

impl Driver for Curl {
    fn names(&self) -> &'static [&'static str] {
        &["curl"]
    }

    /// A transfer, not a sitting: it finishes, and streaming findings would
    /// only interleave them with the transfer's own output.
    fn interactive(&self) -> bool {
        false
    }

    /// **Stdout is curl's.** It is where the response body goes unless `-o`
    /// says otherwise, and a report written there would corrupt exactly what
    /// the user is redirecting.
    fn json_to_stdout(&self) -> bool {
        false
    }

    fn locate(&self, explicit: Option<&str>) -> Result<Tool> {
        let given = explicit.unwrap_or("curl");
        let path = if given.contains(std::path::MAIN_SEPARATOR) {
            let path = PathBuf::from(given);
            path.exists().then_some(path)
        } else {
            super::which(given)
        };
        let path = path.ok_or_else(|| anyhow::anyhow!("no such executable: {given}"))?;
        Ok(Tool {
            name: path
                .file_name()
                .map_or_else(|| given.to_string(), |n| n.to_string_lossy().into_owned()),
            path,
        })
    }

    fn inspect(&self, args: &[String]) -> Invocation {
        let mut invocation = Invocation {
            args: args.to_vec(),
            ..Invocation::default()
        };
        let mut previous: Option<&str> = None;
        for (index, arg) in args.iter().enumerate() {
            let names: Vec<&'static str> = flag_names(arg).collect();
            // An option's value is written into it (`--noproxy=`) or is the
            // argument after it. Both spellings mean the same thing, and
            // `--noproxy ""` — the documented way to undo a `no_proxy` — is
            // only recognisable through the second.
            let value = value_of(arg).or_else(|| {
                names
                    .last()
                    .filter(|name| TAKES_A_VALUE.contains(*name))
                    .and_then(|_| args.get(index + 1).map(String::as_str))
            });
            for name in &names {
                if SENDS_BODY.contains(name) {
                    invocation.sends_body = true;
                }
                invocation.objections.extend(objection(name, value));
            }
            // `--url <url>` names one whatever it looks like; anything else has
            // to look like one, and must not be the value of the option before
            // it.
            if previous == Some("--url")
                || (!TAKES_A_VALUE.contains(&previous.unwrap_or_default()) && is_url(arg))
            {
                invocation.targets.push(arg.clone());
            }
            // A value written into the option is not waiting for the next
            // argument, so the next argument is free to be a URL.
            previous = value_of(arg)
                .is_none()
                .then(|| names.last().copied())
                .flatten();
        }
        invocation
    }

    fn command(&self, tool: &Tool, invocation: &Invocation, at: &Target<'_>) -> Result<Launch> {
        let mut command = tokio::process::Command::new(&tool.path);
        let mut objections = Vec::new();

        // `-q` only works where it is written, so it stays where it was written.
        // Prepending anything ahead of it turns a request to ignore `~/.curlrc`
        // into a silent no-op — and this driver's own warnings about that file
        // would then be describing a file curl was about to read after all.
        //
        // cite(curl): "If used as the first parameter on the command line, the curlrc config file is not read or used."
        let leading_disable = invocation
            .args
            .first()
            .is_some_and(|arg| arg == "-q" || arg == "--disable");
        if leading_disable {
            command.arg(&invocation.args[0]);
        }

        // Told on its own command line rather than through five environment
        // variables with a precedence order between them.
        //
        // cite(curl): "Use the specified proxy."
        command.arg("--proxy").arg(format!("http://{}", at.addr));

        match at.trust_bundle {
            // The bundle, not the bare CA: it is the session's certificate
            // *and* the platform roots, so this extends what curl trusts
            // instead of replacing it.
            //
            // cite(curl): "(TLS) Use the specified certificate file to verify the peer. The file may contain multiple CA certificates. The certificate(s) must be in PEM format. Normally curl is built to use a default file for this, so this option is typically used to alter that default file."
            Some(bundle) => {
                command.arg("--cacert").arg(bundle);
            }
            None => objections.push(Objection::Warn(
                "no session CA to trust; HTTPS through this proxy will fail to verify \
                 (check that the CA could be written, or that tls.enabled is on)"
                    .to_string(),
            )),
        }

        // **The one that ends the silent-empty-run class.** An exported
        // `NO_PROXY` keeps curl away from the proxy and the report then says
        // zero findings, which is indistinguishable from a clean transfer.
        // Skipped when the user wrote their own list, because theirs is an
        // instruction and this is only a default.
        //
        // cite(curl): "This option overrides the environment variables that disable the proxy ("no_proxy" and "NO_PROXY"). If there is an environment variable disabling a proxy, you can set the no proxy list to "" to override it."
        if !invocation
            .args
            .iter()
            .any(|arg| flag_names(arg).any(|name| name == "--noproxy"))
        {
            command.arg("--noproxy").arg("");
        }

        // What the user typed, in the order they typed it, after what this
        // driver added — so an option they wrote wins over one of ours by
        // curl's ordinary last-one-wins, and every objection above is about a
        // case where that matters.
        let passthrough = usize::from(leading_disable);
        command.args(&invocation.args[passthrough..]);

        objections.extend(config_file_objection());
        Ok(Launch {
            command,
            objections,
        })
    }
}

/// The options that make curl send a request body, so the session should keep
/// one.
const SENDS_BODY: &[&str] = &[
    "-d",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
    "--json",
];

/// The options whose value is the next argument, for the one question this
/// needs answered about them: *is the next argument a URL, or is it this
/// option's value?*
///
/// **Not a table of curl's options** — curl has hundreds and this has fourteen.
/// It holds the ones whose value could plausibly be mistaken for a URL, which
/// is the only way a wrong answer here can do damage: a target read out of a
/// `-H` value would scope the report to a host nobody asked about and report a
/// clean nothing. An option missing from this list costs at worst an extra host
/// in the scope, and `--only-host` overrides the whole guess anyway.
const TAKES_A_VALUE: &[&str] = &[
    "-d",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--json",
    "-F",
    "--form",
    "--form-string",
    "-H",
    "--header",
    "-e",
    "--referer",
    "-A",
    "--user-agent",
    "-b",
    "--cookie",
    "-o",
    "--output",
    "-x",
    "--proxy",
    "--preproxy",
    "--noproxy",
    "--cacert",
    "-T",
    "--upload-file",
    "--proxy-header",
    "-K",
    "--config",
];

/// Every option name one argument carries.
///
/// One for a long option, and one *per letter* for a short cluster: curl says
/// short options that need no value "can be used immediately next to each
/// other", so `-sSo out` is `-s`, `-S` and `-o`, and a driver that matched the
/// whole string would miss every flag written that way.
//
// cite(curl): "Short version options that do not need any additional values can be used immediately next to each other, like for example you can specify all the options -O, -L and -v at once as -OLv."
fn flag_names(arg: &str) -> impl Iterator<Item = &'static str> + '_ {
    let long = arg
        .starts_with("--")
        .then(|| arg.split('=').next().unwrap_or(arg));
    let short = (!arg.starts_with("--") && arg.starts_with('-') && arg.len() > 1)
        .then(|| arg[1..].chars())
        .into_iter()
        .flatten();
    // Only names this file knows are yielded: an unrecognized option is opaque,
    // and interning every letter of every cluster would be inventing options
    // curl does not have.
    long.into_iter()
        .filter_map(known_long)
        .chain(short.filter_map(known_short))
}

/// The long options this driver knows, resolved to their canonical spelling.
fn known_long(name: &str) -> Option<&'static str> {
    KNOWN.iter().find(|known| **known == name).copied()
}

/// The short options this driver knows.
fn known_short(letter: char) -> Option<&'static str> {
    KNOWN
        .iter()
        .find(|known| known.len() == 2 && known.as_bytes()[1] as char == letter)
        .copied()
}

/// Every option name this driver reacts to, in any capacity.
const KNOWN: &[&str] = &[
    "-d",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--json",
    "-F",
    "--form",
    "--form-string",
    "-T",
    "--upload-file",
    "-H",
    "--header",
    "-e",
    "--referer",
    "-A",
    "--user-agent",
    "-b",
    "--cookie",
    "-o",
    "--output",
    "-k",
    "--insecure",
    "-x",
    "--proxy",
    "--preproxy",
    "--noproxy",
    "--cacert",
    "--proxy-header",
    "-K",
    "--config",
    "--http3",
    "--http3-only",
    "--url",
];

/// The value written into an argument, when there is one: `--data=x`.
///
/// cite(curl): "If the long option name ends with an equals sign ("="), the argument is the text following on its right side. (Added in 8.16.0)"
fn value_of(arg: &str) -> Option<&str> {
    arg.starts_with("--")
        .then(|| arg.split_once('=').map(|(_, value)| value))
        .flatten()
}

/// Does this argument name a URL?
///
/// Stricter than curl, on purpose. curl treats any argument that is not an
/// option and not an option's value as a URL; this requires a scheme, because
/// the cost of the two mistakes is not symmetric. Missing a target widens the
/// report to every host, which is what `run --` does anyway. *Inventing* one
/// scopes the report to a host nobody asked about, and a scoped-away report is
/// a clean report — the failure this tool exists to not produce.
//
// cite(curl): "If provided text does not start with a dash, it is presumed to be and treated as a URL."
fn is_url(arg: &str) -> bool {
    let Some((scheme, _)) = arg.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// What one curl option does to a report, when it does something.
fn objection(name: &str, value: Option<&str>) -> Option<Objection> {
    match name {
        // Verification off means every TLS finding is about a connection
        // nothing checked.
        //
        // cite(curl): "(TLS SFTP SCP) By default, every secure connection curl makes is verified to be secure before the transfer takes place. This option makes curl skip the verification step and proceed without checking."
        "-k" | "--insecure" => Some(Objection::Warn(
            "--insecure makes curl skip certificate verification, so nothing this session \
             reports about TLS means anything (the session already supplies its own CA \
             through --cacert)"
                .to_string(),
        )),
        // There is one proxy this session can report on.
        //
        // cite(curl): "Use the specified proxy."
        "-x" | "--proxy" => Some(Objection::Refuse(
            "--proxy sends curl somewhere other than this session's proxy, which would \
             leave nothing to report; drop it, or use `lint-http run --` to set the \
             environment and let curl choose"
                .to_string(),
        )),
        // An empty list is the documented way to *undo* a `no_proxy`, and is
        // what this driver passes itself; anything else names hosts that will
        // go unseen.
        //
        // cite(curl): "Comma-separated list of hosts for which not to use a proxy, if one is specified. The only wildcard is a single "*" character, which matches all hosts, and effectively disables the proxy."
        "--noproxy" if value != Some("") => Some(Objection::Warn(
            "--noproxy names hosts curl will reach without a proxy; traffic to them is not \
             in this report"
                .to_string(),
        )),
        // A SOCKS hop in front of the session's proxy still arrives, so this is
        // not a refusal — but a failure to get through it looks like a quiet
        // session rather than an error.
        //
        // cite(curl): "Use the specified SOCKS proxy before connecting to an HTTP or HTTPS --proxy. In such a case curl first connects to the SOCKS proxy and then connects (through SOCKS) to the HTTP or HTTPS proxy. Hence pre proxy."
        "--preproxy" => Some(Objection::Warn(
            "--preproxy puts a SOCKS hop in front of this session's proxy; if it does not \
             carry the connection through, the session reports nothing rather than failing"
                .to_string(),
        )),
        // A session binds no QUIC listener — `h3_listen` is forced off, because
        // a session has one child and one moment — so there is nothing here to
        // speak HTTP/3 to. curl's own fallback is what keeps this a warning.
        //
        // cite(curl): "(HTTP) Attempt HTTP/3 to the host in the URL, but fallback to earlier HTTP versions if the HTTP/3 connection establishment fails or is slow. HTTP/3 is only available for HTTPS and not for HTTP URLs."
        "--http3" => Some(Objection::Warn(
            "--http3 asks for a protocol this session does not listen for; the transfer \
             falls back, so the report is about the version it fell back to"
                .to_string(),
        )),
        // Same, without the fallback that made it survivable.
        //
        // cite(curl): "Use --http3-only for similar functionality without a fallback."
        "--http3-only" => Some(Objection::Refuse(
            "--http3-only leaves curl no version to fall back to, and this session listens \
             for none of it; the transfer would not happen"
                .to_string(),
        )),
        // Last one wins, and the user's is last — so theirs replaces the trust
        // bundle that holds this session's CA.
        //
        // cite(curl): "curl recognizes the environment variable named 'CURL_CA_BUNDLE' if it is set and the TLS backend is not Schannel, and uses the given path as a path to a CA cert bundle. This option overrides that variable."
        "--cacert" => Some(Objection::Warn(
            "--cacert replaces the trust bundle this session supplies, so HTTPS through the \
             session proxy will fail to verify unless that file holds the session CA"
                .to_string(),
        )),
        _ => None,
    }
}

/// A default config file that names something this session cares about.
///
/// The trap: curl reads one whether or not anything on the command line says
/// so, and the manual states no precedence between it and the command line — so
/// this may only look and report, never correct. It reports the *word*, not a
/// parse: a `.curlrc` mentioning `insecure` is worth a sentence whether it is
/// an option, a value or a comment, because either way it is the file to read
/// when the report surprises someone.
///
/// cite(curl): "When curl is invoked, it (unless --disable is used) checks for a default config file and uses it if found, even when --config is used."
fn config_file_objection() -> Option<Objection> {
    objection_for_config(&config_file_path()?)
}

/// The same question about a named file, so it can be asked of one that was put
/// there on purpose. Finding the file and reading it are separate problems and
/// only the first depends on where a user's home is.
fn objection_for_config(path: &Path) -> Option<Objection> {
    let contents = std::fs::read_to_string(path).ok()?;
    let named: Vec<&str> = ["insecure", "proxy", "http3", "cacert"]
        .into_iter()
        .filter(|word| {
            contents
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token.eq_ignore_ascii_case(word))
        })
        .collect();
    (!named.is_empty()).then(|| {
        Objection::Warn(format!(
            "{} names {} and curl reads it whichever options are on the command line; \
             options this session cannot see may be in force (curl -q ignores it)",
            path.display(),
            named.join(", ")
        ))
    })
}

/// Where curl looks for its default config file, in its own order.
///
/// The Windows locations are not here: this looks in order to warn, and warning
/// about the wrong file is worse than not warning. The three that are here are
/// the ones a `$HOME` answers for.
///
/// cite(curl): "The default config file is checked for in the following places in this order:"
/// cite(curl): "1) "$CURL_HOME/.curlrc" 2) "$XDG_CONFIG_HOME/curlrc" (Added in 7.73.0) 3) "$HOME/.curlrc""
fn config_file_path() -> Option<PathBuf> {
    let candidates = [
        (std::env::var_os("CURL_HOME"), ".curlrc"),
        (std::env::var_os("XDG_CONFIG_HOME"), "curlrc"),
        (std::env::var_os("HOME"), ".curlrc"),
    ];
    candidates.into_iter().find_map(|(dir, name)| {
        let path = PathBuf::from(dir?).join(name);
        path.is_file().then_some(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(args: &[&str]) -> Invocation {
        Curl.inspect(&args.iter().map(|a| (*a).to_string()).collect::<Vec<_>>())
    }

    /// **The passthrough promise.** An option this driver has never heard of
    /// reaches curl byte-identical, and raises nothing.
    #[test]
    fn an_option_this_does_not_know_reaches_curl_unchanged() {
        let typed = [
            "--tlsv1.3",
            "--compressed",
            "--retry",
            "3",
            "-sS",
            "https://example.com/",
        ];
        let invocation = inspect(&typed);
        assert_eq!(invocation.args, typed);
        assert!(
            invocation.objections.is_empty(),
            "{:?}",
            invocation.objections
        );
    }

    /// The scope comes from the command line, and *every* URL on it — scoping
    /// to the first would drop the second silently.
    #[test]
    fn every_url_on_the_line_is_a_target() {
        let invocation = inspect(&["-sS", "https://example.com/", "https://www.iana.org/"]);
        assert_eq!(
            invocation.targets,
            ["https://example.com/", "https://www.iana.org/"]
        );
    }

    /// A URL sitting in an option's value is that option's value.
    ///
    /// This is the mistake that would scope a report to a host nobody asked
    /// about and then report it clean, so it is the one worth a table.
    #[test]
    fn a_url_that_is_an_options_value_is_not_a_target() {
        for typed in [
            vec![
                "-H",
                "Referer: https://cdn.other.net/",
                "https://example.com/",
            ],
            vec!["-d", "next=https://cdn.other.net/", "https://example.com/"],
            vec!["-o", "https://not-a-file", "https://example.com/"],
            vec!["-e", "https://cdn.other.net/", "https://example.com/"],
        ] {
            assert_eq!(
                inspect(&typed).targets,
                ["https://example.com/"],
                "{typed:?}"
            );
        }
    }

    /// `--url` names one whatever it looks like, because it says so.
    #[test]
    fn an_explicit_url_option_names_a_target() {
        assert_eq!(
            inspect(&["--url", "example.com/x"]).targets,
            ["example.com/x"]
        );
    }

    /// A bare host is not read as a target. curl would treat it as a URL; this
    /// would rather widen the report than scope it to a guess.
    #[test]
    fn a_target_without_a_scheme_is_not_guessed_at() {
        assert!(inspect(&["example.com"]).targets.is_empty());
    }

    /// Asking for a body is what puts one in a kept capture.
    #[test]
    fn an_invocation_that_sends_a_body_says_so() {
        for typed in [
            vec!["-d", "@order.json", "https://api/orders"],
            vec!["--data-binary", "@x", "https://api/"],
            vec!["--json", "{}", "https://api/"],
            vec!["-F", "file=@x", "https://api/"],
            vec!["-T", "x", "https://api/"],
            vec!["--data-urlencode", "a=b", "https://api/"],
        ] {
            assert!(inspect(&typed).sends_body, "{typed:?}");
        }
        assert!(!inspect(&["-sS", "https://api/"]).sends_body);
    }

    /// A short option written inside a cluster is still that option.
    #[test]
    fn a_clustered_short_option_is_still_read() {
        assert!(inspect(&["-sSd", "a=b", "https://api/"]).sends_body);
        assert!(matches!(
            inspect(&["-sSk", "https://api/"]).objections[..],
            [Objection::Warn(_)]
        ));
    }

    /// The four that would make the report a lie, and which of them stop it.
    #[test]
    fn the_options_that_defeat_linting_are_objected_to() {
        assert!(matches!(
            inspect(&["-k", "https://x/"]).objections[..],
            [Objection::Warn(_)]
        ));
        assert!(matches!(
            inspect(&["-x", "http://someone-else:8080", "https://x/"]).objections[..],
            [Objection::Refuse(_)]
        ));
        assert!(matches!(
            inspect(&["--http3", "https://x/"]).objections[..],
            [Objection::Warn(_)]
        ));
        assert!(matches!(
            inspect(&["--http3-only", "https://x/"]).objections[..],
            [Objection::Refuse(_)]
        ));
        assert!(matches!(
            inspect(&["--noproxy", "example.com", "https://x/"]).objections[..],
            [Objection::Warn(_)]
        ));
        // The empty list is what this driver passes itself, and is no objection.
        assert!(inspect(&["--noproxy", "", "https://x/"])
            .objections
            .is_empty());
    }

    fn rendered(args: &[&str], bundle: Option<&std::path::Path>) -> Vec<String> {
        let tool = Tool {
            path: PathBuf::from("/usr/bin/curl"),
            name: "curl".to_string(),
        };
        let invocation = inspect(args);
        let at = Target {
            addr: "127.0.0.1:9111".parse().unwrap(),
            trust_bundle: bundle,
            spki_pin: None,
            scratch: std::path::Path::new("/tmp"),
        };
        Curl.command(&tool, &invocation, &at)
            .unwrap()
            .command
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// curl is told where the proxy is and what to trust, on its own terms.
    #[test]
    fn the_session_is_written_onto_the_command_line() {
        let args = rendered(
            &["-sS", "https://example.com/"],
            Some(std::path::Path::new("/t/b.crt")),
        );
        assert_eq!(&args[..2], ["--proxy", "http://127.0.0.1:9111"]);
        assert!(args.windows(2).any(|w| w == ["--cacert", "/t/b.crt"]));
        // And what the user typed follows, unchanged and in order.
        assert_eq!(&args[args.len() - 2..], ["-sS", "https://example.com/"]);
    }

    /// The one that ends the silently-empty run: an exported `NO_PROXY` cannot
    /// take this session's traffic away from it.
    #[test]
    fn an_environment_that_disables_proxies_is_overridden() {
        let args = rendered(&["https://example.com/"], None);
        let at = args
            .iter()
            .position(|a| a == "--noproxy")
            .expect("the override is passed");
        assert_eq!(args[at + 1], "", "the list must be empty to override");
    }

    /// Unless the user wrote their own list, which is an instruction rather
    /// than a default to fill in.
    #[test]
    fn a_list_the_user_wrote_is_left_alone() {
        let args = rendered(&["--noproxy", "internal.example", "https://x/"], None);
        assert_eq!(
            args.iter().filter(|a| *a == "--noproxy").count(),
            1,
            "the driver must not add a second list: {args:?}"
        );
    }

    /// `-q` works where it is written and nowhere else, so it stays first.
    #[test]
    fn a_leading_disable_stays_leading() {
        let args = rendered(&["-q", "-sS", "https://example.com/"], None);
        assert_eq!(args.first().map(String::as_str), Some("-q"));
        assert_eq!(
            args.iter().filter(|a| *a == "-q").count(),
            1,
            "and is not also passed through a second time: {args:?}"
        );
    }

    /// A `-q` that is not first is not doing anything, and is passed through as
    /// written rather than promoted into meaning something.
    #[test]
    fn a_disable_written_late_is_left_where_it_was() {
        let args = rendered(&["-sS", "-q", "https://example.com/"], None);
        assert_ne!(args.first().map(String::as_str), Some("-q"));
        assert_eq!(
            &args[args.len() - 3..],
            ["-sS", "-q", "https://example.com/"]
        );
    }

    /// A session with no CA cannot verify anything, and says so.
    #[test]
    fn a_session_without_a_trust_bundle_says_so() {
        let tool = Tool {
            path: PathBuf::from("/usr/bin/curl"),
            name: "curl".to_string(),
        };
        let at = Target {
            addr: "127.0.0.1:9111".parse().unwrap(),
            trust_bundle: None,
            spki_pin: None,
            scratch: std::path::Path::new("/tmp"),
        };
        let launch = Curl.command(&tool, &Invocation::default(), &at).unwrap();
        assert!(launch
            .objections
            .iter()
            .any(|o| o.message().contains("fail to verify")));
    }

    /// A transfer is not a sitting, and stdout is the transfer's.
    #[test]
    fn a_transfer_streams_nothing_and_keeps_its_stdout() {
        assert!(!Curl.interactive());
        assert!(
            !Curl.json_to_stdout(),
            "stdout is where the response body goes"
        );
    }

    /// A path is the executable; a name is looked up; neither invents one.
    #[test]
    fn the_executable_is_the_one_named() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("lint-http-curl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("curl");
        std::fs::write(&path, b"#!/bin/sh\n")?;

        let tool = Curl.locate(Some(&path.to_string_lossy()))?;
        assert_eq!(tool.path, path);
        assert_eq!(tool.name, "curl");

        let missing = dir.join("not-here").display().to_string();
        let Err(err) = Curl.locate(Some(&missing)) else {
            panic!("a path that is not there is not an executable");
        };
        assert!(err.to_string().contains("not-here"), "{err}");

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    /// The two that do not stop a session but change what part of it means.
    #[test]
    fn the_options_that_bend_a_session_are_warned_about() {
        assert!(matches!(
            inspect(&["--preproxy", "socks5://localhost:1080", "https://x/"]).objections[..],
            [Objection::Warn(_)]
        ));
        assert!(matches!(
            inspect(&["--cacert", "/etc/other.pem", "https://x/"]).objections[..],
            [Objection::Warn(_)]
        ));
    }

    /// **The trap this driver can only look at.** A config file naming one of
    /// the settings that change what a finding means is worth a sentence, and
    /// the sentence names the file so it can be read.
    #[test]
    fn a_config_file_that_names_a_setting_is_reported() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("lint-http-curlrc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir)?;

        let loud = dir.join("loud");
        std::fs::write(&loud, "silent\ninsecure\nconnect-timeout = 5\n")?;
        let objection = objection_for_config(&loud).expect("insecure is worth saying");
        assert!(objection.message().contains("insecure"), "{objection:?}");
        assert!(
            objection.message().contains(&loud.display().to_string()),
            "the file has to be named: {objection:?}"
        );

        // A file with nothing this session cares about is not worth a line, and
        // neither is a file that is not there.
        let quiet = dir.join("quiet");
        std::fs::write(&quiet, "silent\nconnect-timeout = 5\n")?;
        assert!(objection_for_config(&quiet).is_none());
        assert!(objection_for_config(&dir.join("absent")).is_none());

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn a_scheme_is_what_makes_an_argument_a_url() {
        assert!(is_url("https://example.com/"));
        assert!(is_url("http://[::1]:8080/"));
        assert!(!is_url("example.com"));
        assert!(!is_url("a=https://example.com"));
        assert!(!is_url("://example.com"));
        assert!(!is_url("-x"));
    }
}
