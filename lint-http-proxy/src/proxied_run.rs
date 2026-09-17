// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! One command, run against a proxy that exists only for it.
//!
//! The question this answers: *how does an arbitrary program get linted without
//! anyone configuring anything?* The proxy already lints everything that
//! crosses it, so nothing here knows about rules — the whole job is to stand a
//! proxy up on a port nobody chose, tell the child where it is, and take it
//! down again with the captures flushed.
//!
//! **Nothing outlives the run.** The CA is generated into a temporary directory
//! and deleted with it, so wrapping a command never leaves an interception CA
//! on the machine and never asks anyone to install one. That is the reason a
//! fresh CA per run is right rather than merely acceptable: the child is handed
//! the certificate directly, so the CA has no reason to persist, and a CA that
//! does not persist cannot be used against the machine later.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::capture::{self, CaptureRecord, CaptureWriter};
use crate::client_env;
use crate::config::Config;
use crate::proxy;

/// A temporary directory that is removed when the run ends, however it ends.
///
/// The same ownership argument the test guard makes, for the same reason: the
/// paths are handed out in one place and cleaned up in another, and every path
/// between them runs through `?`.
struct RunDir(PathBuf);

impl RunDir {
    /// Create it private to this user.
    ///
    /// `0700`, and that is load-bearing rather than tidy: the directory holds
    /// `ca.key`, the private key of a CA the child is being told to trust, and
    /// it lives in a directory every local user can write. The default `0755`
    /// from `create_dir_all` would let any of them read that key while the run
    /// is in flight and mint certificates the wrapped process would accept.
    /// The mode goes on the directory rather than the file because the file is
    /// written by `ca.rs`, which cannot know it is being used this way.
    fn new() -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(format!("lint-http-run-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path)?;
        Ok(Self(path))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        // Best-effort: a run that cannot clean up its own temp directory has
        // nothing useful to say about it, and saying it would land on top of
        // the report the user is actually reading.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a wrapped run produced: how the child ended, and what crossed the proxy
/// while it ran.
#[derive(Debug)]
pub struct WrappedRun {
    /// The child's exit code, or `None` when a signal ended it.
    pub exit_code: Option<i32>,
    /// Every capture record the run committed, in the order they were written.
    pub records: Vec<CaptureRecord>,
    /// Where the captures were written, when the caller asked to keep them.
    pub captures_path: Option<PathBuf>,
}

/// Run `program` with `args` against a private proxy, and return what crossed
/// it.
///
/// `cfg` supplies the rule table and transport policy; the listen address, the
/// captures path and the CA paths in it are overridden, because all three are
/// this function's to choose. `keep_captures` names a file to write them to
/// instead of the temporary one — the only thing a run can leave behind, and
/// only when asked.
pub async fn run_proxied(
    mut cfg: Config,
    program: &str,
    args: &[String],
    keep_captures: Option<&Path>,
) -> anyhow::Result<WrappedRun> {
    let dir = RunDir::new()?;

    // Port zero, and the address is read back rather than assumed: the whole
    // point is not to collide with whatever else the developer is running, and
    // a fixed port would be a fixed way to fail on a busy machine.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr: SocketAddr = listener.local_addr()?;

    let captures_path = match keep_captures {
        Some(path) => path.to_path_buf(),
        None => dir.join("captures.jsonl"),
    };

    cfg.general.listen = addr.to_string();
    cfg.general.captures = captures_path.display().to_string();
    // A per-run CA in the temp directory. Overridden even when the config names
    // paths: a config's `ca.crt` is the long-lived CA a `proxy-start` session
    // wants, and reusing it here would persist exactly what this command exists
    // not to persist.
    let ca_cert = dir.join("ca.crt");
    let ca_key = dir.join("ca.key");
    // What the child is pointed at is not the CA but a bundle containing it —
    // see `write_trust_bundle`.
    let trust_bundle = dir.join("trust-bundle.crt");
    cfg.tls.ca_cert_path = Some(ca_cert.display().to_string());
    cfg.tls.ca_key_path = Some(ca_key.display().to_string());

    // HTTP/3 listening is a long-running proxy's feature and needs a second
    // bound socket; a wrapped run has one child and one moment, so it is off
    // regardless of what the config says. Upstream H3 is untouched — that is
    // the origin-facing leg and costs the child nothing.
    cfg.general.h3_listen = None;

    let tls_enabled = cfg.tls.enabled;
    if !tls_enabled {
        warn!(
            "TLS interception is disabled in this configuration: HTTPS will be tunnelled unlinted"
        );
    }

    // The capture file is opened for append, so a `--captures` path reused
    // across runs already holds earlier runs' records. Count them now and skip
    // exactly that many afterwards, or every run reports the whole history and
    // a `--fail-on` gate trips on traffic from a run that already passed.
    let carried_over = capture::load_capture_records(&captures_path)
        .await
        .map(|existing| existing.len())
        .unwrap_or(0);

    let cfg = Arc::new(cfg);
    let writer = CaptureWriter::new(
        cfg.general.captures.clone(),
        cfg.general.captures_include_body,
    )
    .await?;

    let shutdown = CancellationToken::new();
    let proxy_task = tokio::spawn({
        let cfg = Arc::clone(&cfg);
        let shutdown = shutdown.clone();
        async move { proxy::run_proxy_with_shutdown(listener, writer, cfg, shutdown).await }
    });

    // The CA file has to exist before the child is told to trust it. It is
    // written during proxy startup, so the child cannot be spawned until it
    // appears — a child that reads `SSL_CERT_FILE` at startup and finds nothing
    // there fails to verify anything, which reads as a broken proxy rather than
    // a race.
    let ca_for_child = if tls_enabled {
        wait_for_trust_bundle(&ca_cert, &trust_bundle).await
    } else {
        None
    };

    // Ctrl-C reaches the child through the terminal's process group, and it
    // reaches this process too — where, without this, it would end the run by
    // killing it, and `RunDir`'s cleanup would never run. That would leave
    // `ca.key` behind permanently, which is the one thing this command promises
    // not to do. Racing the signal against the child lets the ordinary path
    // finish: cancel the proxy, drop the directory, report what there was.
    let status = tokio::select! {
        status = spawn_child(program, args, addr, ca_for_child.as_deref()) => status,
        _ = tokio::signal::ctrl_c() => {
            // The child received the same signal from the terminal; give it a
            // moment to end on its own before tearing the proxy down under it.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Err(anyhow::anyhow!("interrupted"))
        }
    };

    // The child is gone; stop accepting and let the shutdown sequence drain
    // handlers and flush the captures. The report is read from that file, so
    // awaiting this is what makes it complete rather than nearly complete.
    shutdown.cancel();
    match proxy_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %e, "proxy ended with an error"),
        Err(e) => warn!(error = %e, "proxy task did not join cleanly"),
    }

    // The child's own failure is reported after the proxy is down, so a command
    // that could not start still leaves a tidy machine behind.
    let status = status?;

    let mut records = capture::load_capture_records(&captures_path).await?;
    // Only what this run produced. `drain` rather than a slice so the records
    // stay owned, and `min` because a file that shrank under us (a truncation
    // between the two reads) must not panic the run.
    let skip = carried_over.min(records.len());
    records.drain(..skip);

    Ok(WrappedRun {
        exit_code: status.code(),
        records,
        captures_path: keep_captures.map(|p| p.to_path_buf()),
    })
}

/// Spawn the child with the proxy variables added to its environment.
///
/// Everything else about the environment is inherited, and stdin, stdout and
/// stderr are the parent's: a wrapper that swallowed the wrapped command's
/// output would not be one.
async fn spawn_child(
    program: &str,
    args: &[String],
    addr: SocketAddr,
    ca_path: Option<&Path>,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut command = tokio::process::Command::new(program);
    command.args(args);
    for (name, value) in client_env::client_env(addr, ca_path) {
        command.env(name, value);
    }
    let status = command.status().await.map_err(|e| {
        // The overwhelmingly common failure is a typo'd or missing program, and
        // the raw io error names neither the program nor the fact that this is
        // the *child* failing rather than the proxy.
        anyhow::anyhow!("failed to run `{program}`: {e}")
    })?;
    Ok(status)
}

/// Wait for the proxy to write its CA, then hand back a bundle the child can
/// trust *without losing the trust it already had*.
///
/// Returns `None` if the CA never appears, which downgrades the run to
/// routing-only rather than pointing the child at a file that is not there.
/// Generating a P-256 CA takes microseconds; the bound is for the case where
/// startup failed altogether, and in that case the run is about to report
/// nothing anyway.
async fn wait_for_trust_bundle(ca_path: &Path, bundle_path: &Path) -> Option<PathBuf> {
    let ca_pem = wait_for_ca_pem(ca_path).await?;
    match write_trust_bundle(bundle_path, &ca_pem) {
        Ok(()) => Some(bundle_path.to_path_buf()),
        Err(e) => {
            warn!(error = %e, "could not build the trust bundle; the child will not trust intercepted TLS");
            None
        }
    }
}

/// Read the CA once it is completely written.
///
/// Existence is not enough. `ca.rs` writes the certificate with `fs::write`,
/// which truncates before it writes, so a file can be observed at zero length
/// or half a PEM block. The end marker is the cheap proof that the whole thing
/// landed — a child handed a truncated bundle fails to verify anything, which
/// reads as a broken proxy rather than as a race.
async fn wait_for_ca_pem(path: &Path) -> Option<String> {
    const END: &str = "-----END CERTIFICATE-----";
    for _ in 0..100 {
        if let Ok(pem) = tokio::fs::read_to_string(path).await {
            if pem.contains(END) {
                return Some(pem);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    warn!(path = %path.display(), "CA certificate never appeared; the child will not trust intercepted TLS");
    None
}

/// Write the per-run CA followed by every platform root certificate.
///
/// **The platform roots are the point.** Each variable in the trust half of the
/// table names a file that *replaces* the child's default trust, it does not
/// add to it — so a bundle holding only the interception CA silently breaks
/// every TLS connection the proxy is not intercepting: a passthrough domain, a
/// host excluded by a pre-set `NO_PROXY`, and anything that is not HTTP at all,
/// such as the database connection a wrapped test suite opens. Wrapping a
/// command must not make it trust *less* than it did unwrapped.
fn write_trust_bundle(dest: &Path, ca_pem: &str) -> anyhow::Result<()> {
    let mut bundle = ca_pem.to_string();
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }

    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        warn!(errors = ?loaded.errors, "errors loading platform certificates for the child's trust bundle");
    }
    // A machine with no platform roots is not a reason to fail the run: the
    // child still needs the interception CA, and it is no worse off than it
    // would have been. It is worth saying out loud, though, because everything
    // the proxy does not intercept is about to stop verifying.
    if loaded.certs.is_empty() {
        warn!("no platform root certificates found; the child will trust only the interception CA");
    }
    for cert in &loaded.certs {
        bundle.push_str(&pem_encode_certificate(cert));
    }

    std::fs::write(dest, bundle)?;
    Ok(())
}

/// DER to a PEM certificate block, 64 characters to the line.
fn pem_encode_certificate(der: &[u8]) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        // The chunks are ASCII base64 by construction.
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin() -> Config {
        Config::load_builtin().expect("built-in config parses")
    }

    /// The wrapper is a wrapper: the child's exit code is the run's, and a
    /// non-zero one is data rather than an error.
    #[tokio::test]
    async fn child_exit_code_comes_back() -> anyhow::Result<()> {
        let run = run_proxied(
            builtin(),
            "sh",
            &["-c".to_string(), "exit 7".to_string()],
            None,
        )
        .await?;
        assert_eq!(run.exit_code, Some(7));
        assert!(run.records.is_empty());
        Ok(())
    }

    /// The child really does receive the table, and the routing rows really do
    /// point at the ephemeral port — checked by having the child print one.
    #[tokio::test]
    async fn child_environment_carries_the_proxy() -> anyhow::Result<()> {
        let out = std::env::temp_dir().join(format!("lint-http-env-{}", uuid::Uuid::new_v4()));
        let run = run_proxied(
            builtin(),
            "sh",
            &[
                "-c".to_string(),
                format!(
                    "printf '%s\\n%s\\n' \"$https_proxy\" \"$SSL_CERT_FILE\" > {}",
                    out.display()
                ),
            ],
            None,
        )
        .await?;
        assert_eq!(run.exit_code, Some(0));

        let seen = std::fs::read_to_string(&out)?;
        let _ = std::fs::remove_file(&out);
        let mut lines = seen.lines();
        let proxy = lines.next().unwrap_or_default();
        let ca = lines.next().unwrap_or_default();

        assert!(
            proxy.starts_with("http://127.0.0.1:"),
            "https_proxy was {proxy:?}"
        );
        assert_ne!(
            proxy, "http://127.0.0.1:0",
            "the ephemeral port leaked as 0"
        );
        // The bundle, not the bare CA — see `write_trust_bundle`.
        assert!(ca.ends_with("trust-bundle.crt"), "SSL_CERT_FILE was {ca:?}");
        Ok(())
    }

    /// A command that does not exist is the child's failure, and the message
    /// says which program could not be run.
    #[tokio::test]
    async fn a_missing_program_names_itself() {
        let err = run_proxied(builtin(), "lint-http-no-such-program", &[], None)
            .await
            .expect_err("a missing program is an error");
        let msg = err.to_string();
        assert!(
            msg.contains("lint-http-no-such-program"),
            "message was {msg:?}"
        );
    }

    /// A reused `--captures` path accumulates records, and the report must
    /// still be about *this* run. Two runs over the same file, and the second
    /// must not re-report the first's traffic — a gate that tripped on a
    /// previous run's findings would never go green again.
    #[tokio::test]
    async fn a_reused_capture_file_does_not_re_report_earlier_runs() -> anyhow::Result<()> {
        let caps =
            std::env::temp_dir().join(format!("lint-http-caps-{}.jsonl", uuid::Uuid::new_v4()));
        // Seed the file with a record no run of ours produced.
        std::fs::write(
            &caps,
            format!(
                "{}\n",
                serde_json::to_string(&crate::capture::CaptureEnvelope {
                    schema_version: crate::capture::CAPTURE_SCHEMA_VERSION,
                    record: crate::capture::CaptureRecord::HttpTransaction(Box::new(
                        lint_http_core::test_helpers::make_test_transaction_with_response(200, &[])
                    )),
                })?
            ),
        )?;

        let run = run_proxied(builtin(), "true", &[], Some(&caps)).await?;
        let _ = std::fs::remove_file(&caps);
        assert!(
            run.records.is_empty(),
            "the seeded record was re-reported as this run's: {} record(s)",
            run.records.len()
        );
        Ok(())
    }

    /// The bundle handed to the child holds the platform roots as well as the
    /// interception CA. A bundle of one replaces the child's trust rather than
    /// extending it, so everything the proxy does not intercept — a passthrough
    /// domain, a non-HTTP TLS connection — stops verifying.
    #[tokio::test]
    async fn the_child_keeps_the_trust_it_arrived_with() -> anyhow::Result<()> {
        let out = std::env::temp_dir().join(format!("lint-http-bundle-{}", uuid::Uuid::new_v4()));
        let run = run_proxied(
            builtin(),
            "sh",
            &[
                "-c".to_string(),
                format!(
                    "grep -c 'BEGIN CERTIFICATE' \"$SSL_CERT_FILE\" > {}",
                    out.display()
                ),
            ],
            None,
        )
        .await?;
        assert_eq!(run.exit_code, Some(0));

        let count: usize = std::fs::read_to_string(&out)?.trim().parse()?;
        let _ = std::fs::remove_file(&out);
        assert!(
            count > 1,
            "the child's bundle held {count} certificate(s) — the platform roots are missing"
        );
        Ok(())
    }

    /// The per-run CA is gone once the run returns.
    ///
    /// Asked of *this* run's CA rather than by counting temp directories: the
    /// tests in a binary run concurrently, so a count sees every other run's
    /// directory too and answers a question nobody asked. The child reports the
    /// path it was told to trust, and that exact path is what must not survive.
    #[tokio::test]
    async fn the_per_run_ca_does_not_survive_the_run() -> anyhow::Result<()> {
        let out = std::env::temp_dir().join(format!("lint-http-ca-{}", uuid::Uuid::new_v4()));
        let run = run_proxied(
            builtin(),
            "sh",
            &[
                "-c".to_string(),
                format!("printf '%s' \"$SSL_CERT_FILE\" > {}", out.display()),
            ],
            None,
        )
        .await?;
        assert_eq!(run.exit_code, Some(0));

        let ca_path = std::fs::read_to_string(&out)?;
        let _ = std::fs::remove_file(&out);
        assert!(!ca_path.is_empty(), "the child was given no CA to trust");
        assert!(
            !std::path::Path::new(&ca_path).exists(),
            "the trust bundle at {ca_path} outlived the run"
        );
        // The directory that held it goes with it.
        let dir = std::path::Path::new(&ca_path).parent().unwrap();
        assert!(
            !dir.exists(),
            "the run directory {} survived",
            dir.display()
        );
        Ok(())
    }
}
