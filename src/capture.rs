// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Request/response capture writing to JSONL format.

use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct CaptureWriter {
    file: ArcFile,
}

#[derive(Clone)]
struct ArcFile {
    inner: std::sync::Arc<Mutex<tokio::fs::File>>,
}

impl ArcFile {
    async fn new(path: &str) -> anyhow::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            inner: std::sync::Arc::new(Mutex::new(f)),
        })
    }

    async fn write_line(&self, line: &str) -> anyhow::Result<()> {
        let mut file = self.inner.lock().await;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }
}

impl CaptureWriter {
    pub async fn new<P: Into<PathBuf>>(path: P) -> anyhow::Result<Self> {
        let path: PathBuf = path.into();
        let p = path.to_string_lossy().to_string();
        let file = ArcFile::new(&p).await?;
        Ok(Self { file })
    }

    /// Write a transaction to the JSONL file
    pub async fn write_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
    ) -> anyhow::Result<()> {
        let line = serde_json::to_string(tx)?;
        self.file.write_line(&line).await?;
        Ok(())
    }
}

/// Load capture records from a JSONL file. Skips malformed lines with warnings.
pub async fn load_captures<P: AsRef<std::path::Path>>(
    path: P,
) -> anyhow::Result<Vec<crate::http_transaction::HttpTransaction>> {
    use tokio::io::AsyncBufReadExt;

    let path_ref = path.as_ref();

    if !tokio::fs::try_exists(path_ref).await.unwrap_or(false) {
        return Ok(Vec::new());
    }

    let file = tokio::fs::File::open(path_ref).await?;
    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();
    let mut records = Vec::new();
    let mut line_num = 0;

    while let Some(line) = lines.next_line().await? {
        line_num += 1;
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<crate::http_transaction::HttpTransaction>(&line) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::warn!(line = line_num, error = %e, "failed to parse capture record, skipping");
            }
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use serde_json::Value;
    use tokio::fs;
    use uuid::Uuid;

    #[tokio::test]
    async fn write_transaction_writes_jsonl() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_capture_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        let cw = CaptureWriter::new(p.clone()).await?;

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse()?);

        let violations = vec![crate::lint::Violation {
            rule: "r1".into(),
            severity: crate::lint::Severity::Warn,
            message: "m".into(),
        }];

        // Build a minimal transaction using helper
        use crate::http_transaction::TimingInfo;
        use crate::test_helpers::make_test_transaction;
        let mut tx = make_test_transaction();
        tx.request.headers = req_headers;
        tx.timing = TimingInfo { duration_ms: 10 };
        tx.violations = violations;

        cw.write_transaction(&tx).await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["request"]["method"].as_str(), Some("GET"));
        assert_eq!(v["request"]["uri"].as_str(), Some("http://example/"));
        assert!(v["request"]["headers"].get("x-test").is_some());
        // Ensure severity serialized as lowercase string
        assert_eq!(v["violations"][0]["severity"].as_str(), Some("warn"));

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_reads_jsonl() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_load_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Write some sample transaction records
        let cw = CaptureWriter::new(p.clone()).await?;

        let mut req_headers = HeaderMap::new();
        req_headers.insert("user-agent", "test-client".parse()?);

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("etag", "\"abc123\"".parse()?);

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(200, &[("etag", "\"abc123\"")]);
        tx.request.headers = req_headers;
        // Ensure URI matches test expectation
        tx.request.uri = "http://example/test".to_string();
        tx.timing.duration_ms = 100;

        cw.write_transaction(&tx).await?;

        // Load the captures
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[0].request.uri, "http://example/test");
        assert_eq!(records[0].timing.duration_ms, 100);
        assert!(records[0].response.is_some());

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_malformed_lines() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_malformed_test_{}.jsonl", Uuid::new_v4()));

        // Write a mix of valid and invalid transaction JSON
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let mut tx1 = make_test_transaction();
        let mut tx2 = make_test_transaction_with_response(201, &[("user", "u2")]);
        // Ensure these transactions reflect the test's expectations
        tx1.request.uri = "http://example/".to_string();
        tx2.request.method = "POST".to_string();
        tx2.request.uri = "http://example/post".to_string();

        let content = format!(
            "{}\ninvalid json line\n{}\n",
            serde_json::to_string(&tx1)?,
            serde_json::to_string(&tx2)?
        );
        fs::write(&tmp, content).await?;

        // Should load only the valid records
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].request.method, "POST");

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_empty_file_returns_empty() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_empty_test_{}.jsonl", Uuid::new_v4()));
        fs::write(&tmp, "").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_nonexistent_file_returns_empty() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_nonexistent_{}.jsonl", Uuid::new_v4()));

        // Should not error, just return empty vector
        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);
        Ok(())
    }
}
