// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Request/response capture writing to JSONL format.

use base64::Engine;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct CaptureWriter {
    file: ArcFile,
    /// Whether to include captured bodies in the serialized output
    pub include_body: bool,
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
    pub async fn new<P: Into<PathBuf>>(path: P, include_body: bool) -> anyhow::Result<Self> {
        let path: PathBuf = path.into();
        let p = path.to_string_lossy().to_string();
        let file = ArcFile::new(&p).await?;
        Ok(Self { file, include_body })
    }

    /// Write a transaction to the JSONL file
    pub async fn write_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
    ) -> anyhow::Result<()> {
        // Convert transaction to a mutable JSON value to optionally insert the
        // captured bodies (base64 encoded) when `include_body` is enabled.
        let mut v = serde_json::to_value(tx)?;

        if self.include_body {
            if let Some(obj) = v.as_object_mut() {
                // request body: if present as skipped field it won't be in `v` by default
                if let Some(req_obj) = obj.get_mut("request").and_then(|r| r.as_object_mut()) {
                    // If original transaction had a body (it is skipped by default),
                    // try to fetch it directly from the original `tx` and insert as base64
                    if let Some(b) = &tx.request_body {
                        req_obj.insert(
                            "body".to_string(),
                            serde_json::Value::String(
                                base64::engine::general_purpose::STANDARD.encode(b),
                            ),
                        );
                    }
                }
                if let Some(resp_val) = obj.get_mut("response") {
                    if resp_val.is_object() {
                        if let Some(resp_obj) = resp_val.as_object_mut() {
                            if let Some(_r) = &tx.response {
                                if let Some(b) = &tx.response_body {
                                    resp_obj.insert(
                                        "body".to_string(),
                                        serde_json::Value::String(
                                            base64::engine::general_purpose::STANDARD.encode(b),
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Ensure body fields are not present in serialized output (defensive)
            if let Some(obj) = v.as_object_mut() {
                if let Some(req_obj) = obj.get_mut("request").and_then(|r| r.as_object_mut()) {
                    req_obj.remove("body");
                }
                if let Some(resp_val) = obj.get_mut("response") {
                    if resp_val.is_object() {
                        if let Some(resp_obj) = resp_val.as_object_mut() {
                            resp_obj.remove("body");
                        }
                    }
                }
            }
        }

        let line = serde_json::to_string(&v)?;
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
        if !line.trim().is_empty() {
            match serde_json::from_str::<crate::http_transaction::HttpTransaction>(&line) {
                Ok(record) => records.push(record),
                Err(e) => {
                    tracing::warn!(line = line_num, error = %e, "failed to parse capture record, skipping");
                }
            }
        } else {
            tracing::debug!(line = line_num, "skipping empty/whitespace capture line");
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

        let cw = CaptureWriter::new(p.clone(), false).await?;

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
    async fn write_transaction_includes_bodies_when_enabled() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_capture_bodies_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("temp path not utf8"))?
            .to_string();

        // Create writer that includes bodies
        let cw = CaptureWriter::new(p.clone(), true).await?;

        use crate::test_helpers::make_test_transaction_with_response;
        let mut tx = make_test_transaction_with_response(
            400,
            &[("content-type", "application/problem+json")],
        );
        tx.request_body = Some(bytes::Bytes::from_static(b"req-body"));
        tx.request.body_length = Some(8);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 400,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "application/problem+json",
            )]),
            body_length: Some(13),
        });
        tx.response_body = Some(bytes::Bytes::from_static(b"{\"type\":\"x\"}"));

        cw.write_transaction(&tx).await?;

        let s = fs::read_to_string(&tmp).await?;
        let v: Value = serde_json::from_str(s.trim())?;
        // request body should be base64 string
        assert!(v["request"]["body"].is_string());
        let req_b64 = v["request"]["body"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(req_b64)?,
            b"req-body"
        );
        // response body should be base64 string
        assert!(v["response"]["body"].is_string());
        let resp_b64 = v["response"]["body"].as_str().unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD.decode(resp_b64)?,
            b"{\"type\":\"x\"}"
        );

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
        let cw = CaptureWriter::new(p.clone(), false).await?;

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
        let mut tx2 = make_test_transaction_with_response(201, [("user", "u2")].as_ref());
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
    async fn load_captures_skips_empty_lines() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_empty_lines_test_{}.jsonl", Uuid::new_v4()));

        // Write a valid record, then an empty line, then another valid record
        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let tx1 = make_test_transaction();
        let tx2 = make_test_transaction_with_response(202, &[("x", "y")]);
        let content = format!(
            "{}\n\n{}\n",
            serde_json::to_string(&tx1)?,
            serde_json::to_string(&tx2)?
        );
        fs::write(&tmp, content).await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].response.as_ref().unwrap().status, 202);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_skips_whitespace_lines() -> anyhow::Result<()> {
        let tmp = std::env::temp_dir().join(format!("lint_ws_test_{}.jsonl", Uuid::new_v4()));

        use crate::test_helpers::{make_test_transaction, make_test_transaction_with_response};
        let tx1 = make_test_transaction();
        let tx2 = make_test_transaction_with_response(202, &[("x", "y")]);
        let content = format!(
            "{}\n   \n{}\n",
            serde_json::to_string(&tx1)?,
            serde_json::to_string(&tx2)?
        );
        fs::write(&tmp, content).await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request.method, "GET");
        assert_eq!(records[1].response.as_ref().unwrap().status, 202);

        fs::remove_file(&tmp).await?;
        Ok(())
    }

    #[tokio::test]
    async fn load_captures_blank_line_returns_empty() -> anyhow::Result<()> {
        let tmp =
            std::env::temp_dir().join(format!("lint_blank_line_test_{}.jsonl", Uuid::new_v4()));
        // Single blank line should be ignored
        fs::write(&tmp, "\n").await?;

        let records = load_captures(&tmp).await?;
        assert_eq!(records.len(), 0);

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

    #[tokio::test]
    async fn capture_new_with_directory_errors() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("lint_capture_dir_{}", Uuid::new_v4()));
        tokio::fs::create_dir(&dir).await?;
        let res = CaptureWriter::new(dir.clone(), false).await;
        assert!(res.is_err());
        tokio::fs::remove_dir(&dir).await?;
        Ok(())
    }
}
