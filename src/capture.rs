// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Request/response capture writing to JSONL format.

use serde::Serialize;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use hyper::header::HeaderMap;

const DEFAULT_PATH: &str = "captures.jsonl";

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
        let p = path
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_PATH.to_string());
        let file = ArcFile::new(&p).await?;
        Ok(Self { file })
    }

    /// Write a capture record to the JSONL file
    pub async fn write_capture(&self, builder: CaptureRecordBuilder<'_>) -> anyhow::Result<()> {
        let record = builder.build();
        let line = serde_json::to_string(&record)?;
        self.file.write_line(&line).await?;
        Ok(())
    }
}

/// Builder for creating capture records with optional fields
pub struct CaptureRecordBuilder<'a> {
    method: &'a str,
    uri: &'a str,
    status: u16,
    request_headers: &'a HeaderMap,
    response_headers: Option<&'a HeaderMap>,
    duration_ms: u64,
    violations: Vec<crate::lint::Violation>,
}

impl<'a> CaptureRecordBuilder<'a> {
    /// Create a new capture record builder with required fields
    pub fn new(
        method: &'a str,
        uri: &'a str,
        status: u16,
        request_headers: &'a HeaderMap,
    ) -> Self {
        Self {
            method,
            uri,
            status,
            request_headers,
            response_headers: None,
            duration_ms: 0,
            violations: Vec::new(),
        }
    }

    /// Add response headers to the capture
    pub fn response_headers(mut self, headers: &'a HeaderMap) -> Self {
        self.response_headers = Some(headers);
        self
    }

    /// Set the request duration in milliseconds
    pub fn duration_ms(mut self, duration: u64) -> Self {
        self.duration_ms = duration;
        self
    }

    /// Add lint violations to the capture
    pub fn violations(mut self, violations: Vec<crate::lint::Violation>) -> Self {
        self.violations = violations;
        self
    }

    /// Build the capture record (internal - generates ID and timestamp)
    fn build(self) -> CaptureRecord {
        CaptureRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: self.method.to_string(),
            uri: self.uri.to_string(),
            status: self.status,
            duration_ms: self.duration_ms,
            request_headers: headers_to_map(self.request_headers),
            response_headers: self.response_headers.map(headers_to_map),
            violations: self.violations,
        }
    }
}

fn headers_to_map(h: &HeaderMap) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    for (k, v) in h.iter() {
        if let Ok(s) = v.to_str() {
            m.insert(k.as_str().to_string(), s.to_string());
        }
    }
    m
}

#[derive(Serialize)]
struct CaptureRecord {
    id: String,
    timestamp: String,
    method: String,
    uri: String,
    status: u16,
    duration_ms: u64,
    request_headers: std::collections::HashMap<String, String>,
    response_headers: Option<std::collections::HashMap<String, String>>,
    violations: Vec<crate::lint::Violation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use serde_json::Value;
    use tokio::fs;
    use uuid::Uuid;

    #[test]
    fn headers_to_map_basic() {
        let mut hm = HeaderMap::new();
        hm.insert("content-type", "text/plain".parse().unwrap());
        let m = headers_to_map(&hm);
        assert_eq!(
            m.get("content-type").map(|s| s.as_str()),
            Some("text/plain")
        );
    }

    #[tokio::test]
    async fn write_capture_writes_jsonl() {
        let tmp =
            std::env::temp_dir().join(format!("lint_capture_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();

        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse().unwrap());

        let violations = vec![crate::lint::Violation {
            rule: "r1".into(),
            severity: "warn".into(),
            message: "m".into(),
        }];

        // Use builder pattern
        cw.write_capture(
            CaptureRecordBuilder::new("GET", "http://example/", 200, &req_headers)
                .duration_ms(10)
                .violations(violations)
        )
        .await
        .expect("write capture");

        let s = fs::read_to_string(&tmp).await.expect("read file");
        let v: Value = serde_json::from_str(s.trim()).expect("parse jsonl");
        assert_eq!(v["method"].as_str().unwrap(), "GET");
        assert_eq!(v["uri"].as_str().unwrap(), "http://example/");
        assert_eq!(v["status"].as_u64().unwrap(), 200);
        assert!(v["request_headers"].get("x-test").is_some());

        let _ = fs::remove_file(&tmp).await;
    }
}
