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

    #[allow(clippy::too_many_arguments)]
    pub async fn write_capture(
        &self,
        method: &str,
        uri: &str,
        status: u16,
        resp_headers: Option<&HeaderMap>,
        duration_ms: u64,
        request_headers: &HeaderMap,
        violations: Vec<crate::lint::Violation>,
    ) -> anyhow::Result<()> {
        let id = Uuid::new_v4().to_string();
        let rec = CaptureRecord {
            id: id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: method.to_string(),
            uri: uri.to_string(),
            status,
            duration_ms,
            request_headers: headers_to_map(request_headers),
            response_headers: resp_headers.map(headers_to_map),
            violations,
        };

        let line = serde_json::to_string(&rec)?;
        self.file.write_line(&line).await?;
        Ok(())
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
            std::env::temp_dir().join(format!("patina_capture_test_{}.jsonl", Uuid::new_v4()));
        let p = tmp.to_str().unwrap().to_string();

        let cw = CaptureWriter::new(p.clone()).await.expect("create writer");

        let mut req_headers = HeaderMap::new();
        req_headers.insert("x-test", "1".parse().unwrap());

        let violations = vec![crate::lint::Violation {
            rule: "r1".into(),
            severity: "warn".into(),
            message: "m".into(),
        }];

        cw.write_capture(
            "GET",
            "http://example/",
            200,
            None,
            10,
            &req_headers,
            violations,
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
