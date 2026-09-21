// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The temp-file guard shared by this crate's unit tests and its integration
//! tests. Included by the second through `mod`, by the first through `#[path]`
//! — see the note in `tests/common/mod.rs`. Depends on nothing but `std` and
//! `uuid`, so it can be compiled into either.

#![allow(dead_code)]

use std::path::PathBuf;

/// The temporary files a test was given, removed when the test ends — however
/// it ends.
///
/// **What this replaces was the last statement of each test body**, and each
/// body reaches its end through dozens of `?` and a handful of assertions.
/// None of those paths ran the removals: a test that failed left its capture
/// file and its generated CA behind in the temp directory, and a test that
/// failed is exactly the one somebody then re-runs. The teardown was also
/// copied per test — fourteen times in one file — which is what made it easy
/// to leave a path out of one copy.
///
/// Ownership is the fix. The guard removes what it handed out, and it does so
/// on the way out of the scope, so returning early is not a way to skip it.
#[derive(Default)]
pub struct TempFiles {
    paths: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl TempFiles {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh path in the temp directory, removed when this guard drops.
    ///
    /// The name carries a UUID because the tests in a binary run concurrently,
    /// and two of them naming one file is a race that reads as a flake.
    pub fn path(&mut self, prefix: &str, extension: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("{prefix}_{}.{extension}", uuid::Uuid::new_v4()));
        self.paths.push(path.clone());
        path
    }

    /// A fresh *directory* path, removed with its contents when this guard
    /// drops. Kept apart from the files because the removal differs, and
    /// because a caller that mixes them up should not compile.
    pub fn dir(&mut self, prefix: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("{prefix}_{}", uuid::Uuid::new_v4()));
        self.dirs.push(path.clone());
        path
    }

    /// Take ownership of a path the caller made for itself.
    pub fn keep(&mut self, path: impl Into<PathBuf>) {
        self.paths.push(path.into());
    }
}

impl Drop for TempFiles {
    fn drop(&mut self) {
        // `std::fs`, not `tokio::fs`: a `Drop` cannot await, and this runs on
        // whatever thread the test ended on — including one that is panicking.
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
        for dir in &self.dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
