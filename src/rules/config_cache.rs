// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Generic configuration caching for rules.
//!
//! This module provides a reusable pattern for rules that need to parse and cache
//! their configuration once at startup, avoiding redundant TOML parsing on every request.
//!
//! # Usage Pattern
//!
//! 1. Define a static cache with your parsed config type:
//!    ```ignore
//!    static CACHED_CONFIG: RuleConfigCache<Vec<String>> = RuleConfigCache::new();
//!    ```
//!
//! 2. In `validate_config`, parse and store the configuration:
//!    ```ignore
//!    fn validate_config(&self, config: &Config) -> anyhow::Result<()> {
//!        let parsed = parse_my_config(config)?;  // Your parsing logic
//!        CACHED_CONFIG.set(parsed);
//!        Ok(())
//!    }
//!    ```
//!
//! 3. In `check_request`/`check_response`, retrieve the cached config:
//!    ```ignore
//!    fn check_response(...) -> Option<Violation> {
//!        let config = CACHED_CONFIG.get_or_init(|| {
//!            panic!("Config not initialized - validate_config should have been called")
//!        });
//!        // Use config...
//!    }
//!    ```
//!
//! # Thread Safety
//!
//! - In production: Uses `OnceLock` for thread-safe, one-time initialization
//! - In tests: Uses `thread_local!` storage to prevent cross-test contamination
//!
//! # Example
//!
//! See `server_clear_site_data.rs` for a complete implementation example.

#[cfg(test)]
use std::marker::PhantomData;
#[cfg(not(test))]
use std::sync::OnceLock;

/// A generic configuration cache that can be used by any rule.
///
/// In production, uses OnceLock for thread-safe one-time initialization.
/// In tests, uses thread-local storage to avoid cross-test contamination.
pub struct RuleConfigCache<T: Clone + Send + Sync + 'static> {
    #[cfg(not(test))]
    cell: OnceLock<T>,
    #[cfg(test)]
    _marker: PhantomData<T>,
}

impl<T: Clone + Send + Sync + 'static> Default for RuleConfigCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + Send + Sync + 'static> RuleConfigCache<T> {
    /// Create a new configuration cache.
    pub const fn new() -> Self {
        Self {
            #[cfg(not(test))]
            cell: OnceLock::new(),
            #[cfg(test)]
            _marker: PhantomData,
        }
    }

    /// Set the cached value. Should be called during validate_config.
    #[cfg(not(test))]
    pub fn set(&self, value: T) {
        self.cell.set(value).ok();
    }

    /// Get the cached value, or initialize it with the provided function.
    /// Should be called during `validate_config` and retrieved during `check_transaction`.
    #[cfg(not(test))]
    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        self.cell.get_or_init(f)
    }
}

// Test implementation uses thread-local storage to avoid cross-test contamination
#[cfg(test)]
thread_local! {
    static TEST_CACHE_REGISTRY: std::cell::RefCell<std::collections::HashMap<usize, Box<dyn std::any::Any>>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

#[cfg(test)]
impl<T: Clone + Send + Sync + 'static> RuleConfigCache<T> {
    /// Get a unique key for this cache instance
    fn key(&self) -> usize {
        self as *const _ as usize
    }

    /// Set the cached value in tests
    pub fn set(&self, value: T) {
        TEST_CACHE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .insert(self.key(), Box::new(Some(value)));
        });
    }

    /// Get the cached value or initialize it in tests
    pub fn get_or_init<F>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        TEST_CACHE_REGISTRY.with(|registry| {
            let mut map = registry.borrow_mut();
            let key = self.key();

            if let Some(boxed) = map.get(&key) {
                if let Some(Some(value)) = boxed.downcast_ref::<Option<T>>() {
                    return value.clone();
                }
            }

            // Not cached yet, initialize it
            let value = f();
            map.insert(key, Box::new(Some(value.clone())));
            value
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_stores_and_retrieves_value() {
        let cache = RuleConfigCache::<Vec<String>>::new();
        let data = vec!["test".to_string()];

        cache.set(data.clone());
        let retrieved = cache.get_or_init(|| panic!("Should not call init"));

        assert_eq!(retrieved, data);
    }

    #[test]
    fn cache_initializes_if_not_set() {
        let cache = RuleConfigCache::<i32>::new();
        let value = cache.get_or_init(|| 42);

        assert_eq!(value, 42);
    }

    #[test]
    fn different_caches_are_independent() {
        let cache1 = RuleConfigCache::<String>::new();
        let cache2 = RuleConfigCache::<String>::new();

        cache1.set("cache1".to_string());
        cache2.set("cache2".to_string());

        assert_eq!(cache1.get_or_init(|| "wrong".to_string()), "cache1");
        assert_eq!(cache2.get_or_init(|| "wrong".to_string()), "cache2");
    }

    #[test]
    fn cache_key_uniqueness() {
        let cache1 = RuleConfigCache::<i32>::new();
        let cache2 = RuleConfigCache::<i32>::new();

        assert_ne!(cache1.key(), cache2.key());
    }

    #[test]
    fn default_works_same_as_new() {
        let cache = RuleConfigCache::<i32>::default();
        let value = cache.get_or_init(|| 7);
        assert_eq!(value, 7);
    }
}
