// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

/// Standard configuration for rules
/// Used as the Config type for non-configurable rules.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
}

/// Parse severity from config for a given rule.
/// Returns RuleConfig with parsed severity. Fails if severity is not explicitly configured.
pub fn parse_rule_config(cfg: &crate::config::Config, rule_id: &str) -> anyhow::Result<RuleConfig> {
    let severity = get_rule_severity_required(cfg, rule_id)?;
    let enabled = get_rule_enabled_required(cfg, rule_id)?;
    Ok(RuleConfig { enabled, severity })
}

/// The `Rule` trait defines a single hook that runs on the canonical
/// `HttpTransaction`. All rules must implement `check_transaction`.
/// Scope of a rule: whether it applies to client-only traffic (requests),
/// server-only traffic (responses), or both (full transactions).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RuleScope {
    Client,
    Server,
    Both,
}

pub trait Rule: Send + Sync {
    /// The type of parsed configuration this rule requires.
    /// Use `RuleConfig` for rules that only need severity.
    type Config: Send + Sync + 'static;

    fn id(&self) -> &'static str;

    /// Validate and parse the rule's configuration. Called once at startup.
    /// Returns the parsed configuration object or an error if invalid.
    /// For rules using `RuleConfig`, this method has a default implementation.
    /// Rules with custom configurations must override this method.
    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<Arc<dyn Any + Send + Sync>> {
        // Default implementation for rules using RuleConfig (only severity)
        let config = parse_rule_config(config, self.id())?;
        Ok(Arc::new(config))
    }

    /// The scope where the rule should be executed. Default is `Both` for
    /// backward compatibility; rules may override for better precision.
    fn scope(&self) -> RuleScope {
        RuleScope::Both
    }

    /// Evaluate an entire `HttpTransaction` and return an optional violation.
    /// The `config` parameter contains the validated configuration.
    fn check_transaction(
        &self,
        _tx: &crate::http_transaction::HttpTransaction,
        _previous: Option<&crate::http_transaction::HttpTransaction>,
        _config: &Self::Config,
    ) -> Option<Violation>;
}

/// Helper trait to enable type-erased configuration caching.
/// Automatically implemented for all Rule implementations.
/// This trait exists to work around the fact that Rule has an associated type
/// which prevents using dyn Rule directly in RULES array.
pub trait RuleConfigValidator: Send + Sync {
    fn id(&self) -> &'static str;
    fn scope(&self) -> RuleScope;
    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<Arc<dyn Any + Send + Sync>>;

    fn check_transaction_erased(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        config: &crate::config::Config,
        engine: &RuleConfigEngine,
    ) -> Option<Violation>;
}

impl<T: Rule> RuleConfigValidator for T {
    fn id(&self) -> &'static str {
        <Self as Rule>::id(self)
    }

    fn scope(&self) -> RuleScope {
        <Self as Rule>::scope(self)
    }

    fn validate_and_box(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<Arc<dyn Any + Send + Sync>> {
        <Self as Rule>::validate_and_box(self, config)
    }

    fn check_transaction_erased(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        previous: Option<&crate::http_transaction::HttpTransaction>,
        _config: &crate::config::Config,
        engine: &RuleConfigEngine,
    ) -> Option<Violation> {
        let config = engine.get_cached::<T::Config>(self.id());
        self.check_transaction(tx, previous, &config)
    }
}

/// Engine that caches parsed rule configurations.
/// Stores type-erased parsed configs in a HashMap keyed by rule ID.
#[derive(Debug, Default)]
pub struct RuleConfigEngine {
    cache: HashMap<&'static str, Arc<dyn Any + Send + Sync>>,
}

impl RuleConfigEngine {
    /// Create a new empty config engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate and cache configurations for all enabled rules.
    /// Should be called once at startup after loading config.
    pub fn validate_and_cache_all(&mut self, config: &crate::config::Config) -> anyhow::Result<()> {
        for rule in RULES {
            if config.is_enabled(rule.id()) {
                let boxed = rule.validate_and_box(config).map_err(|e| {
                    anyhow::anyhow!("Invalid configuration for rule '{}': {}", rule.id(), e)
                })?;
                self.cache.insert(rule.id(), boxed);
            }
        }
        Ok(())
    }

    /// Retrieve the cached parsed config for a rule.
    /// Panics if the rule hasn't been validated/cached - this is a programming error.
    pub fn get_cached<T: Send + Sync + 'static>(&self, rule_id: &'static str) -> Arc<T> {
        self.cache
            .get(rule_id)
            .and_then(|arc| arc.clone().downcast::<T>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "Rule '{}' config not found in cache. This is a bug - validate_and_cache_all must be called for all enabled rules before linting.",
                    rule_id
                )
            })
    }
}

/// Get rule enabled flag, failing if not explicitly configured.
/// All rules must have an explicit enabled field.
pub fn get_rule_enabled_required(cfg: &crate::config::Config, rule: &str) -> anyhow::Result<bool> {
    let Some(rule_cfg) = cfg.get_rule_config(rule) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing configuration. Add:\n[rules.{}]\nenabled = true\nseverity = \"warn\"",
            rule, rule
        ));
    };
    let Some(table) = rule_cfg.as_table() else {
        return Err(anyhow::anyhow!(
            "Rule '{}' configuration must be a table",
            rule
        ));
    };
    let Some(enabled) = table.get("enabled").and_then(|v| v.as_bool()) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing required 'enabled' field. Must be true or false",
            rule
        ));
    };
    Ok(enabled)
}

/// Lookup the configured severity for a rule at runtime,
/// Get rule severity, failing if not explicitly configured.
/// All enabled rules must have an explicit severity field.
pub fn get_rule_severity_required(
    cfg: &crate::config::Config,
    rule: &str,
) -> anyhow::Result<crate::lint::Severity> {
    let Some(rule_cfg) = cfg.get_rule_config(rule) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' is enabled but missing configuration. Add:\n[rules.{}]\nenabled = true\nseverity = \"warn\"",
            rule, rule
        ));
    };
    let Some(table) = rule_cfg.as_table() else {
        return Err(anyhow::anyhow!(
            "Rule '{}' configuration must be a table",
            rule
        ));
    };
    let Some(s) = table.get("severity").and_then(|v| v.as_str()) else {
        return Err(anyhow::anyhow!(
            "Rule '{}' missing required 'severity' field. Must be one of: info, warn, error",
            rule
        ));
    };
    match s {
        "info" => Ok(crate::lint::Severity::Info),
        "warn" => Ok(crate::lint::Severity::Warn),
        "error" => Ok(crate::lint::Severity::Error),
        _ => Err(anyhow::anyhow!(
            "Rule '{}' has invalid severity '{}'. Must be one of: info, warn, error",
            rule,
            s
        )),
    }
}

pub fn validate_rules(config: &crate::config::Config) -> anyhow::Result<RuleConfigEngine> {
    // Ensure every rule table specifies valid `enabled` and `severity` entries.
    for (rule_name, val) in &config.rules {
        if let toml::Value::Table(table) = val {
            // Validate `enabled` field - must be present and be a boolean
            match table.get("enabled") {
                Some(toml::Value::Boolean(_)) => {}
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "Invalid 'enabled' for rule '{}': must be a boolean (true or false)",
                        rule_name
                    ));
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing required 'enabled' key for rule '{}'",
                        rule_name
                    ));
                }
            }

            // Validate `severity` field - must be present and be a valid string
            match table.get("severity") {
                Some(toml::Value::String(s)) => match s.as_str() {
                    "info" | "warn" | "error" => {}
                    _ => {
                        return Err(anyhow::anyhow!(
                                "Invalid severity '{}' for rule '{}': must be one of 'info', 'warn', 'error'",
                                s,
                                rule_name
                            ));
                    }
                },
                Some(_) => {
                    return Err(anyhow::anyhow!(
                        "Invalid severity for rule '{}': must be a string 'info', 'warn', or 'error'",
                        rule_name
                    ));
                }
                None => {
                    return Err(anyhow::anyhow!(
                        "Missing required 'severity' key for rule '{}'",
                        rule_name
                    ));
                }
            }
        }
    }

    let mut engine = RuleConfigEngine::new();
    engine.validate_and_cache_all(config)?;
    Ok(engine)
}

pub mod client_accept_encoding_present;
pub mod client_cache_respect;
pub mod client_expect_header_valid;
pub mod client_host_header;
pub mod client_range_header_syntax_valid;
pub mod client_request_method_token_uppercase;
pub mod client_request_origin_header_present_for_cors;
pub mod client_request_target_form_checks;
pub mod client_request_target_no_fragment;
pub mod client_request_uri_percent_encoding_valid;
pub mod client_user_agent_present;
pub mod message_accept_and_content_type_negotiation;
pub mod message_accept_encoding_parameter_validity;
pub mod message_accept_header_media_type_syntax;
pub mod message_accept_language_weight_validity;
pub mod message_accept_ranges_and_206_consistency;
pub mod message_access_control_allow_credentials_when_origin;
pub mod message_access_control_allow_origin_valid;
pub mod message_age_header_numeric;
pub mod message_allow_header_method_tokens;
pub mod message_auth_scheme_iana_registered;
pub mod message_authorization_credentials_present;
pub mod message_cache_control_token_valid;
pub mod message_charset_iana_registered;
pub mod message_conditional_headers_consistency;
pub mod message_connection_header_tokens_valid;
pub mod message_connection_upgrade;
pub mod message_content_disposition_parameter_validity;
pub mod message_content_disposition_token_valid;
pub mod message_content_encoding_and_type_consistency;
pub mod message_content_encoding_iana_registered;
pub mod message_content_length;
pub mod message_content_length_vs_transfer_encoding;
pub mod message_content_transfer_encoding_valid;
pub mod message_content_type_iana_registered;
pub mod message_content_type_well_formed;
pub mod message_cookie_attribute_consistency;
pub mod message_cross_origin_embedder_policy_valid;
pub mod message_cross_origin_opener_policy_valid;
pub mod message_cross_origin_resource_policy_valid;
pub mod message_date_and_time_headers_consistency;
pub mod message_digest_header_syntax;
pub mod message_early_data_header_safe_method;
pub mod message_etag_syntax;
pub mod message_extension_headers_registered;
pub mod message_forwarded_header_validity;
pub mod message_from_header_email_syntax;
pub mod message_header_field_names_token;
pub mod message_http_version_syntax_valid;
pub mod message_if_match_etag_syntax;
pub mod message_if_modified_since_date_format;
pub mod message_if_none_match_etag_syntax;
pub mod message_if_unmodified_since_date_format;
pub mod message_language_tag_format_valid;
pub mod message_link_header_validity;
pub mod message_max_forwards_numeric;
pub mod message_media_type_suffix_validity;
pub mod message_multipart_boundary_syntax;
pub mod message_pragma_token_valid;
pub mod message_prefer_header_valid;
pub mod message_preference_applied_header_valid;
pub mod message_priority_header_syntax;
pub mod message_range_and_content_range_consistency;
pub mod message_referer_uri_valid;
pub mod message_retry_after_date_or_delay;
pub mod message_sec_fetch_dest_value_valid;
pub mod message_sec_fetch_mode_value_valid;
pub mod message_sec_fetch_site_value_valid;
pub mod message_sec_fetch_user_value_valid;
pub mod message_server_header_product_valid;
pub mod message_te_header_constraints;
pub mod message_trailer_headers_valid;
pub mod message_transfer_coding_iana_registered;
pub mod message_transfer_encoding_chunked_final;
pub mod message_user_agent_token_valid;
pub mod message_via_header_syntax_valid;
pub mod message_warning_header_syntax;
pub mod message_www_authenticate_challenge_syntax;
pub mod server_accept_ranges_values_valid;
pub mod server_alt_svc_header_syntax;
pub mod server_cache_control_present;
pub mod server_charset_specification;
pub mod server_clear_site_data;
pub mod server_content_type_present;
pub mod server_deprecation_header_syntax;
pub mod server_etag_or_last_modified;
pub mod server_last_modified_rfc1123_format;
pub mod server_location_header_uri_valid;
pub mod server_must_revalidate_and_immutable_mismatch;
pub mod server_no_body_for_1xx_204_304;
pub mod server_patch_accept_patch_header;
pub mod server_problem_details_content_type;
pub mod server_response_405_allow;
pub mod server_response_location_on_redirect;
pub mod server_server_timing_header_syntax;
pub mod server_status_code_valid_range;
pub mod server_vary_header_valid;
pub mod server_x_content_type_options;
pub mod server_x_frame_options_value_valid;
pub mod server_x_xss_protection_value_valid;

pub const RULES: &[&dyn RuleConfigValidator] = &[
    &server_cache_control_present::ServerCacheControlPresent,
    &server_must_revalidate_and_immutable_mismatch::ServerMustRevalidateAndImmutableMismatch,
    &server_etag_or_last_modified::ServerEtagOrLastModified,
    &server_last_modified_rfc1123_format::ServerLastModifiedRfc1123Format,
    &server_location_header_uri_valid::ServerLocationHeaderUriValid,
    &server_response_location_on_redirect::ServerResponseLocationOnRedirect,
    &server_x_content_type_options::ServerXContentTypeOptions,
    &server_x_frame_options_value_valid::ServerXFrameOptionsValueValid,
    &server_x_xss_protection_value_valid::ServerXXssProtectionValueValid,
    &server_response_405_allow::ServerResponse405Allow,
    &server_clear_site_data::ServerClearSiteData,
    &server_no_body_for_1xx_204_304::ServerNoBodyFor1xx204304,
    &client_user_agent_present::ClientUserAgentPresent,
    &client_accept_encoding_present::ClientAcceptEncodingPresent,
    &client_cache_respect::ClientCacheRespect,
    &client_host_header::ClientHostHeader,
    &client_request_target_no_fragment::ClientRequestTargetNoFragment,
    &client_request_target_form_checks::ClientRequestTargetFormChecks,
    &client_request_uri_percent_encoding_valid::ClientRequestUriPercentEncodingValid,
    &client_range_header_syntax_valid::ClientRangeHeaderSyntaxValid,
    &server_accept_ranges_values_valid::ServerAcceptRangesValuesValid,
    &server_vary_header_valid::ServerVaryHeaderValid,
    &server_patch_accept_patch_header::ServerPatchAcceptPatchHeader,
    &server_server_timing_header_syntax::ServerServerTimingHeaderSyntax,
    &server_deprecation_header_syntax::ServerDeprecationHeaderSyntax,
    &server_alt_svc_header_syntax::ServerAltSvcHeaderSyntax,
    &server_problem_details_content_type::ServerProblemDetailsContentType,
    &client_request_method_token_uppercase::ClientRequestMethodTokenUppercase,
    &client_request_origin_header_present_for_cors::ClientRequestOriginHeaderPresentForCors,
    &client_expect_header_valid::ClientExpectHeaderValid,
    &message_content_length_vs_transfer_encoding::MessageContentLengthVsTransferEncoding,
    &message_content_length::MessageContentLength,
    &message_range_and_content_range_consistency::MessageRangeAndContentRangeConsistency,
    &message_accept_ranges_and_206_consistency::MessageAcceptRangesAnd206Consistency,
    &message_header_field_names_token::MessageHeaderFieldNamesToken,
    &message_extension_headers_registered::MessageExtensionHeadersRegistered,
    &message_transfer_encoding_chunked_final::MessageTransferEncodingChunkedFinal,
    &message_connection_header_tokens_valid::MessageConnectionHeaderTokensValid,
    &server_content_type_present::ServerContentTypePresent,
    &message_content_type_well_formed::MessageContentTypeWellFormed,
    &message_content_type_iana_registered::MessageContentTypeIanaRegistered,
    &message_media_type_suffix_validity::MessageMediaTypeSuffixValidity,
    &message_charset_iana_registered::MessageCharsetIanaRegistered,
    &message_multipart_boundary_syntax::MessageMultipartBoundarySyntax,
    &message_content_disposition_token_valid::MessageContentDispositionTokenValid,
    &message_content_disposition_parameter_validity::MessageContentDispositionParameterValidity,
    &message_accept_header_media_type_syntax::MessageAcceptHeaderMediaTypeSyntax,
    &message_accept_and_content_type_negotiation::MessageAcceptAndContentTypeNegotiation,
    &message_language_tag_format_valid::MessageLanguageTagFormatValid,
    &message_early_data_header_safe_method::MessageEarlyDataHeaderSafeMethod,
    &message_user_agent_token_valid::MessageUserAgentTokenValid,
    &message_sec_fetch_site_value_valid::MessageSecFetchSiteValueValid,
    &message_sec_fetch_mode_value_valid::MessageSecFetchModeValueValid,
    &message_sec_fetch_user_value_valid::MessageSecFetchUserValueValid,
    &message_server_header_product_valid::MessageServerHeaderProductValid,
    &message_digest_header_syntax::MessageDigestHeaderSyntax,
    &message_warning_header_syntax::MessageWarningHeaderSyntax,
    &message_www_authenticate_challenge_syntax::MessageWwwAuthenticateChallengeSyntax,
    &message_authorization_credentials_present::MessageAuthorizationCredentialsPresent,
    &message_auth_scheme_iana_registered::MessageAuthSchemeIanaRegistered,
    &message_cookie_attribute_consistency::MessageCookieAttributeConsistency,
    &message_etag_syntax::MessageEtagSyntax,
    &message_if_match_etag_syntax::MessageIfMatchEtagSyntax,
    &message_if_none_match_etag_syntax::MessageIfNoneMatchEtagSyntax,
    &message_if_modified_since_date_format::MessageIfModifiedSinceDateFormat,
    &message_if_unmodified_since_date_format::MessageIfUnmodifiedSinceDateFormat,
    &message_conditional_headers_consistency::MessageConditionalHeadersConsistency,
    &message_date_and_time_headers_consistency::MessageDateAndTimeHeadersConsistency,
    &message_connection_upgrade::MessageConnectionUpgrade,
    &message_content_encoding_iana_registered::MessageContentEncodingIanaRegistered,
    &message_content_encoding_and_type_consistency::MessageContentEncodingAndTypeConsistency,
    &message_accept_encoding_parameter_validity::MessageAcceptEncodingParameterValidity,
    &message_accept_language_weight_validity::MessageAcceptLanguageWeightValidity,
    &message_content_transfer_encoding_valid::MessageContentTransferEncodingValid,
    &message_transfer_coding_iana_registered::MessageTransferCodingIanaRegistered,
    &message_te_header_constraints::MessageTeHeaderConstraints,
    &message_trailer_headers_valid::MessageTrailerHeadersValid,
    &message_retry_after_date_or_delay::MessageRetryAfterDateOrDelay,
    &message_sec_fetch_dest_value_valid::MessageSecFetchDestValueValid,
    &message_priority_header_syntax::MessagePriorityHeaderSyntax,
    &message_prefer_header_valid::MessagePreferHeaderValid,
    &message_cache_control_token_valid::MessageCacheControlTokenValid,
    &message_pragma_token_valid::MessagePragmaTokenValid,
    &message_preference_applied_header_valid::MessagePreferenceAppliedHeaderValid,
    &message_max_forwards_numeric::MessageMaxForwardsNumeric,
    &message_age_header_numeric::MessageAgeHeaderNumeric,
    &message_allow_header_method_tokens::MessageAllowHeaderMethodTokens,
    &message_via_header_syntax_valid::MessageViaHeaderSyntaxValid,
    &message_forwarded_header_validity::MessageForwardedHeaderValidity,
    &message_access_control_allow_credentials_when_origin::MessageAccessControlAllowCredentialsWhenOrigin,
    &message_access_control_allow_origin_valid::MessageAccessControlAllowOriginValid,
    &message_cross_origin_opener_policy_valid::MessageCrossOriginOpenerPolicyValid,
    &message_cross_origin_resource_policy_valid::MessageCrossOriginResourcePolicyValid,
    &message_cross_origin_embedder_policy_valid::MessageCrossOriginEmbedderPolicyValid,
    &message_referer_uri_valid::MessageRefererUriValid,
    &message_link_header_validity::MessageLinkHeaderValidity,
    &message_from_header_email_syntax::MessageFromHeaderEmailSyntax,
    &message_http_version_syntax_valid::MessageHttpVersionSyntaxValid,
    &server_status_code_valid_range::ServerStatusCodeValidRange,
    &server_charset_specification::ServerCharsetSpecification,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{enable_rule, enable_rule_with_paths};

    #[test]
    fn rule_ids_unique_and_non_empty() {
        let mut ids = std::collections::HashSet::new();
        for rule in RULES {
            let id = rule.id();
            assert!(!id.is_empty(), "Rule id should not be empty");
            assert!(ids.insert(id), "Duplicate rule id found: {}", id);
        }
    }

    #[test]
    fn validate_rules_ok_when_enabled_rule_has_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // server_cache_control_present doesn't require config; enabling should pass
        enable_rule(&mut cfg, "server_cache_control_present");
        // server_clear_site_data requires paths; enable with valid paths too
        enable_rule_with_paths(&mut cfg, "server_clear_site_data", &["/logout"]);
        let _engine = validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn config_example_includes_all_rules() -> anyhow::Result<()> {
        let s = std::fs::read_to_string("config_example.toml")?;

        for rule in RULES {
            let id = rule.id();
            let marker = format!("[rules.{}]", id);
            assert!(
                s.contains(&marker),
                "config_example.toml missing example for rule '{}'",
                id
            );
        }

        Ok(())
    }

    #[test]
    fn validate_rules_errors_on_invalid_rule_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        // Enable server_clear_site_data but with invalid empty paths
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("paths".to_string(), toml::Value::Array(vec![]));
        cfg.rules.insert(
            "server_clear_site_data".to_string(),
            toml::Value::Table(table),
        );

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("server_clear_site_data"));
        Ok(())
    }

    #[test]
    #[should_panic(expected = "config not found in cache")]
    fn test_get_cached_missing_panics() {
        let engine = RuleConfigEngine::new();
        let _: std::sync::Arc<RuleConfig> = engine.get_cached("nonexistent_rule");
    }

    #[test]
    fn rule_config_engine_validate_and_cache_for_new_rule() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_forwarded_header_validity");
        let mut engine = RuleConfigEngine::new();
        engine.validate_and_cache_all(&cfg)?;
        let cfg_obj: Arc<RuleConfig> = engine.get_cached("message_forwarded_header_validity");
        assert!(cfg_obj.enabled);
        Ok(())
    }

    #[test]
    fn test_validate_rules_invalid_severity() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("critical".into()),
        );
        cfg.rules
            .insert("test_rule".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid severity"));
    }

    #[test]
    fn get_rule_enabled_required_not_table_errors() {
        let mut cfg = crate::config::Config::default();
        // Put a non-table value for the rule
        cfg.rules
            .insert("test_rule_nt".into(), toml::Value::String("oops".into()));

        let res = get_rule_enabled_required(&cfg, "test_rule_nt");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("configuration must be a table"));
    }

    #[test]
    fn get_rule_severity_required_missing_or_not_string_errors() {
        let mut cfg = crate::config::Config::default();

        // Missing severity
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("test_rule_no_sev".into(), toml::Value::Table(table.clone()));

        let res = get_rule_severity_required(&cfg, "test_rule_no_sev");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing required 'severity'"));

        // Severity present but not a string
        let mut table2 = table;
        table2.insert("severity".to_string(), toml::Value::Integer(1));
        cfg.rules
            .insert("test_rule_bad_sev".into(), toml::Value::Table(table2));

        let res2 = get_rule_severity_required(&cfg, "test_rule_bad_sev");
        assert!(res2.is_err());
        assert!(res2
            .unwrap_err()
            .to_string()
            .contains("missing required 'severity'"));
    }

    #[test]
    fn validate_rules_enabled_not_bool_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Integer(1));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("r_enabled_bad".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Invalid 'enabled'"));
    }

    #[test]
    fn validate_rules_missing_enabled_key_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("r_missing_enabled".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required 'enabled' key"));
    }

    #[test]
    fn validate_rules_severity_not_string_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::Integer(1));
        cfg.rules
            .insert("r_sev_not_string".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("must be a string"));
    }

    #[test]
    fn validate_rules_missing_severity_key_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules
            .insert("r_missing_sev".into(), toml::Value::Table(table));

        let res = validate_rules(&cfg);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Missing required 'severity' key"));
    }
    #[test]
    fn default_rule_scope_is_both() {
        struct DummyRule;
        impl Rule for DummyRule {
            type Config = RuleConfig;

            fn id(&self) -> &'static str {
                "dummy_rule"
            }

            fn check_transaction(
                &self,
                _tx: &crate::http_transaction::HttpTransaction,
                _previous: Option<&crate::http_transaction::HttpTransaction>,
                _config: &Self::Config,
            ) -> Option<Violation> {
                None
            }
        }

        let r = DummyRule;
        // Direct call to default implementation (disambiguate trait method)
        assert_eq!(crate::rules::Rule::scope(&r), RuleScope::Both);

        // Also verify through the type-erased validator trait
        let v: &dyn RuleConfigValidator = &r;
        assert_eq!(v.scope(), RuleScope::Both);
    }

    #[test]
    fn parse_rule_config_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules.insert(
            "server_cache_control_present".into(),
            toml::Value::Table(table),
        );

        let rc = parse_rule_config(&cfg, "server_cache_control_present")?;
        assert!(rc.enabled);
        assert_eq!(rc.severity, crate::lint::Severity::Warn);
        Ok(())
    }

    #[test]
    fn validate_and_cache_all_get_cached_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("error".into()));
        cfg.rules.insert(
            "server_cache_control_present".into(),
            toml::Value::Table(table),
        );

        let mut engine = RuleConfigEngine::new();
        engine.validate_and_cache_all(&cfg)?;
        let rc: std::sync::Arc<RuleConfig> = engine.get_cached("server_cache_control_present");
        assert_eq!(rc.severity, crate::lint::Severity::Error);
        Ok(())
    }

    #[test]
    fn get_rule_enabled_and_severity_required_success() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("test_rule".into(), toml::Value::Table(table));

        let enabled = get_rule_enabled_required(&cfg, "test_rule")?;
        assert!(enabled);

        let sev = get_rule_severity_required(&cfg, "test_rule")?;
        assert_eq!(sev, crate::lint::Severity::Warn);
        Ok(())
    }

    #[test]
    fn get_rule_severity_required_invalid_string_errors() {
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert(
            "severity".to_string(),
            toml::Value::String("critical".into()),
        );
        cfg.rules
            .insert("test_rule_invalid".into(), toml::Value::Table(table));

        let res = get_rule_severity_required(&cfg, "test_rule_invalid");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid severity"));
    }

    #[test]
    fn get_rule_enabled_required_missing_config_errors() {
        let cfg = crate::config::Config::default();
        let res = get_rule_enabled_required(&cfg, "nope");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("missing configuration"));
    }
}
