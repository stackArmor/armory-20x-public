locals {
  okta_common_tags = {
    service = "Okta"
    benchmark = "Okta STIG"
  }
}

benchmark "okta_stig" {
  title       = "Okta STIG"
  description = "This benchmark assesses the compliance of Okta configurations against the Okta STIG. v1-r1"
  tags        = merge(local.okta_common_tags, {
    type = "Benchmark"
  })
  children = [
    control.okta_default_global_session_policy_enforces_15_minute_inactivity_logout,
    control.okta_default_global_session_policy_does_not_use_default_rule_at_priority_1,
    control.okta_global_session_policies_disable_persistent_global_session_cookies_in_priority_1_rules,
    control.okta_password_policies_enforce_lockout_after_3_failed_attempts,
    control.okta_dashboard_authentication_policy_requires_non_phishable_authenticators,
    control.okta_admin_console_authentication_policy_requires_non_phishable_authenticators,
    control.okta_admin_console_requires_multifactor_authentication,
    control.okta_dashboard_requires_multifactor_authentication,
    control.okta_password_policies_require_minimum_password_length_of_15_characters,
    control.okta_password_policies_require_at_least_1_uppercase_character,
    control.okta_password_policies_require_at_least_1_lowercase_character,
    control.okta_password_policies_require_at_least_1_numeric_character,
    control.okta_password_policies_require_at_least_1_special_character,
    control.okta_password_policies_enforce_24_hour_or_greater_minimum_password_lifetime,
    control.okta_password_policies_enforce_60_day_maximum_password_lifetime,
    control.okta_default_global_session_policy_limits_global_session_lifetime_to_18_hours,
    control.okta_password_policies_prevent_common_passwords,
    control.okta_password_policy_prevents_reuse_of_at_least_last_5_passwords,
  ]
}
