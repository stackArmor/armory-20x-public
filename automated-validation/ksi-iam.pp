locals {
  all_ksi_iam_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-IAM"
  })
}

benchmark "fedramp20x_ksi_iam" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Identity and Access Management (IAM)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Identity and Access Management (IAM) based on infrastructure state"
    tags        = local.all_ksi_iam_common_tags
    children = [
        benchmark.fedramp20x_ksi_iam_01,
        benchmark.fedramp20x_ksi_iam_02,
        benchmark.fedramp20x_ksi_iam_03,
        benchmark.fedramp20x_ksi_iam_04,
        benchmark.fedramp20x_ksi_iam_05,
        benchmark.fedramp20x_ksi_iam_06,
    ]
}

benchmark "fedramp20x_ksi_iam_01" {
    title       = "KSI-IAM-01 Enforce phishing-resistant MFA for all user authentication."
    description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_01,
        benchmark.okta_fedramp20x_ksi_iam_01,
    ]
    # Needs Okta benchmark; need to utilize checks on Okta policies.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-01"
    })
}

benchmark "fedramp20x_ksi_iam_02" {
    title       = "KSI-IAM-02 Use secure passwordless or strong password + MFA authentication."
    description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_02,
        benchmark.okta_fedramp20x_ksi_iam_02,
        benchmark.googledirectory_fedramp20x_ksi_iam_02,
    ]
    # This needs an Okta benchmark; need to utilize checks on Okta policies.
    # This requires development of a custom Okta benchmark.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-02"
    })
}

benchmark "fedramp20x_ksi_iam_03" {
    title       = "KSI-IAM-03 Enforce secure authentication for non-user/service accounts."
    description = "Enforce appropriately secure authentication methods for non-user accounts and services."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_03,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-03"
    })
}

benchmark "fedramp20x_ksi_iam_04" {
    title       = "KSI-IAM-04 Use least-privileged, role/attribute-based, just-in-time authorization."
    description = "Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_04,
    ]
    # This needs some level of checks against direct user level assignments in IDP and cloud provider. "Just in time" needs to be defined on a per-service basis.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-04"
    })
}

benchmark "fedramp20x_ksi_iam_05" {
    title       = "KSI-IAM-05 Apply zero trust design principles."
    description = "Apply zero trust design principles."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_05,
    ]
    # This needs to be defined on a per-service basis.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-05"
    })
}

benchmark "fedramp20x_ksi_iam_06" {
    title       = "KSI-IAM-06 Automatically secure privileged accounts on suspicious activity."
    description = "Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity."
    children = [
        benchmark.gcp_fedramp20x_ksi_iam_06,
    ]
    # Needs Okta benchmark; need to utilize checks on Okta policies.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-06"
    })
}
######## GCP specific benchmarks ########

benchmark "gcp_fedramp20x_ksi_iam_01" {
    title       = "KSI-IAM-01 - GCP"
    description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
    children = []
    # This may not be possible to implement checks directly in GCP using steampipe.
    # This needs Okta benchmark; need to utilize checks on Okta policies.
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-01"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "okta_fedramp20x_ksi_iam_01" {
    title       = "KSI-IAM-01 - Okta"
    description = "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."
    children = [
        control.okta_dashboard_authentication_policy_requires_non_phishable_authenticators,
        control.okta_admin_console_authentication_policy_requires_non_phishable_authenticators,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-01"
        plugin   = "okta"
        service  = "Okta"
    })
}

benchmark "gcp_fedramp20x_ksi_iam_02" {
    title       = "KSI-IAM-02 - GCP"
    description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
    children = []
    # This needs to be implemented to check Okta policies.
    # Needs to tie to cdefs
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-02"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "okta_fedramp20x_ksi_iam_02" {
    title       = "KSI-IAM-02 - Okta"
    description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
    children = [
        control.okta_admin_console_requires_multifactor_authentication,
        control.okta_dashboard_requires_multifactor_authentication,
        control.okta_password_policies_require_minimum_password_length_of_15_characters,
        control.okta_password_policies_require_at_least_1_uppercase_character,
        control.okta_password_policies_require_at_least_1_lowercase_character,
        control.okta_password_policies_require_at_least_1_numeric_character,
        control.okta_password_policies_require_at_least_1_special_character,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-02"
        plugin   = "okta"
        service  = "Okta"
    })
}

benchmark "googledirectory_fedramp20x_ksi_iam_02" {
    title       = "KSI-IAM-02 - Google Directory"
    description = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
    children = [
        control.googledirectory_user_accounts_require_two_step_verification,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-02"
        plugin   = "googledirectory"
        service  = "Google Directory"
    })
}

benchmark "gcp_fedramp20x_ksi_iam_03" {
    title       = "KSI-IAM-03 - GCP"
    description = "Enforce appropriately secure authentication methods for non-user accounts and services."
    children = [
        gcp_compliance.control.iam_service_account_gcp_managed_key,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id   = "KSI-IAM-03"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_iam_04" {
    title       = "KSI-IAM-04 - GCP"
    description = "Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services."
    children = [
        # # IAM
        gcp_compliance.control.denylist_public_users,
        gcp_compliance.control.iam_api_key_age_90,
        gcp_compliance.control.iam_api_key_restricts_apis,
        gcp_compliance.control.iam_api_key_restricts_websites_hosts_apps,
        gcp_compliance.control.iam_service_account_gcp_managed_key,
        # gcp_compliance.control.iam_service_account_without_admin_privilege, # This control considers service editor permissions to be failing, erroneously warns on terraform service accounts.
        control.gcp_service_account_without_admin_privileges,
        gcp_compliance.control.iam_user_kms_separation_of_duty_enforced,
        # gcp_compliance.control.iam_user_not_assigned_service_account_user_role_project_level, # This incorrectly flags cases where principals such as  serviceAccount:680685234603-compute@developer.gserviceaccount.com have this permission which is required for cloud functions to utilize least privilege service principals.
        control.gcp_nonapproved_iam_principal_not_assigned_service_account_user_at_project_level,
        gcp_compliance.control.iam_user_separation_of_duty_enforced, # This may as well read "Don't directly assign permissions to users, use groups instead". It will return no results if there are no user principals assigned roles directly.
        control.gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly, # This is the same as iam_user_separation_of_duty_enforced but shows other principal types.
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id     = "KSI-IAM-04"
        plugin     = "gcp"
        service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_iam_05" {
    title       = "KSI-IAM-05 - GCP"
    description = "Apply zero trust design principles."
    children = [
        gcp_compliance.control.denylist_public_users,
        # gcp_compliance.control.iam_service_account_without_admin_privilege, # This control considers service editor permissions to be failing, erroneously warns on terraform service accounts.
        control.gcp_service_account_without_admin_privileges,
        gcp_compliance.control.iam_user_kms_separation_of_duty_enforced,
        # gcp_compliance.control.iam_user_not_assigned_service_account_user_role_project_level, # Incorrectly flags service principals
        control.gcp_nonapproved_iam_principal_not_assigned_service_account_user_at_project_level,
        gcp_compliance.control.iam_user_separation_of_duty_enforced, # This will return no results if there are no user principals assigned roles directly.
        control.gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly, # This is the same as iam_user_separation_of_duty_enforced but shows other principal types.
        gcp_compliance.control.only_my_domain,
        gcp_compliance.control.iam_service_account_gcp_managed_key,
        gcp_compliance.control.iam_service_account_key_age_90,
        gcp_compliance.control.compute_network_contains_no_default_network,
        gcp_compliance.control.compute_network_contains_no_legacy_network,
        gcp_compliance.control.restrict_firewall_rule_rdp_world_open,
        gcp_compliance.control.restrict_firewall_rule_ssh_world_open,
        gcp_compliance.control.kms_key_not_publicly_accessible,
        gcp_compliance.control.kms_key_separation_of_duties_enforced,
        gcp_compliance.control.compute_instance_no_service_account_impersonate_permission,
        gcp_compliance.control.compute_instance_no_iam_write_permission,
        control.okta_admin_console_requires_multifactor_authentication,
        control.okta_dashboard_requires_multifactor_authentication,
        control.okta_global_session_policies_disable_persistent_global_session_cookies_in_priority_1_rules,

    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id     = "KSI-IAM-05"
        plugin     = "gcp"
        service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_iam_06" {
    title       = "KSI-IAM-06 - GCP"
    description = "Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity."
    children = [
        control.gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval,
        control.gitlab_ensure_source_controlled_account_management_process,
        control.okta_password_policies_enforce_lockout_after_3_failed_attempts,
    ]
    tags = merge(local.all_ksi_iam_common_tags, {
        ksi_id     = "KSI-IAM-06"
        plugin     = "gcp"
        service    = "GCP"
    })
}
