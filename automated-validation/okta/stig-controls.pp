# Okta STIG controls are defined here.
locals {
  okta_stig_common_tags = {
    service = "Okta",
    okta_stig = "true",
  }
}

control "okta_default_global_session_policy_enforces_15_minute_inactivity_logout" {
  title       = "OKTA-APP-000020 Okta must log out sessions after a ${var.okta_stig_max_session_idle_minutes} minute period of inactivity. The default Global Session Policy must enforce this requirement."
  description = "Ensure that the default global session policy enforces a ${var.okta_stig_max_session_idle_minutes} minute inactivity logout."
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273186",
    okta_stig_version = "OKTA-APP-000020",
    severity = "moderate",
  })
  query = query.okta_default_global_session_policy_enforces_15_minute_inactivity_logout
}

query "okta_default_global_session_policy_enforces_15_minute_inactivity_logout" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        -- rules,
        rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes' as max_session_idle_minutes,
        case
            when rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes' = '${var.okta_stig_max_session_idle_minutes}' then 'ok'
            when rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes' is null then 'alarm'
            -- If less than 15 but greater than 0 (no timeout), this is ok
            when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes')::int < ${var.okta_stig_max_session_idle_minutes} and (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes')::int > 0 then 'ok'
            else 'alarm'
        end as status,
        case
            when rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes' is null then name || ' does not appear to define an inactivity logout and requires manual review'
            -- handle case where maxSessionIdleMinutes is 0 (no timeout)
            when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes')::int = 0 then name || ' does not enforce an inactivity logout'
            when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes')::int < ${var.okta_stig_max_session_idle_minutes} then name || ' enforces a ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes') || '-minute inactivity logout, which is more aggressive than the required ${var.okta_stig_max_session_idle_minutes} minutes'
            else name || ' enforces a ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionIdleMinutes') || '-minute inactivity logout'
        end as reason
    from okta_signon_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        name = 'Default Policy'
  EOQ
}

# Some requirements are foundational for multiple STIGs such as "don't rely on default rules"
control "okta_default_global_session_policy_does_not_use_default_rule_at_priority_1" {
  title       = "[OKTA-APP-000020,OKTA-APP-001665,OKTA-APP-001710] Okta must not use the default rule at priority 1 in the default global session policy."
  description = "Ensure that the default global session policy does not use the 'Default Rule' at priority 1. This is a foundational requirement for a number of STIGs."
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "[V-273186,V-273206,V-273203]",
    okta_stig_version = "[OKTA-APP-000020,OKTA-APP-001665,OKTA-APP-001710]",
    severity = "moderate",
  })
  query = query.okta_default_global_session_policy_does_not_use_default_rule_at_priority_1
}

query "okta_default_global_session_policy_does_not_use_default_rule_at_priority_1" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        -- rules,
        -- rule_elem->'PolicyRule'->>'priority' as rule_priority,
        -- rule_elem->'PolicyRule'->>'name' as rule_name,
        case
            when rule_elem->'PolicyRule'->>'name' = 'Default Rule' then 'alarm'
            when rule_elem->'PolicyRule'->>'name' is null then 'alarm'
            else 'ok'
        end as status,
        case
            when rule_elem->'PolicyRule'->>'name' = 'Default Rule' then name || ' uses the Default Rule with priority 1 which violates STIG requirements.'
            when rule_elem->'PolicyRule'->>'name' is null then name || ' is missing a rule name for its priority 1 rule. Manual review required.'
            else name || ' uses a rule named ' || (rule_elem->'PolicyRule'->>'name') || ' with priority 1.'
        end as reason
    from okta_signon_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        name = 'Default Policy'
        and rule_elem->'PolicyRule'->>'priority' = '1'
  EOQ
}

control "okta_global_session_policies_disable_persistent_global_session_cookies_in_priority_1_rules" {
  title       = "OKTA-APP-001710 Okta must disable persistent global session cookies in all global session policy priority 1 rules."
  description = "Ensure that all global session policies disable persistent global session cookies in priority 1 rules. If cached authentication information is out of date, the validity of the authentication information may be questionable."
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273206",
    okta_stig_version = "OKTA-APP-001710",
    severity = "moderate",
    zero_trust = "true",
  })
  query = query.okta_global_session_policies_disable_persistent_global_session_cookies_in_priority_1_rules
}

query "okta_global_session_policies_disable_persistent_global_session_cookies_in_priority_1_rules" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        -- rules,
        -- rule_elem->'PolicyRule'->>'priority' as rule_priority,
        -- rule_elem->'PolicyRule'->>'name' as rule_name,
        -- rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' as use_persistent_cookie,
        case
            when rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' = 'false' then 'ok'
            when rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' is null then 'alarm'
            when rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' = 'true' then 'alarm'
            else 'alarm'
        end as status,
        case
            when rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' is null then name || ' does not appear to define persistent global session cookie handling and requires manual review.'
            when rule_elem->'Actions'->'signon'->'session'->>'usePersistentCookie' = 'true' then name || ' allows persistent global session cookies, which is not allowed in priority 1 rules.'
            else name || ' does not allow persistent global session cookies.'
        end as reason
    from okta_signon_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        rule_elem->'PolicyRule'->>'priority' = '1'
  EOQ
}

control "okta_password_policies_enforce_lockout_after_3_failed_attempts" {
  title       = "OKTA-APP-000170 Okta must enforce the limit of three consecutive invalid login attempts by a user during a 15-minute time period."
  description = "By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. Satisfies: SRG-APP-000065, SRG-APP-000345"
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273189",
    okta_stig_version = "OKTA-APP-000170",
    severity = "moderate",
  })
  query = query.okta_password_policies_enforce_lockout_after_3_failed_attempts
}

query "okta_password_policies_enforce_lockout_after_3_failed_attempts" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        settings->'password'->>'lockout' as lockout_settings,
        case
            when settings->'password'->'lockout'->>'maxAttempts' = '3' then 'ok'
            when settings->'password'->'lockout'->>'maxAttempts' is null then 'alarm'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'lockout'->>'maxAttempts' is null then name || ' does not appear to define lockout settings and requires manual review.'
            when settings->'password'->'lockout'->>'maxAttempts' = '3' then name || ' enforces lockout after 3 attempts, which is compliant with STIG mandate.'
            else name || ' does not enforce lockout after 3 attempts, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_dashboard_authentication_policy_requires_non_phishable_authenticators" {
  title       = "OKTA-APP-000180 The Okta Dashboard application must be configured to allow authentication only via non-phishable authenticators."
  description = "Requiring the use of non-phishable authenticators protects against brute force/password dictionary attacks. This provides a better level of security while removing the need to lock out accounts after three attempts in 15 minutes."
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273190",
    okta_stig_version = "OKTA-APP-001665",
    severity = "moderate",
    zero_trust = "true",
  })
  query = query.okta_dashboard_authentication_policy_requires_non_phishable_authenticators
}

query "okta_dashboard_authentication_policy_requires_non_phishable_authenticators" {
  sql = <<-EOQ
    select distinct on (name)
        name as resource,
        description,
        (rule_elem->'PolicyRule'->>'priority')::int as rule_priority,
        rule_elem->'PolicyRule'->>'name' as rule_name,
        rule_elem->'PolicyRule'->>'status' as rule_status,
        -- rules,
        -- rule_elem,
        constraint_elem,
        case
            when constraint_elem is null then 'alarm'
            when constraint_elem->'possession'->>'phishingResistant' = 'REQUIRED' then 'ok'
            else 'alarm'
        end as status,
        case
            when constraint_elem is null then name || ' policy does not define possession factor constraints and requires manual review.'
            when constraint_elem->'possession'->>'phishingResistant' = 'REQUIRED' then name || ' policy requires non-phishable authenticators, which is compliant with STIG mandate.'
            else name || ' policy does not require non-phishable authenticators as a possession factor constraint, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_authentication_policy,
        lateral jsonb_array_elements(rules) as rule_elem
        left join lateral jsonb_array_elements(rule_elem ->'Actions'->'appSignOn'->'verificationMethod'->'constraints') as constraint_elem on true
    where
        name = 'Okta Dashboard'
        and rule_elem->'PolicyRule'->>'status' = 'ACTIVE'
    -- We only want the lowest number (highest priority) rule for each policy. Since we have select distinct above only the first record is returned.
    order by name, (rule_elem->'PolicyRule'->>'priority')::int asc
  EOQ
}

control "okta_admin_console_authentication_policy_requires_non_phishable_authenticators" {
  title       = "OKTA-APP-000190 The Okta Admin Console application must be configured to allow authentication only via non-phishable authenticators."
  description = "Requiring the use of non-phishable authenticators protects against brute force/password dictionary attacks. This provides a better level of security while removing the need to lock out accounts after three attempts in 15 minutes."
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273191",
    okta_stig_version = "OKTA-APP-000190",
    severity = "moderate",
    zero_trust = "true",
  })
  query = query.okta_admin_console_authentication_policy_requires_non_phishable_authenticators
}

query "okta_admin_console_authentication_policy_requires_non_phishable_authenticators" {
  sql = <<-EOQ
    select distinct on (name)
        name as resource,
        description,
        (rule_elem->'PolicyRule'->>'priority')::int as rule_priority,
        rule_elem->'PolicyRule'->>'name' as rule_name,
        rule_elem->'PolicyRule'->>'status' as rule_status,
        -- rules,
        -- rule_elem,
        constraint_elem,
        case
            when constraint_elem is null then 'alarm'
            when constraint_elem->'possession'->>'phishingResistant' = 'REQUIRED' then 'ok'
            else 'alarm'
        end as status,
        case
            when constraint_elem is null then name || ' policy does not define possession factor constraints and requires manual review.'
            when constraint_elem->'possession'->>'phishingResistant' = 'REQUIRED' then name || ' policy requires non-phishable authenticators, which is compliant with STIG mandate.'
            else name || ' policy does not require non-phishable authenticators as a possession factor constraint, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_authentication_policy,
        lateral jsonb_array_elements(rules) as rule_elem
        left join lateral jsonb_array_elements(rule_elem ->'Actions'->'appSignOn'->'verificationMethod'->'constraints') as constraint_elem on true
    where
        name = 'Okta Admin Console'
        and rule_elem->'PolicyRule'->>'status' = 'ACTIVE'
    -- We only want the lowest number (highest priority) rule for each policy. Since we have select distinct above only the first record is returned.
    order by name, (rule_elem->'PolicyRule'->>'priority')::int asc
  EOQ
}

# V-273192 DoD notice and consent banner cannot be validated with steampipe.

control "okta_admin_console_requires_multifactor_authentication" {
  title       = "OKTA-APP-000560 The Okta Admin Console application must be configured to use multifactor authentication."
  description = <<-EOD
    Without the use of multifactor authentication, the ease of access to privileged functions
    is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. Factors
    include: (i) something a user knows (e.g., password/PIN); (ii) something a user has (e.g., cryptographic identification
    device, token); or (iii) something a user is (e.g., biometric). A privileged account is defined as an information system
    account with authorizations of a privileged user. Network access is defined as access to an information system by a
    user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area
    network, or the internet). Satisfies: SRG-APP-000149, SRG-APP-000154
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273193",
    okta_stig_version = "OKTA-APP-000560",
    severity = "high",
    zero_trust = "true",
  })
  query = query.okta_admin_console_requires_multifactor_authentication
}

query "okta_admin_console_requires_multifactor_authentication" {
  sql = <<-EOQ
    select distinct on (name)
        name as resource,
        description,
        (rule_elem->'PolicyRule'->>'priority')::int as rule_priority,
        rule_elem->'PolicyRule'->>'name' as rule_name,
        rule_elem->'PolicyRule'->>'status' as rule_status,
        -- rules,
        -- rule_elem,
        rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' as factor_mode,
        case
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' = '2FA' then 'ok'
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' is null then 'alarm'
            else 'alarm'
        end as status,
        case
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' is null then name || ' policy does not define factor mode and requires manual review.'
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' = '2FA' then name || ' policy requires 2FA which is compliant with STIG mandate.'
            else name || ' policy specifies ' || (rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode') || ' for factorMode, which is not compliant with STIG mandate.'
        end as reason
    from
        okta_authentication_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        name = 'Okta Admin Console'
        and rule_elem->'PolicyRule'->>'status' = 'ACTIVE'
    -- We only want the lowest number (highest priority) rule for each policy. Since we have select distinct above only the first record is returned.
    order by name, (rule_elem->'PolicyRule'->>'priority')::int asc
  EOQ
}

control "okta_dashboard_requires_multifactor_authentication" {
  title       = "OKTA-APP-000570 The Okta Dashboard application must be configured to use multifactor authentication."
  description = <<-EOD
    To ensure accountability and prevent unauthenticated access, nonprivileged users must use
    multifactor authentication to prevent potential misuse and compromise of the system. Multifactor authentication uses
    two or more factors to achieve authentication. Factors include: (i) Something you know (e.g., password/PIN); (ii) Something
    you have (e.g., cryptographic identification device, token); or (iii) Something you are (e.g., biometric). A nonprivileged
    account is any information system account with authorizations of a nonprivileged user. Network access is any access
    to an application by a user (or process acting on behalf of a user) where the access is obtained through a network connection.
    Applications integrating with the DOD Active Directory and using the DOD CAC are examples of compliant multifactor authentication
    solutions. Satisfies: SRG-APP-000150, SRG-APP-000155
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273194",
    okta_stig_version = "OKTA-APP-000570",
    severity = "high",
    zero_trust = "true",
  })
  query = query.okta_dashboard_requires_multifactor_authentication
}

query "okta_dashboard_requires_multifactor_authentication" {
  sql = <<-EOQ
    select distinct on (name)
        name as resource,
        description,
        (rule_elem->'PolicyRule'->>'priority')::int as rule_priority,
        rule_elem->'PolicyRule'->>'name' as rule_name,
        rule_elem->'PolicyRule'->>'status' as rule_status,
        -- rules,
        -- rule_elem,
        rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' as factor_mode,
        case
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' = '2FA' then 'ok'
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' is null then 'alarm'
            else 'alarm'
        end as status,
        case
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' is null then name || ' policy does not define factor mode and requires manual review.'
            when rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode' = '2FA' then name || ' policy requires 2FA which is compliant with STIG mandate.'
            else name || ' policy specifies ' || (rule_elem->'Actions'->'appSignOn'->'verificationMethod'->>'factorMode') || ' for factorMode, which is not compliant with STIG mandate.'
        end as reason
    from
        okta_authentication_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        name = 'Okta Dashboard'
        and rule_elem->'PolicyRule'->>'status' = 'ACTIVE'
    -- We only want the lowest number (highest priority) rule for each policy. Since we have select distinct above only the first record is returned.
    order by name, (rule_elem->'PolicyRule'->>'priority')::int asc
  EOQ
}

control "okta_password_policies_require_minimum_password_length_of_15_characters" {
  title       = "OKTA-APP-000650 Okta must enforce a minimum 15-character password length."
  description = <<-EOD
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting
    attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength
    and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that
    need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase
    the time and/or resources required to compromise the password.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273195",
    okta_stig_version = "OKTA-APP-000650",
    severity = "moderate",
  })
  query = query.okta_password_policies_require_minimum_password_length_of_15_characters
}

query "okta_password_policies_require_minimum_password_length_of_15_characters" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'complexity' as complexity_settings,
        case
            when (settings->'password'->'complexity'->>'minLength')::int >= 15 then 'ok'
            when settings->'password'->'complexity'->>'minLength' is null then 'alarm'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->>'minLength' is null then name || ' does not appear to define password minimum length settings and requires manual review.'
            when (settings->'password'->'complexity'->>'minLength')::int >= 15 then name || ' enforces a minimum password length of ' || (settings->'password'->'complexity'->>'minLength')::int || ' characters, which is compliant with STIG mandate.'
            else name || ' enforces a minimum password length of ' || (settings->'password'->'complexity'->>'minLength')::int || ' characters, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_password_policies_require_at_least_1_uppercase_character" {
  title       = "OKTA-APP-000670 Okta must enforce password complexity by requiring that at least one uppercase character be used."
  description = <<-EOD
    Use of a complex password helps to increase the time and resources required to compromise
    the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts
    at guessing and brute-force attacks. Password complexity is one factor of several that determine how long it takes to
    crack a password. The more complex the password is, the greater the number of possible combinations that need to be
    tested before the password is compromised.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273196",
    okta_stig_version = "OKTA-APP-000670",
    severity = "moderate",
  })
  query = query.okta_password_policies_require_at_least_1_uppercase_character
}

query "okta_password_policies_require_at_least_1_uppercase_character" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'complexity' as complexity_settings,
        case
            when settings->'password'->'complexity'->>'minUpperCase' is null then 'alarm'
            when (settings->'password'->'complexity'->>'minUpperCase')::int >=1 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->>'minUpperCase' is null then name || ' does not appear to define complexity settings and requires manual review.'
            when (settings->'password'->'complexity'->>'minUpperCase')::int >= 1 then name || ' requires at least one uppercase character, which is compliant with STIG mandate.'
            else name || ' does not require at least one uppercase character, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_password_policies_require_at_least_1_lowercase_character" {
  title       = "OKTA-APP-000680 Okta must enforce password complexity by requiring that at least one lowercase character be used."
  description = <<-EOD
    Use of a complex password helps to increase the time and resources required to compromise
    the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts
    at guessing and brute-force attacks. Password complexity is one factor of several that determine how long it takes to
    crack a password. The more complex the password, the greater the number of possible combinations that need to be tested
    before the password is compromised.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273197",
    okta_stig_version = "OKTA-APP-000680",
    severity = "moderate",
  })
  query = query.okta_password_policies_require_at_least_1_lowercase_character
}

query "okta_password_policies_require_at_least_1_lowercase_character" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'complexity' as complexity_settings,
        case
            when settings->'password'->'complexity'->>'minLowerCase' is null then 'alarm'
            when (settings->'password'->'complexity'->>'minLowerCase')::int >=1 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->>'minLowerCase' is null then name || ' does not appear to define complexity settings and requires manual review.'
            when (settings->'password'->'complexity'->>'minLowerCase')::int >= 1 then name || ' requires at least one lowercase character, which is compliant with STIG mandate.'
            else name || ' does not require at least one lowercase character, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
      EOQ
}

control "okta_password_policies_require_at_least_1_numeric_character" {
  title       = "OKTA-APP-000690 Okta must enforce password complexity by requiring that at least one numeric character be used."
  description = <<-EOD
    Use of a complex password helps to increase the time and resources required to compromise
    the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts
    at guessing and brute-force attacks. Password complexity is one factor of several that determine how long it takes to
    crack a password. The more complex the password, the greater the number of possible combinations that need to be tested
    before the password is compromised.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273198",
    okta_stig_version = "OKTA-APP-000690",
    severity = "moderate",
  })
  query = query.okta_password_policies_require_at_least_1_numeric_character
}

query "okta_password_policies_require_at_least_1_numeric_character" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'complexity' as complexity_settings,
        case
            when settings->'password'->'complexity'->>'minNumber' is null then 'alarm'
            when (settings->'password'->'complexity'->>'minNumber')::int >=1 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->>'minNumber' is null then name || ' does not appear to define complexity settings and requires manual review.'
            when (settings->'password'->'complexity'->>'minNumber')::int >= 1 then name || ' requires at least one numeric character, which is compliant with STIG mandate.'
            else name || ' does not require at least one numeric character, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_password_policies_require_at_least_1_special_character" {
  title       = "OKTA-APP-000700 Okta must enforce password complexity by requiring that at least one special character be used."
  description = <<-EOD
    Use of a complex password helps to increase the time and resources required to compromise
    the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts
    at guessing and brute-force attacks. Password complexity is one factor in determining how long it takes to crack a password.
    The more complex the password, the greater the number of possible combinations that need to be tested before the password
    is compromised. Special characters are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273199",
    okta_stig_version = "OKTA-APP-000700",
    severity = "moderate",
  })
  query = query.okta_password_policies_require_at_least_1_special_character
}

query "okta_password_policies_require_at_least_1_special_character" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'complexity' as complexity_settings,
        case
            when settings->'password'->'complexity'->>'minSymbol' is null then 'alarm'
            when (settings->'password'->'complexity'->>'minSymbol')::int >=1 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->>'minSymbol' is null then name || ' does not appear to define complexity settings and requires manual review.'
            when (settings->'password'->'complexity'->>'minSymbol')::int >= 1 then name || ' requires at least one special character, which is compliant with STIG mandate.'
            else name || ' does not require at least one special character, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_password_policies_enforce_24_hour_or_greater_minimum_password_lifetime" {
  title       = "OKTA-APP-0007400 Okta must enforce 24 hours/one day as the minimum password lifetime."
  description = <<-EOD
    Enforcing a minimum password lifetime helps prevent repeated password changes to defeat
      the password reuse or history enforcement requirement. Restricting this setting limits the user's ability to change
      their password. Passwords must be changed at specific policy-based intervals; however, if the application allows the
      user to immediately and continually change their password, it could be changed repeatedly in a short period of time
      to defeat the organization's policy regarding password reuse. Satisfies: SRG-APP-000173, SRG-APP-000870
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273200",
    okta_stig_version = "OKTA-APP-0007400",
    severity = "moderate",
  })
  query = query.okta_password_policies_enforce_24_hour_or_greater_minimum_password_lifetime
}

query "okta_password_policies_enforce_24_hour_or_greater_minimum_password_lifetime" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'age' as age_settings,
        case
            when settings->'password'->'age'->>'minAgeMinutes' is null then 'alarm'
            when (settings->'password'->'age'->>'minAgeMinutes')::int >= 1440 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'age'->>'minAgeMinutes' is null then name || ' does not appear to define age settings and requires manual review.'
            when (settings->'password'->'age'->>'minAgeMinutes')::int >= 1440 then name || ' enforces a minimum password lifetime of ' || (settings->'password'->'age'->>'minAgeMinutes') || ' minutes, which is compliant with STIG mandate of at least 24 hours.'
            else name || ' enforces a minimum password lifetime of ' || (settings->'password'->'age'->>'minAgeMinutes') || ' minutes, which is non compliant with STIG mandate of at least 24 hours.'
        end as reason
    from
        okta_password_policy
  EOQ
}

control "okta_password_policies_enforce_60_day_maximum_password_lifetime" {
  title       = "OKTA-APP-000745 Okta must enforce a 60-day maximum password lifetime restriction."
  description = <<-EOD
    Any password, no matter how complex, can eventually be cracked. Therefore, passwords must
    be changed at specific intervals. One method of minimizing this risk is to use complex passwords and periodically change
    them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is
    the risk that the system and/or application passwords could be compromised. This requirement does not include emergency
    administration accounts, which are meant for access to the application in case of failure. These accounts are not required
    to have maximum password lifetime restrictions.
  EOD
  tags        = merge(local.okta_stig_common_tags, {
    okta_stig_id = "V-273201",
    okta_stig_version = "OKTA-APP-000745",
    severity = "moderate",
  })
  query = query.okta_password_policies_enforce_60_day_maximum_password_lifetime
}

query "okta_password_policies_enforce_60_day_maximum_password_lifetime" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password'->'age' as age_settings,
        case
            when settings->'password'->'age'->>'maxAgeDays' is null then 'alarm'
            when (settings->'password'->'age'->>'maxAgeDays')::int = 0 then 'alarm'
            when (settings->'password'->'age'->>'maxAgeDays')::int <= 60 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'age'->>'maxAgeDays' is null then name || ' does not appear to define age settings and requires manual review.'
            when (settings->'password'->'age'->>'maxAgeDays')::int = 0 then name || ' does not enforce a maximum password lifetime, which is non compliant with STIG mandate.'
            when (settings->'password'->'age'->>'maxAgeDays')::int <= 60 then name || ' enforces a maximum password lifetime of ' || (settings->'password'->'age'->>'maxAgeDays') || ' days, which is compliant with STIG mandate.'
            else name || ' enforces a maximum password lifetime of ' || (settings->'password'->'age'->>'maxAgeDays') || ' days, which is non compliant with STIG mandate.'
        end as reason
    from
        okta_password_policy
  EOQ
}

# OKTA-APP-001430 External audit server cannot be validated with steampipe at current time. Would need to be a check for a service app?
# Okta must off-load audit records onto a central log server.
# Could potentially check for okta log types in GCP, but this is currently outside the context of steampipe. Would need flowpipe implemented for that

# Author's note: This STIG is shockingly poorly written as it requires EXACTLY 18 hours and ONLY on the Default Policy.
# Unfortunately the checks are extremely specific so we cannot generalize this to be more useful.
control "okta_default_global_session_policy_limits_global_session_lifetime_to_18_hours" {
    title = "OKTA-APP-001665 Okta must be configured to limit the global session lifetime to 18 hours."
    description = <<-EOF
        Without reauthentication, users may access resources or perform tasks for which they do not
        have authorization. When applications provide the capability to change security roles or escalate the functional capability
        of the application, it is critical the user reauthenticate. In addition to the reauthentication requirements associated
        with session locks, organizations may require reauthentication of individuals and/or devices in other situations, including
        (but not limited to) the following circumstances. (i) When authenticators change; (ii) When roles change; (iii) When
        security categories of information systems change; (iv) When the execution of privileged functions occurs; (v) After
        a fixed period of time; or (vi) Periodically. Within the DOD, the minimum circumstances requiring reauthentication are
        privilege escalation and role changes.
    EOF
    tags = merge(local.okta_stig_common_tags, {
        okta_stig_id = "V-273203",
        okta_stig_version = "OKTA-APP-001665",
        severity = "moderate"
    })
    query = query.okta_default_global_session_policy_limits_global_session_lifetime_to_18_hours
}

query "okta_default_global_session_policy_limits_global_session_lifetime_to_18_hours" {
  sql = <<-EOQ
    select
      domain,
      name as resource,
      description,
      rule_elem,
      case
          when rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes' is null then 'alarm'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int =0 then 'alarm'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int > 1080 then 'alarm'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int <= 1080 then 'ok'
          else 'ok'
      end as status,
      case
          when rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes' is null then 'Max Session Lifetime is not set'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int = 0 then 'Max Session Lifetime is set to ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes') || ' minutes which is equivalent to no limit'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int > 1080 then 'Max Session Lifetime is set to ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes') || ' minutes which exceeds the recommended limit of 18 hours'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int > 1080 then 'Max Session Lifetime is ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes') || ' minutes'
          when (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes')::int <= 1080 then 'Max Session Lifetime is ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes') || ' minutes'
          else 'Max Session Lifetime is ' || (rule_elem->'Actions'->'signon'->'session'->>'maxSessionLifetimeMinutes') || ' minutes'
      end as reason
    from
        okta_signon_policy,
        lateral jsonb_array_elements(rules) as rule_elem
    where
        rule_elem->'PolicyRule'->>'priority' = '1'
        and name = 'Default Policy'
  EOQ
}

# OKTA-APP-001670 Okta must be configured to accept Personal Identity Verification (PIV) credentials. does not appear possible to validate with current steampipe plugin as okta_authenticators is not a valid table. 

# OKTA-APP-001700 The Okta Verify application must be configured to connect only to FIPS-compliant devices. does not appear possible to validate with current steampipe plugin as okta_authenticators is not a valid table.

# OKTA-APP-001920 Okta must be configured to use only DOD-approved certificate authorities. does not appear possible validate with current steampipe plugin as okta_identity_providers is not a valid table.

control "okta_password_policies_prevent_common_passwords" {
    title = "OKTA-APP-002980 Okta must validate passwords against a list of commonly used, expected, or compromised passwords."
    description = <<-EOF
        Password-based authentication applies to passwords regardless of whether they are used in
        single-factor or multifactor authentication. Long passwords or passphrases are preferable over shorter passwords. Enforced
        composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to
        establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances
        and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password
        is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list
        of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary
        words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service,
        username, and derivatives thereof.
    EOF
    tags = merge(local.okta_stig_common_tags, {
        okta_stig_id = "V-273208",
        okta_stig_version = "OKTA-APP-002980",
        severity = "moderate"
    })
    query = query.okta_password_policies_prevent_common_passwords
}

query "okta_password_policies_prevent_common_passwords" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        priority,
        settings->'password' as password_settings,
        -- settings->'password'->'complexity'->'dictionary'->'common'->>'exclude' as exclude_common,
        case
            when settings->'password'->'complexity'->'dictionary'->'common'->>'exclude' is null then 'alarm'
            when settings->'password'->'complexity'->'dictionary'->'common'->>'exclude' = 'true' then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'complexity'->'dictionary'->'common'->>'exclude' is null then name || ' does not appear to define common password exclusion settings and requires manual review.'
            when settings->'password'->'complexity'->'dictionary'->'common'->>'exclude' = 'true' then name || ' enforces the exclusion of common passwords, which is compliant with STIG requirements.'
            else name || ' does not enforce the exclusion of common passwords, which is non-compliant with STIG requirements.'
        end as reason
    from
        okta_password_policy
  EOQ
}

########

control "okta_password_policy_prevents_reuse_of_at_least_last_5_passwords" {
    title = "OKTA-APP-003010 Okta must prohibit password reuse for a minimum of five generations."
    description = <<-EOF
        Password-based authentication applies to passwords regardless of whether they are used in
        single-factor or multifactor authentication. Long passwords or passphrases are preferable over shorter passwords. Enforced
        composition rules provide marginal security benefits while decreasing usability. However, organizations may choose to
        establish certain rules for password generation (e.g., minimum character length for long passwords) under certain circumstances
        and can enforce this requirement in IA-5(1)(h). Account recovery can occur, for example, in situations when a password
        is forgotten. Cryptographically protected passwords include salted one-way cryptographic hashes of passwords. The list
        of commonly used, compromised, or expected passwords includes passwords obtained from previous breach corpuses, dictionary
        words, and repetitive or sequential characters. The list includes context-specific words, such as the name of the service,
        username, and derivatives thereof.
    EOF
    tags = merge(local.okta_stig_common_tags, {
        okta_stig_id = "V-273209",
        okta_stig_version = "OKTA-APP-003010",
        severity = "moderate"
    })
    query = query.okta_password_policy_prevents_reuse_of_at_least_last_5_passwords
}

query "okta_password_policy_prevents_reuse_of_at_least_last_5_passwords" {
  sql = <<-EOQ
    select
        domain,
        name as resource,
        description,
        settings->'password'->'age'->>'historyCount' as password_history_setting,
        case
            when settings->'password'->'age'->>'historyCount' is null then 'alarm'
            when (settings->'password'->'age'->>'historyCount')::int < 5 then 'alarm'
            when (settings->'password'->'age'->>'historyCount')::int >=5 then 'ok'
            else 'alarm'
        end as status,
        case
            when settings->'password'->'age'->>'historyCount' is null then name || ' password history not configured'
            when (settings->'password'->'age'->>'historyCount')::int < 5 then name || ' password history is set to ' || (settings->'password'->'age'->>'historyCount') || ', which is less than the required 5 passwords.'
            when (settings->'password'->'age'->>'historyCount')::int >= 5 then name || ' password history is set to ' || (settings->'password'->'age'->>'historyCount') || ', which meets the requirement of at least 5 previous passwords.'
            else name || ' Unable to determine password history configuration.'
            end as reason
    from okta_password_policy
EOQ
}