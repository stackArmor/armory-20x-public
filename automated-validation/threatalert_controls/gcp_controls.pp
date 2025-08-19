# This file declares ThreatAlert-specific controls for FedRAMP 20x GCP benchmarks.
locals {
  gcp_threatalert_common_tags = {
    service = "GCP",
    threatAlert_control = "true",
  }
}

control "gcp_compute_disk_snapshot_within_last_24h" {
    title = "Ensure GCP compute disks have up to date snapshots taken within the last 24 hours"
    description = "Ensure that GCP compute disks have up to date snapshots taken within the last 24 hours to maintain compliance with RPO"
    query = query.gcp_compute_disk_snapshot_within_last_24h
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/Compute",
        severity = "high",
    })
}

query "gcp_compute_disk_snapshot_within_last_24h" {
    sql = <<-EOQ
    select
        d.self_link as resource,
        d.name,
        d.size_gb,
        s.latest_snapshot_timestamp,
        case
            when s.latest_snapshot_timestamp is null then 'alarm'
            when s.latest_snapshot_timestamp < now() - interval '24 hours' then 'alarm'
            when s.latest_snapshot_timestamp >= now() - interval '24 hours' then 'ok'
            else 'alarm'
        end as status,
        case
            when s.latest_snapshot_timestamp is null then 'No snapshot exists for '|| d.self_link
            when s.latest_snapshot_timestamp < now() - interval '24 hours' then 'Latest snapshot for ' || d.self_link || ' is older than 24 hours'
            when s.latest_snapshot_timestamp >= now() - interval '24 hours' then 'Latest snapshot for ' || d.self_link || ' is within the last 24 hours'
        end as reason
    from gcp_compute_disk d
    left join (
        select
            source_disk,
            max(creation_timestamp) as latest_snapshot_timestamp
        from gcp_compute_snapshot
        where storage_bytes_status = 'UP_TO_DATE'
        group by source_disk
    ) s
    on d.self_link = s.source_disk
    where
        d.status = 'READY'
    EOQ
}

control "gcp_sql_instance_backup_within_last_24h" {
    title = "Ensure GCP SQL instances have current backups taken within the last 24 hours"
    description = "Ensure that GCP SQL instances have current backups taken within the last 24 hours to maintain compliance with RPO"
    query = query.gcp_sql_instance_backup_within_last_24h
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/SQL",
        severity = "high",
    })
}

query "gcp_sql_instance_backup_within_last_24h" {
    sql = <<-EOQ
    select
        i.self_link as resource,
        i.name,
        b.normalized_self_link,
        b.latest_backup_timestamp,
        case
            when b.latest_backup_timestamp is null then 'alarm'
            when b.latest_backup_timestamp < now() - interval '24 hours' then 'alarm'
            when b.latest_backup_timestamp >= now() - interval '24 hours' then 'ok'
            else 'alarm'
        end as status,
        case
            when b.latest_backup_timestamp is null then 'No successful backup exists for ' || i.self_link
            when b.latest_backup_timestamp < now() - interval '24 hours' then 'Latest backup for ' || i.self_link || ' is older than 24 hours'
            when b.latest_backup_timestamp >= now() - interval '24 hours' then 'Latest backup for ' || i.self_link || ' is within the last 24 hours'
            else 'Backup status is unknown for ' || i.self_link
        end as reason
    from gcp_sql_database_instance i
    left join (
        select
            -- Strip the /backupRuns/* part from the self_link to match with instance self_link
            regexp_replace(self_link, '/backupRuns/[^/]+$', '') as normalized_self_link,
            max(end_time) as latest_backup_timestamp
        from gcp_sql_backup
        where status = 'SUCCESSFUL'
        group by normalized_self_link
    ) b
    on i.self_link = b.normalized_self_link
    EOQ
}

control "gcp_gcs_documentation_object_store_ssdf_attestation_exists" {
    title = "Ensure GCS documentation object store has SSDF attestation"
    description = "Ensure that the GCS documentation object store contains a valid SSDF attestation document"
    query = query.gcp_gcs_documentation_object_store_ssdf_attestation_exists
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/GCS",
        severity = "high",
    })
}

query "gcp_gcs_documentation_object_store_ssdf_attestation_exists" {
    sql = <<-EOQ
    select distinct
        media_link as resource,
        name,
        content_type,
        time_created,
        updated,
        'ok' as status,
        'SSDF attestation document exists: ' || name as reason
    from gcp_storage_object
    where
        bucket = '${var.bucket_name}'
        and name like '%system-documentation/system-security-plan/%SSDF-attestation%'

    union all
    -- If no matches, show a single alarm row
    select
        'SSDF-attestation' as resource,
        '${var.bucket_name}/system-documentation/system-security-plan/SSDF-attestation' as name,
        null as content_type,
        null as time_created,
        null as updated,
        'alarm' as status,
        'No SSDF attestation could be found in ${var.bucket_name}' as reason
    where not exists (
        select 1
        from gcp_storage_object
        where
            bucket = '${var.bucket_name}'
            and name like '%system-documentation/system-security-plan/%SSDF-attestation%'
    )
    EOQ
}

control "gcp_ddos_protection_enabled" {
    title = "Ensure DDoS protection is implemented for external-facing services"
    description = "DDoS protection is a core requirement that is implemented by default in GCP using Cloud Armor. DDoS protection is always on as specified in https://cloud.google.com/armor/docs/advanced-network-ddos"
    query = query.gcp_ddos_protection_enabled
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/Network",
        severity = "high",
    })
}

query "gcp_ddos_protection_enabled" {
    sql = <<-EOQ
    select
        name as resource,
        'ok' as status,
        'Cloud Armor standard tier protection is enabled by default for all GCP projects as detailed in https://cloud.google.com/armor/docs/advanced-network-ddos' as reason
    from gcp_compute_address
    where address_type like 'EXTERNAL'
    EOQ
}

control "gcp_compute_ssl_policy_tls_1_2_or_greater_enabled" {
  title       = "Ensure that ssl policies enforce TLS 1.2 or greater"
  description = "Check that SSL policies enforce TLS 1.2 or greater to maintain compliance with security standards."
  query       = query.gcp_compute_ssl_policy_tls_1_2_or_greater_enabled
  tags = merge(local.gcp_threatalert_common_tags, {
      service = "GCP/Network",
      severity = "high",
  })
}


# TODO: Update query to more specifically target regional table instead of global.  Pending plugin bug fix by Steampipe.
query "gcp_compute_ssl_policy_tls_1_2_or_greater_enabled" {
  sql = <<-EOQ
    select
      self_link as resource,
      name,
      profile,
      min_tls_version,
      case
        when min_tls_version >= 'TLS_1_2' then 'ok'
        else 'alarm'
      end as status,
      case
        when min_tls_version >= 'TLS_1_2' then 'SSL policy enforces TLS 1.2 or greater for ' || name
        else 'SSL policy does NOT enforce TLS 1.2 or greater for ' || name
      end as reason
    from
      gcp_compute_ssl_policy
  EOQ
}

control "gcp_compute_disk_encrypted_with_cmk" {
    title       = "Ensure that GCP compute disks are encrypted with customer-managed keys (CMK)"
    description = "GCP Compute disks should be encrypted with customer managed keys (CMK). If any disk with READY (usable) status is not encrypted with a CMK, it will fail the control."
    query       = query.gcp_compute_disk_encrypted_with_cmk
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/Compute",
        severity = "high",
    })
}

query "gcp_compute_disk_encrypted_with_cmk" {
    sql = <<-EOQ
    select
        d.self_link as resource,
        d.name,
        d.size_gb,
        d.disk_encryption_key,
        (d.disk_encryption_key->>'kmsKeyName') as cmk_key,
        case
            when (d.disk_encryption_key->>'kmsKeyName') is not null and (d.disk_encryption_key->>'kmsKeyName') != '' then 'ok'
            else 'alarm'
        end as status,
        case
            when (d.disk_encryption_key->>'kmsKeyName') is not null and (d.disk_encryption_key->>'kmsKeyName') != '' then
                'Disk ' || d.name || ' is encrypted with CMK: ' || (d.disk_encryption_key->>'kmsKeyName')
            else
                'Disk ' || d.name || ' is NOT encrypted with CMK'
        end as reason 
    from gcp_compute_disk d
    where d.status = 'READY'
    EOQ
}

control "gcp_storage_bucket_encrypted_with_cmk" {
    title       = "Ensure that GCP storage buckets are encrypted with customer-managed keys (CMK)"
    description = "GCP Storage buckets should be encrypted with customer managed keys (CMK). If any bucket is not encrypted with a CMK, it will fail the control."
    query       = query.gcp_storage_bucket_encrypted_with_cmk
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/Storage",
        severity = "high",
    })
}

query "gcp_storage_bucket_encrypted_with_cmk" {
    sql = <<-EOQ
    select
        b.self_link as resource,
        b.name,
        b.default_kms_key_name as cmk_key,
        case
            when b.default_kms_key_name is not null then 'ok'
            else 'alarm'
        end as status,
        case
            when b.default_kms_key_name is not null then 'Bucket ' || b.name || ' is encrypted with CMK: ' || b.default_kms_key_name
            else 'Bucket ' || b.name || ' is NOT encrypted with CMK'
        end as reason
    from gcp_storage_bucket b
    EOQ
}

control "gcp_cloud_sql_encrypted_with_cmk" {
    title       = "Ensure that GCP Cloud SQL instances are encrypted with customer-managed keys (CMK)"
    description = "Ensure that GCP Cloud SQL instances are encrypted with customer-managed keys (CMK) to maintain compliance with security standards."
    query       = query.gcp_cloud_sql_encrypted_with_cmk
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/SQL",
        severity = "high",
    })
}

query "gcp_cloud_sql_encrypted_with_cmk" {
    sql = <<-EOQ
    select
        i.self_link as resource,
        i.name,
        i.kms_key_name as cmk_key,
        case
            when i.kms_key_name is not null then 'ok'
            else 'alarm'
        end as status,
        case
            when i.kms_key_name is not null then
                'Cloud SQL instance ' || i.name || ' is encrypted with CMK: ' || i.kms_key_name
            else
                'Cloud SQL instance ' || i.name || ' is NOT encrypted with CMK'
        end as reason
    from gcp_sql_database_instance i
    EOQ
}

control "gcp_armory_organization_log_buckets_active" {
  title       = "Ensure that Armory organization log buckets are active"
  description = "The Armory system requires organization log buckets to be configured and used for centralized log aggregation and retention. These buckets must be in an active state."
  query       = query.gcp_armory_organization_log_buckets_active
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Logging",
        severity = "high",
  })
}

query "gcp_armory_organization_log_buckets_active" {
  sql = <<-EOQ
    select
        name as resource,
        description,
        lifecycle_state,
        retention_days,
        project,
        case
            when lifecycle_state = 'ACTIVE' then 'ok'
            else 'alarm'
        end as status,
        case
            when lifecycle_state = 'ACTIVE' then 'Organization log bucket is active: ' || name || ' (Retention: ' || retention_days || ' days)'
            else 'Organization log bucket is not active: ' || name || ' (Lifecycle State: ' || lifecycle_state || ')'
        end as reason
    from
        gcp_logging_bucket
    where
        name like 'org%'
  EOQ
}

control "gcp_armory_organization_log_bucket_retention_compliant_with_m21_31" {
  title       = "Ensure that Armory organization log buckets have a retention period compliant with M-21-31"
  description = "The Armory system requires organization log buckets to have a retention period of at least 900 days in accordance with M-21-31 requirements."
  query       = query.gcp_armory_organization_log_bucket_retention_compliant_with_m21_31
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Logging",
    severity = "high",
  })
}

query "gcp_armory_organization_log_bucket_retention_compliant_with_m21_31" {
  sql = <<-EOQ
    select
        name as resource,
        description,
        lifecycle_state,
        retention_days,
        project,
        case
            when retention_days >= 900 then 'ok'
            else 'alarm'
        end as status,
        case
            when retention_days >= 900 then 'Organization log bucket retention is compliant: ' || name || ' (Retention: ' || retention_days || ' days)'
            else 'Organization log bucket retention is not compliant: ' || name || ' (Retention: ' || retention_days || ' days)'
        end as reason
    from
        gcp_logging_bucket
    where
        name like 'org%'
  EOQ
}


control "gcp_custom_ssl_policy_configured_for_projects_hosting_compute_instances" {
  title       = "Ensure that a custom SSL policy requiring at least TLS 1.2 is configured for projects hosting Compute Engine instances"
  description = "A custom SSL policy enforcing at least TLS 1.2 should be configured for projects hosting Compute Engine instances. If no custom SSL policy meeting the requirements is configured, this is a finding."
  query       = query.gcp_custom_ssl_policy_configured_for_projects_hosting_compute_instances
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Compute",
    severity = "high",
  })
}

query "gcp_custom_ssl_policy_configured_for_projects_hosting_compute_instances" {
  sql = <<-EOQ
    -- every gcp project with compute resources must declare a custom SSL policy which requires TLS 1.2 or later
    with compute_projects as (
        select distinct
            project,
            location
        from
            gcp_compute_instance
    )
    select
        compute_projects.project as resource,
        gcp_compute_ssl_policy.self_link as ssl_policy_resource,
        gcp_compute_ssl_policy.name as ssl_policy_name,
        gcp_compute_ssl_policy.min_tls_version,
        gcp_compute_ssl_policy.profile,
        gcp_compute_ssl_policy.enabled_features,
        case
            when gcp_compute_ssl_policy.min_tls_version is null then 'alarm'
            when gcp_compute_ssl_policy.min_tls_version not in ('TLS_1_2', 'TLS_1_3') then 'alarm'
            else 'ok'
        end as status,
        case
            when gcp_compute_ssl_policy.min_tls_version is null then 'Custom SSL policy not configured for project ' || compute_projects.project
            when gcp_compute_ssl_policy.min_tls_version not in ('TLS_1_2', 'TLS_1_3') then 'Custom SSL policy ' || gcp_compute_ssl_policy.name || ' not configured correctly for project ' || compute_projects.project || '. Min TLS version: ' || gcp_compute_ssl_policy.min_tls_version
            else 'Custom SSL policy ' || gcp_compute_ssl_policy.name || ' configured correctly for project ' || compute_projects.project || '. Min TLS version: ' || gcp_compute_ssl_policy.min_tls_version
        end as reason
    from
        compute_projects
    left join
        gcp_compute_ssl_policy
        on compute_projects.project = gcp_compute_ssl_policy.project
  EOQ
}

control "gcp_custom_ssl_policies_enable_only_fips_compliant_ciphers" {
  title       = "Ensure that custom SSL policies enable only secure and FIPS compliant ciphers"
  description = "Custom SSL policies should require FIPS compliant ciphers to ensure secure communication. If a custom SSL policy does not enable only FIPS compliant ciphers, this is a finding."
  query       = query.gcp_custom_ssl_policies_enable_only_fips_compliant_ciphers
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Compute",
    severity = "high",
  })
}

query "gcp_custom_ssl_policies_enable_only_fips_compliant_ciphers" {
  sql = <<-EOQ
    select
        self_link as resource,
        enabled_features::text,
        warnings,
        min_tls_version,
        case
            when (enabled_features ?| array['TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA']) then 'alarm'
            else 'ok'
        end as status,
        case
            when (enabled_features ?| array['TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA']) then 'Custom policy has disallowed ciphers enabled'
            else 'Custom SSL policy enables only FIPS compliant and secure ciphers'
        end as reason
    from
        gcp_compute_ssl_policy
  EOQ
}

control "gcp_compute_instance_oslogin_effectively_enabled" {
  title       = "Ensure that OS Login is effectively enabled for Compute Engine instances (via project metadata or instance metadata)"
  description = "OS Login should be effectively enabled via project or instance metadata for Compute Engine instances to enhance security by managing SSH access through IAM roles. If OS Login is not effectively enabled, this is a finding."
  query       = query.gcp_compute_instance_oslogin_effectively_enabled
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Compute",
    severity = "moderate",
    threatAlert_control = "true",
  })
}

 query "gcp_compute_instance_oslogin_effectively_enabled" {
  sql = <<-EOQ
    select
        i.self_link as resource,
        i.project,
        case
        when i.metadata -> 'items' @> '[{"key":"enable-oslogin","value":"TRUE"}]' then 'ok'
        when m.common_instance_metadata -> 'items' is null or not (m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin"}]') then 'alarm'
        when m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin","value":"FALSE"}]' then 'alarm'
        when m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin","value":"TRUE"}]' and i.metadata -> 'items' @> '[{"key":"enable-oslogin","value":"FALSE"}]' then 'alarm'
        else 'ok'
        end as status,
        case
        when i.metadata -> 'items' @> '[{"key":"enable-oslogin","value":"TRUE"}]' then i.self_link || ' OS login enabled at instance level.'
        when
            m.common_instance_metadata -> 'items' is null
            or not(m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin"}]')
            or m.common_instance_metadata -> 'items' @> '[{"key": "enable-oslogin", "value": "FALSE"}]'
            then i.self_link || ' has OS login disabled at project level.'
        when m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin","value":"TRUE"}]' and i.metadata -> 'items' @> '[{"key":"enable-oslogin","value":"FALSE"}]'
            then i.self_link || ' OS login settings is disabled.'
        when m.common_instance_metadata -> 'items' @> '[{"key":"enable-oslogin","value":"TRUE"}]' and i.metadata -> 'items' is null
            then i.self_link || ' inherits OS login settings from project level.'
        else i.self_link || ' OS login enabled.'
        end as reason
    from
        gcp_compute_instance i
        left join gcp_compute_project_metadata m on i.project = m.project;
  EOQ
}

control "gcp_cloudfunction_ingress_settings_not_set_to_allow_all_where_https_trigger_defined" {
  title       = "Ensure that Cloud Function ingress settings are not set to allow all when HTTPS trigger is defined"
  description = "Cloud Functions with HTTPS triggers should not have ingress settings set to 'ALLOW_ALL' to prevent unauthorized access. If ingress settings are set to 'ALLOW_ALL' where an HTTPS trigger is defined, this is a finding."
  query       = query.gcp_cloudfunction_ingress_settings_not_set_to_allow_all_where_https_trigger_defined
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Cloud Functions",
    severity = "high",
  })
}

query "gcp_cloudfunction_ingress_settings_not_set_to_allow_all_where_https_trigger_defined" {
  sql = <<-EOQ
    select
        self_link as resource,
        project,
        case
            when ingress_settings  = 'ALLOW_ALL' and https_trigger is not null then 'alarm'
            when event_trigger is not null and https_trigger is null then 'ok'
            else 'alarm'
        end as status,
        case
            when ingress_settings = 'ALLOW_ALL' and https_trigger is not null then name || ' ingress settings is set to allow all where an HTTPS trigger is defined.'
            when event_trigger is not null and https_trigger is null then name || ' event trigger is defined and https trigger is not defined, so ingress settings are not relevant.'
            when ingress_settings is null then name || ' ingress settings is not set.'
            when ingress_settings != 'ALLOW_ALL' then name || ' ingress settings is not set to allow all.'
            else name || ' status needs review.'
        end as reason
    from
        gcp_cloudfunctions_function;
  EOQ
}

control "gcp_nonapproved_iam_principal_not_assigned_service_account_user_at_project_level" {
  title       = "Ensure that non-approved IAM principals are not assigned the Service Account User role at the project level"
  description = "IAM principals should not be assigned the Service Account User role at the project level unless they are approved. If non-approved principals are assigned this role, this is a finding."
  query       = query.gcp_nonapproved_iam_principal_not_assigned_service_account_user_at_project_level
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/IAM",
    severity = "high",
    threatAlert_control = "true",
  })
}

query "gcp_nonapproved_iam_principal_not_assigned_service_account_user_at_project_level" {
  sql = <<-EOQ
    with unapproved_bindings as (
        select
            project,
            p,
            entity
        from
            gcp_iam_policy,
            jsonb_array_elements(bindings) as p,
            jsonb_array_elements_text(p -> 'members') as entity
        where
            p ->> 'role' in ('roles/iam.serviceAccountTokenCreator','roles/iam.serviceAccountUser')
            -- We exclude GCP service principals at this level
            and entity not like '%iam.gserviceaccount.com%' and entity not like '%compute@developer.gserviceaccount.com'
    )
    select
        p.project as resource,
        b.entity,
        -- We exclude specific Armory groups at this level
        case
            when entity is not null and (entity not like 'group:%-owners@%' and entity not like 'group:gcp-devops@%' and entity not like 'group:gcp-organization-admins@%') then 'alarm'
            else 'ok'
        end as status,
        case
            when entity is not null and (entity like 'group:%-owners@%' or entity like 'group:gcp-devops@%' or entity like 'group:gcp-organization-admins@%')
                then entity || ' is an approved group and associated with iam.serviceAccountTokenCreator or iam.serviceAccountUser role.'
            when entity is not null
                then entity || ' associated with iam.serviceAccountTokenCreator or iam.serviceAccountUser role, but is not an approved group.'
            else  'No IAM principals associated with iam.serviceAccountTokenCreator or iam.serviceAccountUser role.'
        end as reason
    from
        gcp_iam_policy as p
        left join unapproved_bindings as b on p.project = b.project;
  EOQ
}

control "gcp_non_proxy_compute_subnetwork_flow_log_enabled" {
  title       = "Ensure that non-proxy Compute Engine subnetwork flow logs are enabled"
  description = "Flow logs should be enabled for non-proxy Compute Engine subnetworks to ensure network traffic is logged. If flow logs are not enabled, this is a finding. Flow logs are not supported for proxy-only subnets: https://cloud.google.com/load-balancing/docs/proxy-only-subnets"
  query       = query.gcp_non_proxy_compute_subnetwork_flow_log_enabled
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Compute",
    severity = "high",
  })
}

query "gcp_non_proxy_compute_subnetwork_flow_log_enabled" {
  sql = <<-EOQ
    select
        self_link as resource,
        purpose,
        case
            when enable_flow_logs then 'ok'
            when purpose = 'REGIONAL_MANAGED_PROXY' then 'ok' -- REGIONAL_MANAGED_PROXY subnetworks do not support flow logs
            else 'alarm'
        end as status,
        case
            when enable_flow_logs
                then title || ' flow logging enabled.'
            when purpose = 'REGIONAL_MANAGED_PROXY'
                then title || ' is a REGIONAL_MANAGED_PROXY subnetwork and does not support flow logging.'
            else title || ' flow logging disabled.'
        end as reason
    from
        gcp_compute_subnetwork;
  EOQ
}

control "gcp_non_proxy_compute_subnetwork_private_google_access_configured" {
  title       = "Ensure that non-proxy Compute Engine subnetworks have Private Google Access configured"
  description = "Private Google Access should be enabled for non-proxy Compute Engine subnetworks to allow instances without external IP addresses to access Google APIs and services. If Private Google Access is not configured, this is a finding."
  query       = query.gcp_non_proxy_compute_subnetwork_private_google_access_configured
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/Compute",
    severity = "high",
  })
}

query "gcp_non_proxy_compute_subnetwork_private_google_access_configured" {
  sql = <<-EOQ
    select
        self_link resource,
        name,
        case
            when private_ip_google_access then 'ok'
            when purpose = 'REGIONAL_MANAGED_PROXY' then 'ok' -- REGIONAL_MANAGED_PROXY subnetworks do not support private Google Access
            else 'alarm'
        end as status,
        case
            when private_ip_google_access then title || ' private Google Access is enabled.'
            when purpose = 'REGIONAL_MANAGED_PROXY'
                then title || ' is a REGIONAL_MANAGED_PROXY subnetwork and does not support private Google Access.'
            else title || ' private Google Access is disabled.'
        end as reason
    from
        gcp_compute_subnetwork;
  EOQ
}

control "gcp_service_account_without_admin_privileges" {
  title       = "Ensure that service accounts do not have admin, owner, or editor privileges outside of specific cases"
  description = "Service accounts should not have admin, owner, or editor privileges to prevent unauthorized access and actions. If a service account has these privileges and does not belong to a specifically excluded set of accounts, this is a finding."
  query       = query.gcp_service_account_without_admin_privileges
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/IAM",
    severity = "high",
    threatAlert_control = "true",
  })
}

query "gcp_service_account_without_admin_privileges" {
  sql = <<-EOQ
    with user_roles as (
        select
            split_part(entity, ':', 2) as user_name,
            p ->> 'role' as role
        from
            gcp_iam_policy,
            jsonb_array_elements(bindings) as p,
            jsonb_array_elements_text(p -> 'members') as entity
        where
            p ->> 'role' like any (array ['%admin','%Admin','%Editor','%Owner','%editor','%owner'])
            and split_part(entity, ':', 2) like '%@' || project || '.iam.gserviceaccount.com'
            -- Some editor roles are acceptable or in fact required for service accounts. E.g. for cloudbuild to function correctly
            and p ->> 'role' not like any (array ['%cloudbuild.builds.editor'])
    ),
    agg_roles as (
        select
            user_name,
            string_agg(role, ', ') as roles
        from user_roles
        group by user_name
    )
    select
        'https://iam.googleapis.com/v1/projects/' || project || '/serviceAccounts/' || name as resource,
        case
            when name not like '%@' || project || '.iam.gserviceaccount.com' then 'skip'
            when name like '%-0@%iac-core-0.iam.gserviceaccount.com' then 'skip' -- Exclude resman service accounts used by Terraform
            when agg_roles.user_name is not null then 'alarm'
            else 'ok'
        end as status,
        case
            when name not like '%@' || project || '.iam.gserviceaccount.com' then 'Google-created service account ' || title || ' excluded.'
            when name like '%-0@%iac-core-0.iam.gserviceaccount.com' then name || ' (' || title || ') is a resman service account used by Terraform and excluded.'
            when agg_roles.user_name is not null then name || ' (' || title || ') has admin, owner or editor privileges: ' || agg_roles.roles
            else name || ' (' || title || ') has no admin, owner or editor privileges.'
        end as reason
    from
        gcp_service_account
    left join agg_roles on name = agg_roles.user_name;
  EOQ
}

control "gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly" {
  title       = "Ensure that user principals are not assigned Service Account User and Admin roles directly"
  description = "User principals should not be assigned Service Account User and Admin roles directly. If a user principal is assigned these roles directly, this is a finding."
  query       = query.gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly
  tags = merge(local.gcp_threatalert_common_tags, {
    service = "GCP/IAM",
    severity = "high",
    threatAlert_control = "true",
  })
}

query "gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly" {
  sql = <<-EOQ
    -- This query displays all principals and checks that user principals do not have both service account user and service account admin roles assigned.
    -- This is an adaptation of the gcp compliance benchmark which does not display other principal types with direct role assignments.
    with users_with_roles as (
        select
        distinct split_part(member_entity, ':', 2) as principal_identifier,
            member_entity,
            project,
            _ctx,
            p ->> 'role' as assigned_role
        from
            gcp_iam_policy,
            jsonb_array_elements(bindings) as p,
            jsonb_array_elements_text(p -> 'members') as member_entity
        -- where
        -- split_part(member_entity, ':', 1) = 'user' -- This causes a problem as it restricts to ONLY users, not service accounts or other principal types. Filtering must be done further downstream to faithfully represent state.
    ),
    account_admin_users as(
        select
            principal_identifier,
            project
        from
            users_with_roles
        where assigned_role = 'roles/iam.serviceAccountAdmin'
    ),
    account_users as(
        select
            principal_identifier,
            project
        from
            users_with_roles
        where assigned_role = 'roles/iam.serviceAccountUser'
    )
    select
        distinct member_entity as resource,
        case
            when principal_identifier in (select principal_identifier from account_users) and principal_identifier in (select principal_identifier from account_admin_users) and (split_part(member_entity, ':', 1) != 'user') then 'skip'
            when principal_identifier in (select principal_identifier from account_users) and principal_identifier in (select principal_identifier from account_admin_users) and (split_part(member_entity, ':', 1) = 'user') then 'alarm'
            else 'ok'
        end as status,
        case
            when principal_identifier in (select principal_identifier from account_users) and principal_identifier in (select principal_identifier from account_admin_users) and (split_part(member_entity, ':', 1) = 'user')
                then  principal_identifier || ' is a user assigned both Service Account Admin and Service Account User roles.'
            when principal_identifier in (select principal_identifier from account_users) and principal_identifier in (select principal_identifier from account_admin_users)
                then principal_identifier || ' is assigned both Service Account Admin and Service Account User roles but is not a user.'
            else principal_identifier || ' does not have both Service Account Admin and Service Account User roles.'
        end as reason
    from
        users_with_roles;
  EOQ
}