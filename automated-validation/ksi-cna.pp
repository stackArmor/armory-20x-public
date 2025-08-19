locals {
  all_ksi_cna_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-CNA"
  })
}

benchmark "fedramp20x_ksi_cna" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Cloud Native Architecture (CNA)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Cloud Native Architecture (CNA) based on infrastructure state"
    tags        = local.all_ksi_cna_common_tags
    children = [
        benchmark.fedramp20x_ksi_cna_01,
        benchmark.fedramp20x_ksi_cna_02,
        benchmark.fedramp20x_ksi_cna_03,
        benchmark.fedramp20x_ksi_cna_04,
        benchmark.fedramp20x_ksi_cna_05,
        benchmark.fedramp20x_ksi_cna_06,
        benchmark.fedramp20x_ksi_cna_07,
    ]
}

benchmark "fedramp20x_ksi_cna_01" {
    title       = "KSI-CNA-01 Configure ALL information resources to limit inbound and outbound traffic."
    description = "Configure ALL information resources to limit inbound and outbound traffic."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_01,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-01"
    })
}

benchmark "fedramp20x_ksi_cna_02" {
    title       = "KSI-CNA-02 Design systems to minimize the attack surface and minimize lateral movement if compromised."
    description = "Design systems to minimize the attack surface and minimize lateral movement if compromised."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_02,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-02"
    })
}

benchmark "fedramp20x_ksi_cna_03" {
    title       = "KSI-CNA-03 Use logical networking and related capabilities to enforce traffic flow controls."
    description = "Use logical networking and related capabilities to enforce traffic flow controls."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_03,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-03"
    })
}

benchmark "fedramp20x_ksi_cna_04" {
    title       = "KSI-CNA-04 Use immutable infrastructure with strictly defined functionality and privileges by default."
    description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_04,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-04"
    })
}

benchmark "fedramp20x_ksi_cna_05" {
    title       = "KSI-CNA-05 Have denial of service protection."
    description = "Have denial of service protection."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_05,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-05"
    })
}

benchmark "fedramp20x_ksi_cna_06" {
    title       = "KSI-CNA-06 Design systems for high availability and rapid recovery."
    description = "Design systems for high availability and rapid recovery."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_06,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-06"
    })
}

benchmark "fedramp20x_ksi_cna_07" {
    title       = "KSI-CNA-07 Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance."
    description = "Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance."
    children = [
        benchmark.gcp_fedramp20x_ksi_cna_07,
    ]
    tags = merge(local.all_ksi_cna_common_tags, {
        ksi_id  = "KSI-CNA-07"
    })
}

######## GCP specific benchmarks ########
benchmark "gcp_fedramp20x_ksi_cna_01" {
    title       = "KSI-CNA-01 - GCP"
    description = "Configure all information resources to limit inbound and outbound traffic"
    children= [
        gcp_compliance.control.prevent_public_ip_cloudsql,
        gcp_compliance.control.sql_world_readable,
        gcp_compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off,
        gcp_compliance.control.compute_instance_with_no_public_ip_addresses,
        gcp_compliance.control.storage_bucket_not_publicly_accessible,
        gcp_compliance.control.require_bq_table_iam,
        gcp_compliance.control.compute_instance_ip_forwarding_disabled,
        gcp_compliance.control.require_bucket_policy_only,
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id   = "KSI-CNA-01"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_02" {
    title       = "KSI-CNA-02 - GCP"
    description = "Design systems to minimize the attack surface and minimize lateral movement if compromised."
    children= [
        gcp_compliance.control.compute_instance_with_no_public_ip_addresses,
        gcp_compliance.control.require_bq_table_iam,
        gcp_compliance.control.compute_instance_ip_forwarding_disabled,
        gcp_compliance.control.compute_instance_serial_port_connection_disabled,
        gcp_compliance.control.compute_instance_with_no_default_service_account,
        gcp_compliance.control.compute_instance_with_no_default_service_account_with_full_access,
        gcp_compliance.control.compute_instance_block_project_wide_ssh_enabled,
        gcp_compliance.control.require_bucket_policy_only,
        gcp_compliance.control.storage_bucket_not_publicly_accessible,
        gcp_compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off,
        gcp_compliance.control.compute_network_contains_no_default_network,
        gcp_compliance.control.compute_network_contains_no_legacy_network,
        gcp_compliance.control.iam_user_separation_of_duty_enforced, # This will return no results if there are no user principals assigned roles directly.
        control.gcp_user_principals_not_assigned_service_account_user_and_admin_roles_directly, # This is the same as iam_user_separation_of_duty_enforced but shows other principal types.
        # gcp_compliance.control.iam_service_account_without_admin_privilege, # This check is misaligned to SE/Armory patterns where highly privileged service principals are the ONLY principals able to execute stages
        # gcp_compliance.control.iam_user_not_assigned_service_account_user_role_project_level, # This check is too blunt, as core SE pattern is for groups to be granted permissions, and this check picks those up
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id   = "KSI-CNA-02"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_03" {
    title       = "KSI-CNA-03 - GCP"
    description = "Use logical networking and related capabilities to enforce traffic flow controls."
    children= [
        gcp_compliance.control.compute_instance_with_no_public_ip_addresses,
        # gcp_compliance.control.compute_instance_ip_forwarding_disabled, # Used for multiple other KSIs; probably not a candidate for reuse here.
        gcp_compliance.control.app_engine_application_iap_enabled,
        # gcp_compliance.control.cloudfunction_function_no_ingress_settings_allow_all, # There are valid use cases for allowing all ingress such as when event triggers are used. In such cases ingress settings are not relevant, but this control does not accurately assess that use case.
        control.gcp_cloudfunction_ingress_settings_not_set_to_allow_all_where_https_trigger_defined,
        # gcp_compliance.control.cloudfunction_function_restrict_public_access, # Appears broken, returns error. Good idea, poor implementation. TODO: push upstream fix
        # gcp_compliance.control.cloudfunction_function_vpc_connector_enabled, # This is an opinion which google asserts but there are legitimate reasons for deploying cloud functions without a VPC connector. That is all academic however, as VPC connectors DO NOT SUPPORT KMS (at least as of 2025-07) and thus cannot be used for a compliant deployment.
        gcp_compliance.control.cloudrun_service_restrict_public_access,
        # # Compute Firewall rules
        # gcp_compliance.control.compute_external_backend_service_iap_enabled, # This is only situationally applicable
        # gcp_compliance.control.compute_firewall_allow_connections_proxied_by_iap, # Not well crafted- internal VM to VM traffic will generally be required
        # gcp_compliance.control.compute_firewall_allow_tcp_connections_proxied_by_iap, # This is egregious, as it fails for all non-IAP traffic including internal rules. 
        gcp_compliance.control.compute_firewall_default_rule_restrict_ingress_access_except_http_and_https,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_dns_port_53,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_ftp_port_21,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_http_port_80,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_microsoft_ds_port_445,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_mongo_db_port_27017,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_mysql_db_port_3306,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_netbios_snn_port_139,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_oracle_db_port_1521,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_pop3_port_110,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10250,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_10255,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_postgresql_port_5432,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_smtp_port_25,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_137_to_139,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_27017_to_27019,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_61620_61621,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_636,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_6379,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7000_7001,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_7199,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_8888,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9042,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9090,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9160,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9200_9300,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11211,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_11214_to_11215,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_2483_to_2484,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_389,
        gcp_compliance.control.compute_firewall_rule_ingress_access_restricted_to_telnet_port_23,
        gcp_compliance.control.restrict_firewall_rule_rdp_world_open,
        gcp_compliance.control.restrict_firewall_rule_ssh_world_open,
        # gcp_compliance.control.compute_firewall_rule_logging_enabled, # Debatable - this should be covered by VPC flow logs?
        gcp_compliance.control.compute_firewall_rule_restrict_ingress_all_with_no_specific_target,
        gcp_compliance.control.compute_firewall_rule_restrict_ingress_all,
        # # Kubernetes
        gcp_compliance.control.allow_only_private_cluster,
        gcp_compliance.control.disable_gke_legacy_endpoints,
        gcp_compliance.control.enable_alias_ip_ranges,
        gcp_compliance.control.enable_gke_master_authorized_networks,
        gcp_compliance.control.gke_restrict_pod_traffic,
        gcp_compliance.control.kubernetes_cluster_incoming_traffic_open_to_all,
        gcp_compliance.control.kubernetes_cluster_network_policy_enabled,
        gcp_compliance.control.kubernetes_cluster_no_default_network,
        gcp_compliance.control.kubernetes_cluster_private_nodes_configured,
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id   = "KSI-CNA-03"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_04" {
    title       = "KSI-CNA-04 - GCP"
    description = "Use immutable infrastructure with strictly defined functionality and privileges by default."
    children = [
        # # Cloud Functions
        # gcp_compliance.control.cloudfunction_function_no_deployments_manager_permission, # Bugged. if ANY service account has the permissions the control incorrectly asserts that cloudfunctions has it. TODO: push fix upstream
        # gcp_compliance.control.cloudfunction_function_no_disrupt_logging_permission, # Bugged. if ANY service account has the permissions the control incorrectly asserts that cloudfunctions has it. TODO: push fix upstream
        # gcp_compliance.control.cloudfunction_function_restrict_public_access, # Bugged- this improperly identifies functions as publicly accessible when they are not. TODO: push fix upstream
        # gcp_compliance.control.cloudfunction_function_restricted_permission, # This control is bugged, as ANY service principal (including google service principals) will cause the check to fail. TODO: push fix upstream
        # # Kubernetes
        gcp_compliance.control.allow_only_private_cluster,
        gcp_compliance.control.disable_gke_default_service_account,
        gcp_compliance.control.disable_gke_legacy_abac,
        gcp_compliance.control.disable_gke_legacy_endpoints,
        gcp_compliance.control.enable_gke_master_authorized_networks,
        gcp_compliance.control.gke_container_optimized_os,
        gcp_compliance.control.gke_restrict_pod_traffic,
        gcp_compliance.control.kubernetes_cluster_binary_authorization_enabled,
        gcp_compliance.control.kubernetes_cluster_kubernetes_alpha_enabled,
        gcp_compliance.control.kubernetes_cluster_network_policy_enabled,
        gcp_compliance.control.kubernetes_cluster_no_default_network,
        gcp_compliance.control.kubernetes_cluster_node_no_default_service_account,
        gcp_compliance.control.kubernetes_cluster_private_nodes_configured,
        gcp_compliance.control.kubernetes_cluster_release_channel_configured,
        gcp_compliance.control.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled,
        gcp_compliance.control.kubernetes_cluster_shielded_node_secure_boot_enabled,
        gcp_compliance.control.kubernetes_cluster_shielded_nodes_enabled,
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id   = "KSI-CNA-04"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_05" {
    title       = "KSI-CNA-05 - GCP"
    description = "Have denial of service protection."
    children= [
        control.gcp_ddos_protection_enabled
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id   = "KSI-CNA-05"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_06" {
    title       = "KSI-CNA-06 - GCP"
    description = "Design systems for high availability and rapid recovery."
    children= [
        # # Cloud SQL
        gcp_compliance.control.sql_instance_automated_backups_enabled,
        # # Kubernetes
        gcp_compliance.control.enable_auto_repair,
        gcp_compliance.control.kubernetes_cluster_http_load_balancing_enabled,
        gcp_compliance.control.kubernetes_cluster_zone_redundant,
        # # Generic Compute
        gcp_compliance.control.compute_instance_preemptible_termination_disabled,
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id     = "KSI-CNA-06"
      plugin     = "gcp"
      service    = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_cna_07" {
    title       = "KSI-CNA-07 - GCP"
    description = "Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance."
    children = [
        # # AlloyDB
        gcp_compliance.control.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter,
        gcp_compliance.control.alloydb_instance_log_min_error_statement_database_flag_configured,
        gcp_compliance.control.alloydb_instance_log_min_messages_database_flag_error,
        # # BigQuery
        gcp_compliance.control.require_bq_table_iam,
        # gcp_compliance.control.restrict_gmail_bigquery_dataset, # Broken. TODO- determine why; push fix upstream
        # gcp_compliance.control.restrict_googlegroups_bigquery_dataset, # Broken. TODO- determine why; push fix upstream
        # # Cloud Functions
        # gcp_compliance.control.cloudfunction_function_no_deployments_manager_permission, # Bugged. if ANY service account has the permissions the control incorrectly asserts that cloudfunctions has it. Whoever the original author was, they should have been more careful with left joins.
        # gcp_compliance.control.cloudfunction_function_no_disrupt_logging_permission, # Bugged. if ANY service account has the permissions the control incorrectly asserts that cloudfunctions has it
        # gcp_compliance.control.cloudfunction_function_no_ingress_settings_allow_all, # Invalid check. Refer to below for correct state assessment.
        control.gcp_cloudfunction_ingress_settings_not_set_to_allow_all_where_https_trigger_defined,
        # gcp_compliance.control.cloudfunction_function_restrict_public_access, # Bugged- this improperly identifies functions as publicly accessible when they are not.
        # gcp_compliance.control.cloudfunction_function_restricted_permission, # Bugged, as ANY service principal (including google service principals) will cause the check to fail.
        # gcp_compliance.control.cloudfunction_function_vpc_connector_enabled, # This is an opinion which google asserts but there are legitimate reasons for deploying cloud functions without a VPC connector. That is all academic however, as VPC connectors DO NOT SUPPORT KMS (at least as of 2025-07) and thus cannot be used for a compliant deployment.
        # # Cloud Run
        gcp_compliance.control.cloudrun_service_restrict_public_access,
        # # Generic Compute
        gcp_compliance.control.compute_https_load_balancer_logging_enabled,
        # gcp_compliance.control.compute_instance_block_project_wide_ssh_enabled, # TODO - revisit with @vennemp
        # gcp_compliance.control.compute_instance_confidential_computing_enabled, # Not relevant for low baseline
        gcp_compliance.control.compute_instance_ip_forwarding_disabled,
        gcp_compliance.control.compute_instance_no_data_destruction_permission,
        gcp_compliance.control.compute_instance_no_database_write_permission,
        gcp_compliance.control.compute_instance_no_deployments_manager_permission,
        gcp_compliance.control.compute_instance_no_disrupt_logging_permission,
        gcp_compliance.control.compute_instance_no_iam_write_permission,
        gcp_compliance.control.compute_instance_no_service_account_impersonate_permission,
        gcp_compliance.control.compute_instance_no_write_permission_on_deny_policy,
        # gcp_compliance.control.compute_instance_oslogin_enabled, # OS Login is specifically enabled for each VM in terraform so this check may be erroneous. Ref VM metadata items":[{"key":"enable-oslogin","value":"TRUE"}. Check is bad as it uses an OR when it should use an AND for evaluating failure. There is also a separate control for project level OS config, so this needs rewrite.
        control.gcp_compute_instance_oslogin_effectively_enabled, # This control correctly evaluates effective permissions
        gcp_compliance.control.compute_instance_preemptible_termination_disabled,
        gcp_compliance.control.compute_instance_serial_port_connection_disabled,
        # gcp_compliance.control.compute_instance_shielded_vm_enabled, # Shielded VM is not compatible with Trend Micro Deep Security Agent
        gcp_compliance.control.compute_instance_template_ip_forwarding_disabled,
        gcp_compliance.control.compute_instance_with_custom_metadata,
        gcp_compliance.control.compute_instance_with_no_default_service_account_with_full_access,
        gcp_compliance.control.compute_instance_with_no_default_service_account,
        gcp_compliance.control.compute_instance_with_no_public_ip_addresses,
        gcp_compliance.control.compute_instance_wth_no_high_level_basic_role,
        # gcp_compliance.control.compute_ssl_policy_with_no_weak_cipher, # Alas, FIPS mandates weak ciphers. TODO: write custom benchmark to ensure FIPS ciphers.
        # gcp_compliance.control.compute_target_https_proxy_quic_protocol_enabled, # TODO - determine if QUIC is acceptable to gov entities
        gcp_compliance.control.compute_target_https_proxy_quic_protocol_no_default_ssl_policy,
        # gcp_compliance.control.compute_target_https_uses_latest_tls_version, # FIPS takes precedence
        # gcp_compliance.control.enable_network_flow_logs, # This assertion is not valid for REGIONAL_MANAGED_PROXY subnetworks. Custom control required.
        control.gcp_non_proxy_compute_subnetwork_flow_log_enabled,
        # gcp_compliance.control.enable_network_private_google_access, # This assertion is not valid for REGIONAL_MANAGED_PROXY subnetworks. Custom control required.
        control.gcp_non_proxy_compute_subnetwork_private_google_access_configured,
        # gcp_compliance.control.restrict_firewall_rule_world_open_tcp_udp_all_ports # Message is nonsense- TODO- rewrite
        # gcp_compliance.control.kms_key_users_limited_to_3, # This is arbitrary and capricious; not relevant and not even particularly meaningful given how key permissions are managed.
        gcp_compliance.control.bigquery_dataset_encrypted_with_cmk,
        gcp_compliance.control.bigquery_table_encrypted_with_cmk,
        gcp_compliance.control.dataproc_cluster_encryption_with_cmek,
        gcp_compliance.control.alloydb_cluster_encrypted_with_cmk,
        # # Kubernetes
        gcp_compliance.control.allow_only_private_cluster,
        gcp_compliance.control.disable_gke_dashboard,
        gcp_compliance.control.disable_gke_default_service_account,
        gcp_compliance.control.disable_gke_legacy_abac,
        gcp_compliance.control.disable_gke_legacy_endpoints,
        gcp_compliance.control.enable_alias_ip_ranges,
        gcp_compliance.control.enable_auto_repair,
        gcp_compliance.control.enable_auto_upgrade,
        gcp_compliance.control.enable_gke_master_authorized_networks,
        gcp_compliance.control.gke_container_optimized_os,
        gcp_compliance.control.gke_restrict_pod_traffic,
        gcp_compliance.control.kubernetes_cluster_binary_authorization_enabled,
        gcp_compliance.control.kubernetes_cluster_client_certificate_authentication_enabled,
        gcp_compliance.control.kubernetes_cluster_database_encryption_enabled,
        gcp_compliance.control.kubernetes_cluster_http_load_balancing_enabled,
        gcp_compliance.control.kubernetes_cluster_incoming_traffic_open_to_all,
        gcp_compliance.control.kubernetes_cluster_intra_node_visibility_enabled,
        gcp_compliance.control.kubernetes_cluster_kubernetes_alpha_enabled,
        gcp_compliance.control.kubernetes_cluster_logging_enabled,
        gcp_compliance.control.kubernetes_cluster_monitoring_enabled,
        gcp_compliance.control.kubernetes_cluster_network_policy_enabled,
        gcp_compliance.control.kubernetes_cluster_no_default_network,
        gcp_compliance.control.kubernetes_cluster_node_no_default_service_account,
        gcp_compliance.control.kubernetes_cluster_private_nodes_configured,
        gcp_compliance.control.kubernetes_cluster_release_channel_configured,
        gcp_compliance.control.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled,
        gcp_compliance.control.kubernetes_cluster_shielded_node_secure_boot_enabled,
        gcp_compliance.control.kubernetes_cluster_shielded_nodes_enabled,
        gcp_compliance.control.kubernetes_cluster_subnetwork_private_ip_google_access_enabled,
        gcp_compliance.control.kubernetes_cluster_with_less_than_three_node_auto_upgrade_enabled,
        gcp_compliance.control.kubernetes_cluster_with_resource_labels,
        gcp_compliance.control.kubernetes_cluster_zone_redundant,
        # # Organization
        gcp_compliance.control.organization_essential_contacts_configured,
        # # Project
        gcp_compliance.control.project_access_approval_settings_enabled,
        # gcp_compliance.control.project_no_api_key, # As far as I can tell, Assured Workloads means that the API to determine this state is explicitly disallowed. Plus the check is worded poorly.
        gcp_compliance.control.project_oslogin_enabled,
        # gcp_compliance.control.project_service_cloudasset_api_enabled, # Not actually relevant where steampipe is used for cloud asset and state evaluation.
        # gcp_compliance.control.project_service_container_scanning_api_enabled, # This is not globally applicable- projects which don't host containerized workloads should not have the API enabled.
        # # Audit (Resource Manager)
        gcp_compliance.control.audit_logging_configured_for_all_service, # Doesn't actually return results for the Armory. TODO- determine cause. Possibly because this is an org config?
        # # Cloud SQL
        gcp_compliance.control.prevent_public_ip_cloudsql,
        # gcp_compliance.control.require_ssl_sql, # This check is broken as the configuration is controlled with sslMode. TODO- contribute to upstream so check is valid.
        gcp_compliance.control.sql_instance_automated_backups_enabled,
        gcp_compliance.control.sql_instance_mysql_binary_log_enabled,
        gcp_compliance.control.sql_instance_mysql_local_infile_database_flag_off,
        gcp_compliance.control.sql_instance_mysql_skip_show_database_flag_on,
        # gcp_compliance.control.sql_instance_not_publicly_accessible, # Check is broken, as it does not handle PSC. TODO - contribute to upstream to fix check.
        gcp_compliance.control.sql_instance_postgresql_cloudsql_pgaudit_database_flag_enabled,
        # gcp_compliance.control.sql_instance_postgresql_log_checkpoints_database_flag_on, # incorrectly flags failure when default setting is compliant (off)
        gcp_compliance.control.sql_instance_postgresql_log_connections_database_flag_on,
        gcp_compliance.control.sql_instance_postgresql_log_disconnections_database_flag_on,
        gcp_compliance.control.sql_instance_postgresql_log_duration_database_flag_on,
        # gcp_compliance.control.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter, # incorrectly flags failure when default setting is compliant (off)
        # gcp_compliance.control.sql_instance_postgresql_log_executor_stats_database_flag_off, # incorrectly flags failure when default setting is compliant (off)
        gcp_compliance.control.sql_instance_postgresql_log_hostname_database_flag_configured,
        gcp_compliance.control.sql_instance_postgresql_log_lock_waits_database_flag_on,
        gcp_compliance.control.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled,
        gcp_compliance.control.sql_instance_postgresql_log_min_error_statement_database_flag_configured,
        # gcp_compliance.control.sql_instance_postgresql_log_min_messages_database_flag_error, # incorrectly flags failure when default setting is compliant (warning)
        # gcp_compliance.control.sql_instance_postgresql_log_parser_stats_database_flag_off, # incorrectly flags failure when default setting is compliant (off)
        # gcp_compliance.control.sql_instance_postgresql_log_planner_stats_database_flag_off, # incorrectly flags failure when default setting is compliant (off)
        # gcp_compliance.control.sql_instance_postgresql_log_statement_database_flag_ddl, # Conflicts with CIS expectation for 'all'
        # gcp_compliance.control.sql_instance_postgresql_log_statement_stats_database_flag_off, # Identified by Kratos as incorrectly flagging as non-compliant when default behavior is compliant.
        gcp_compliance.control.sql_instance_postgresql_log_temp_files_database_flag_0,
        gcp_compliance.control.sql_instance_sql_3625_trace_database_flag_off,
        gcp_compliance.control.sql_instance_sql_3625_trace_database_flag_on,
        gcp_compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off,
        gcp_compliance.control.sql_instance_sql_cross_db_ownership_chaining_database_flag_off,
        gcp_compliance.control.sql_instance_sql_external_scripts_enabled_database_flag_off,
        gcp_compliance.control.sql_instance_sql_remote_access_database_flag_off,
        gcp_compliance.control.sql_instance_sql_user_connections_database_flag_configured,
        gcp_compliance.control.sql_instance_sql_user_options_database_flag_not_configured,
        gcp_compliance.control.sql_instance_with_labels,
        gcp_compliance.control.sql_world_readable,
        # # Storage
        gcp_compliance.control.require_bucket_policy_only,
        gcp_compliance.control.storage_bucket_log_not_publicly_accessible,
        gcp_compliance.control.storage_bucket_log_object_versioning_enabled,
        gcp_compliance.control.storage_bucket_log_retention_policy_enabled,
        gcp_compliance.control.storage_bucket_log_retention_policy_lock_enabled,
        gcp_compliance.control.storage_bucket_not_publicly_accessible,
        gcp_compliance.control.storage_bucket_uniform_access_enabled,
    ]
    tags        = merge(local.all_ksi_cna_common_tags, {
      ksi_id     = "KSI-CNA-07"
      plugin     = "gcp"
      service    = "GCP"
    })
}

