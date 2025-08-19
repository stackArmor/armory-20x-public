locals {
  all_ksi_svc_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-SVC"
  })
}

benchmark "fedramp20x_ksi_svc" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Service Configuration (SVC)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Service Configuration (SVC) based on infrastructure state"
    tags        = local.all_ksi_svc_common_tags
    children = [
        benchmark.fedramp20x_ksi_svc_01,
        benchmark.fedramp20x_ksi_svc_02,
        benchmark.fedramp20x_ksi_svc_03,
        benchmark.fedramp20x_ksi_svc_04,
        benchmark.fedramp20x_ksi_svc_05,
        benchmark.fedramp20x_ksi_svc_06,
        benchmark.fedramp20x_ksi_svc_07,
    ]
}

benchmark "fedramp20x_ksi_svc_01" {
    title       = "KSI-SVC-01 Harden and review network and system configurations."
    description = "Harden and review network and system configurations."
    children = [
        benchmark.gitlab_fedramp20x_ksi_svc_01
    ]
    # GCP benchmark results + tasks for traffic flow review
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-01"
    })
}

benchmark "fedramp20x_ksi_svc_02" {
    title       = "KSI-SVC-02 Encrypt or otherwise secure network traffic."
    description = "Encrypt or otherwise secure network traffic."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_02,
        benchmark.nessus_fedramp20x_ksi_svc_02,
    ]
    # May be able to inherit wholesale from GCP. 
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-02"
    })
}

benchmark "fedramp20x_ksi_svc_03" {
    title       = "KSI-SVC-03 Encrypt all federal and sensitive information at rest."
    description = "Encrypt all federal and sensitive information at rest."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_03
    ]
    # CMK/CSEK checks for GCP/AWS/Azure
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-03"
    })
}

benchmark "fedramp20x_ksi_svc_04" {
    title       = "KSI-SVC-04 Manage configuration centrally."
    description = "Manage configuration centrally."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_04,
        benchmark.gitlab_fedramp20x_ksi_svc_04,
    ]
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-04"
    })
}

benchmark "fedramp20x_ksi_svc_05" {
    title       = "KSI-SVC-05 Enforce system and information resource integrity through cryptographic means."
    description = "Enforce system and information resource integrity through cryptographic means."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_05
    ]
    # TODO: determine what exactly FedRAMP is asking for here.
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-05"
    })
}

benchmark "fedramp20x_ksi_svc_06" {
    title       = "KSI-SVC-06 Use automated key management systems to manage, protect, and regularly rotate digital keys and certificates."
    description = "Use automated key management systems to manage, protect, and regularly rotate digital keys and certificates."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_06
    ]
    # Key rotation checks. Will be difficult to check for automated certificate rotations
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-06"
    })
}

benchmark "fedramp20x_ksi_svc_07" {
    title       = "KSI-SVC-07 Use a consistent, risk-informed approach for applying security patches."
    description = "Use a consistent, risk-informed approach for applying security patches."
    children = [
        benchmark.gcp_fedramp20x_ksi_svc_07
    ]
    # May need to ref TBD patching policy or similar artifact under source control in GitLab.
    # Evaluation of implementation will likely not be possible to asses in a fully automated manner.
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-07"
    })
}

######## GitLab specific benchmarks ########
benchmark "gitlab_fedramp20x_ksi_svc_01" {
  title       = "KSI-SVC-01 GitLab"
  description = "Harden and review network and system configurations."
  tags        = merge(local.all_ksi_svc_common_tags, {
    ksi_id   = "KSI-SVC-01",
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
  })
  children = [
    control.gitlab_harden_and_review_network_and_system_configurations,
  ]
}



######## GCP specific benchmarks ########

benchmark "gcp_fedramp20x_ksi_svc_02" {
    title       = "KSI-SVC-02 - GCP"
    description = "Ensure that network traffic is encrypted or otherwise secured."
    children = [
        # future enhancement may include:
        # gcp_compliance.control.compute_firewall_allow_connections_proxied_by_iap,
        control.gcp_compute_ssl_policy_tls_1_2_or_greater_enabled,
        control.gcp_custom_ssl_policy_configured_for_projects_hosting_compute_instances,
        control.gcp_custom_ssl_policies_enable_only_fips_compliant_ciphers,
        gcp_compliance.control.require_ssl_sql
     ]
    # May be able to inherit wholesale from GCP.
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-02"
    })
}

benchmark "nessus_fedramp20x_ksi_svc_02" {
    title       = "KSI-SVC-02 Nessus"
    description = "Ensure that network traffic is encrypted or otherwise secured."
    tags        = merge(local.all_ksi_svc_common_tags, {
        service = "Nessus",
        plugin = "nessus",
        threatalert_control = "true",
        ksi_id   = "KSI-SVC-02"
    })
    children    = [
        control.nessus_rhel8_stig_fips_check_passing,
    ]
}

benchmark "gcp_fedramp20x_ksi_svc_03" {
    title       = "KSI-SVC-03 - GCP"
    description = "Ensure that all federal and sensitive information are encrypted at rest."
    children = [
        # Note - the following gcp_compliance control may cause errors in cases where the resource is not present in the Armory
        # however, this is expected and are not validation failures.
        gcp_compliance.control.alloydb_cluster_encrypted_with_cmk,
        gcp_compliance.control.bigquery_dataset_encrypted_with_cmk,
        gcp_compliance.control.bigquery_table_encrypted_with_cmk,
        gcp_compliance.control.dataproc_cluster_encryption_with_cmek,
        gcp_compliance.control.kubernetes_cluster_database_encryption_enabled,
        # custom validations
        control.gcp_compute_disk_encrypted_with_cmk,
        control.gcp_storage_bucket_encrypted_with_cmk,
        control.gcp_cloud_sql_encrypted_with_cmk
    ]
    # CMK/CSEK checks for GCP/AWS/Azure
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-03"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_svc_04" {
    title       = "KSI-SVC-04 - GCP"
    description = "Ensure that configuration is managed centrally."
    children = [
        # TODO- determine if it is desirable to recycle benchmarks here or mandate that controls only be used at this level.
        # gcp_compliance.benchmark.nist_800_53_rev_5_cm_2,
        # gcp_compliance.benchmark.nist_800_53_rev_5_cm_6
        # Really this KSI wants some level of validation that resources were not clickopsed into being. To do so requires some level of dependence on organizational policy as HOW that is prevented and enforced is more of a policy question- there are too many cases to fully handle it with technical benchmarks.
    ]
    # This will likely need to check state of source controlled declarations in GitLab.
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-04"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_svc_05" {
    title       = "KSI-SVC-05 - GCP"
    description = "Ensure that system and information resource integrity is enforced through cryptographic means."
    children = [
        control.gcp_compute_disk_encrypted_with_cmk,
        control.gcp_storage_bucket_encrypted_with_cmk
    ]
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-05"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_svc_06" {
    title       = "KSI-SVC-06 - GCP"
    description = "Ensure that automated key management systems are used to manage, protect, and regularly rotate digital keys and certificates."
    children = [
        gcp_compliance.control.kms_key_rotated_within_90_day,
    ]
    # Key rotation checks. Will be difficult to check for automated certificate rotations
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-06"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gcp_fedramp20x_ksi_svc_07" {
    title       = "KSI-SVC-07 - GCP"
    description = "Ensure a consistent, risk-informed approach is used for applying security patches."
    children = [
        control.gitlab_ensure_documented_process_for_monitoring_vulnerabilities
    ]
    # May need to ref TBD patching policy or similar artifact under source control in GitLab.
    # Evaluation of implementation will likely not be possible to asses in a fully automated manner.
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-07"
        plugin   = "gcp"
        service  = "GCP"
    })
}

benchmark "gitlab_fedramp20x_ksi_svc_04" {
    title       = "KSI-SVC-04 GitLab"
    description = "Ensure that configuration is managed centrally."
    children = [
        control.terraform_defined_in_system_iac_project,
    ]
    tags = merge(local.all_ksi_svc_common_tags, {
        ksi_id   = "KSI-SVC-04"
        plugin   = "gitlab"
        service  = "GitLab"
    })
}