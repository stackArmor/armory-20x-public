locals {
  all_ksi_rpl_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-RPL"
  })
}

benchmark "fedramp20x_ksi_rpl" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Recovery Planning (RPL)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Recovery Planning (RPL) based on infrastructure state"
    tags        = local.all_ksi_rpl_common_tags
    children = [
        benchmark.fedramp20x_ksi_rpl_01,
        benchmark.fedramp20x_ksi_rpl_02,
        benchmark.fedramp20x_ksi_rpl_03,
        benchmark.fedramp20x_ksi_rpl_04,
    ]
}

benchmark "fedramp20x_ksi_rpl_01" {
    title       = "KSI-RPL-01 Define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
    description = "Define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
    children = [
        benchmark.gitlab_fedramp20x_ksi_rpl_01,
    ]
    tags = merge(local.all_ksi_rpl_common_tags, {
        ksi_id   = "KSI-RPL-01"
    })
}

benchmark "fedramp20x_ksi_rpl_02" {
    title       = "KSI-RPL-02 Develop and maintain a recovery plan that aligns with the defined recovery objectives."
    description = "Develop and maintain a recovery plan that aligns with the defined recovery objectives."
    children = [
        benchmark.gitlab_fedramp20x_ksi_rpl_02,
    ]
    tags = merge(local.all_ksi_rpl_common_tags, {
        ksi_id   = "KSI-RPL-02"
    })
}

benchmark "fedramp20x_ksi_rpl_03" {
    title       = "KSI-RPL-03 Perform system backups aligned with recovery objectives."
    description = "Perform system backups aligned with recovery objectives."
    children = [
        benchmark.gcp_fedramp20x_ksi_rpl_03,
    ]
    # Current implementation checks backup status. RPO is presumed 24h which is fine for MVP as it matches system. RPO will need to be parameterized such that it can be read from a config or otherwise extracted to be generically applicable. GCP|AWS|Azure configuration(s) would then need to be checked. Complex.
    tags = merge(local.all_ksi_rpl_common_tags, {
        ksi_id   = "KSI-RPL-03"
    })
}

benchmark "fedramp20x_ksi_rpl_04" {
    title       = "KSI-RPL-04 Regularly test the capability to recover from incidents and contingencies."
    description = "Regularly test the capability to recover from incidents and contingencies."
    children = [
        benchmark.tsw_fedramp20x_ksi_rpl_04,
        benchmark.gitlab_fedramp20x_ksi_rpl_04,
    ]
    tags = merge(local.all_ksi_rpl_common_tags, {
        ksi_id   = "KSI-RPL-04"
    })
}

# GCP specific benchmarks
benchmark "gcp_fedramp20x_ksi_rpl_03" {
    title       = "GCP KSI-RPL-03: Perform system backups aligned with recovery objectives."
    description = "This benchmark assesses the configuration of stateful resource backups in GCP"
    tags        = merge(local.all_ksi_rpl_common_tags, { 
        ksi_id = "KSI-RPL-03",
        plugin     = "gcp"
        service    = "GCP"
    })
    children    = [
        control.gcp_compute_disk_snapshot_within_last_24h,
        gcp_compliance.control.sql_instance_automated_backups_enabled,
        control.gcp_sql_instance_backup_within_last_24h,
    ]
}

# GitLab specific benchmarks
benchmark "gitlab_fedramp20x_ksi_rpl_01" {
    title       = "KSI-RPL-01 GitLab"
    description = "Define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)."
    tags        = merge(local.all_ksi_rpl_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        ksi_id  = "KSI-RPL-01"
    })
    children    = [
        control.gitlab_ensure_rto_documented_in_criticality_analysis,
        control.gitlab_ensure_rpo_documented_in_criticality_analysis,
    ]
    # Parse RTO and RPO from source controlled declarations in GitLab.
}

benchmark "gitlab_fedramp20x_ksi_rpl_02" {
    title       = "KSI-RPL-02 GitLab"
    description = "Develop and maintain a recovery plan that aligns with the defined recovery objectives."
    tags        = merge(local.all_ksi_rpl_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        ksi_id  = "KSI-RPL-02"
    })
    children    = [
        control.gitlab_ensure_recovery_plan_documented_in_iscp,
    ]
    # Reference the recovery plan declaration. Maybe some attribute checks?
}

benchmark "gitlab_fedramp20x_ksi_rpl_04" {
    title       = "KSI-RPL-04 GitLab"
    description = "Regularly test the capability to recover from incidents and contingencies."
    tags        = merge(local.all_ksi_rpl_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        ksi_id  = "KSI-RPL-04"
    })
    children    = [
        control.gitlab_ensure_ir_cp_testing_issue_not_closed_with_incomplete_checklist,
        control.gitlab_ensure_ir_cp_tabletop_issue_not_closed_with_incomplete_checklist,
    ]
}

benchmark "tsw_fedramp20x_ksi_rpl_04" {
    title       = "KSI-RPL-04 TSW"
    description = "Regularly test the capability to recover from incidents and contingencies."
    tags        = merge(local.all_ksi_rpl_common_tags, {
        service = "TSW",
        plugin  = "tsw",
        ksi_id  = "KSI-RPL-04"
    })
    children    = [
        control.tsw_ir_cp_tasks_not_overdue,
    ]
}