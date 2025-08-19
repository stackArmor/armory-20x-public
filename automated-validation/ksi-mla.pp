locals {
  all_ksi_mla_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-MLA"
  })
}

benchmark "fedramp20x_ksi_mla" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Monitoring, Logging and Auditing (MLA)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Monitoring, Logging and Auditing (MLA) based on infrastructure state"
    tags        = local.all_ksi_mla_common_tags
    children = [
        benchmark.fedramp20x_ksi_mla_01,
        benchmark.fedramp20x_ksi_mla_02,
        benchmark.fedramp20x_ksi_mla_03,
        benchmark.fedramp20x_ksi_mla_04,
        benchmark.fedramp20x_ksi_mla_05,
        benchmark.fedramp20x_ksi_mla_06,
    ]
}

benchmark "fedramp20x_ksi_mla_01" {
    title       = "KSI-MLA-01 Operate a SIEM or similar for centralized, tamper-resistant logging."
    description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_mla_01 = "true", ksi_id = "KSI-MLA-01" })
    children    = [
      benchmark.gcp_fedramp20x_ksi_mla_01,
    ]
    # This may need to check log sink configs. Custom GCP benchmark?
}

benchmark "fedramp20x_ksi_mla_02" {
    title       = "KSI-MLA-02 Regularly review and audit logs."
    description = "Regularly review and audit logs."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_id = "KSI-MLA-02" })
    children    = [
        benchmark.gitlab_fedramp20x_ksi_mla_02,
    ]
    # Needs to eval task status.
}

benchmark "fedramp20x_ksi_mla_03" {
    title       = "KSI-MLA-03 Rapidly detect and remediate or mitigate vulnerabilities."
    description = "Rapidly detect and remediate or mitigate vulnerabilities."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_id = "KSI-MLA-03" })
    children    = [
        benchmark.gitlab_fedramp20x_ksi_mla_03,
        benchmark.nessus_fedramp20x_ksi_mla_03,
    ]
    # This can partially leverage the vulnerability management controls in GitLab, but holistic evaluation requires validation of scanner.
}

benchmark "fedramp20x_ksi_mla_04" {
    title       = "KSI-MLA-04 Perform authenticated vulnerability scanning on information resources."
    description = "Perform authenticated vulnerability scanning on information resources."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_id = "KSI-MLA-04" })
    children    = [
        benchmark.gitlab_fedramp20x_ksi_mla_04,
    ]
    # Needs to eval inventory<>scan reconciliation.
}

benchmark "fedramp20x_ksi_mla_05" {
    title       = "KSI-MLA-05 Perform Infrastructure as Code and configuration evaluation and testing."
    description = "Perform Infrastructure as Code and configuration evaluation and testing."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_id = "KSI-MLA-05" })
    children    = [
        benchmark.gitlab_fedramp20x_ksi_mla_05,
    ]
}

benchmark "fedramp20x_ksi_mla_06" {
    title       = "KSI-MLA-06 Centrally track and prioritize mitigation/remediation of vulnerabilities."
    description = "Centrally track and prioritize the mitigation and/or remediation of identified vulnerabilities."
    tags        = merge(local.all_ksi_mla_common_tags, { ksi_id = "KSI-MLA-06" })
    children    = [
        benchmark.gitlab_fedramp20x_ksi_mla_06,
    ]
}

# GCP specific benchmarks
benchmark "gcp_fedramp20x_ksi_mla_01" {
  title       = "KSI-MLA-01 GCP"
  description = "Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GCP",
    plugin = "gcp",
    ksi_id   = "KSI-MLA-01"
  })
  children    = [
    control.gcp_armory_organization_log_buckets_active,
    control.gcp_armory_organization_log_bucket_retention_compliant_with_m21_31,
  ]
}

benchmark "gcp_fedramp20x_ksi_mla_04" {
  title       = "KSI-MLA-04 GCP"
  description = "Perform authenticated vulnerability scanning on information resources."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GCP",
    plugin = "gcp",
    ksi_id   = "KSI-MLA-04"
  })
  children    = [
  ]
  # This won't be relevant until steampipe supports the GCP web security scanner.
}

benchmark "gcp_fedramp20x_ksi_mla_05" {
  title       = "KSI-MLA-05 GCP"
  description = "Perform Infrastructure as Code and configuration evaluation and testing."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GCP",
    plugin = "gcp",
    ksi_id   = "KSI-MLA-05"
  })
  children    = [
  ]
}

# GitLab specific benchmarks

benchmark "gitlab_fedramp20x_ksi_mla_02" {
  title       = "KSI-MLA-02 GitLab"
  description = "Regularly review and audit logs."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-02"
  })
  children    = [
    control.gitlab_ensure_daily_review_tasks_are_completed_and_closed_on_time,
    control.gitlab_ensure_daily_review_tasks_not_closed_with_incomplete_checklist,
  ]
}

benchmark "gitlab_fedramp20x_ksi_mla_03" {
  title       = "KSI-MLA-03 GitLab"
  description = "Rapidly detect and remediate or mitigate vulnerabilities."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-03"
  })
  children    = [
    control.gitlab_ensure_vulnerability_issues_not_overdue_without_being_on_poam,
    control.gitlab_ensure_compliance_issues_not_overdue_without_being_on_poam,
  ]
}

benchmark "nessus_fedramp20x_ksi_mla_03" {
  title       = "KSI-MLA-03 Nessus"
  description = "Rapidly detect and remediate or mitigate vulnerabilities."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "Nessus",
    plugin = "nessus",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-03"
  })
  children    = [
    control.nessus_scans_completed_within_last_7_days,
  ]
}

benchmark "gitlab_fedramp20x_ksi_mla_04" {
  title       = "KSI-MLA-04 GitLab"
  description = "Validate completion of authenticated vulnerability scanning on information resources."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-04"
  })
  children    = [
    control.gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist,
  ]
}

benchmark "gitlab_fedramp20x_ksi_mla_05" {
  title       = "KSI-MLA-05 GitLab"
  description = "Perform Infrastructure as Code and configuration evaluation and testing."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-05"
  })
  children    = [
    control.gitlab_ensure_change_request_not_completed_without_testing
  ]
}

benchmark "gitlab_fedramp20x_ksi_mla_06" {
  title       = "KSI-MLA-06 GitLab"
  description = "Centrally track and prioritize the mitigation and/or remediation of identified vulnerabilities."
  tags        = merge(local.all_ksi_mla_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-MLA-06"
  })
  children    = [
    control.gitlab_ensure_vulnerability_issues_not_overdue_without_being_on_poam,
    control.gitlab_ensure_compliance_issues_not_overdue_without_being_on_poam,
    control.gitlab_ensure_vulnerability_issues_assigned_to_finding_owner,
    control.gitlab_ensure_compliance_issues_assigned_to_finding_owner,
  ]
}