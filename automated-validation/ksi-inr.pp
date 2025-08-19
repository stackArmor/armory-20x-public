locals {
  all_ksi_inr_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-INR"
  })
}

benchmark "fedramp20x_ksi_inr" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Incident Reporting (INR)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Incident Reporting (INR) based on infrastructure state"
    tags        = local.all_ksi_inr_common_tags
    children = [
        benchmark.fedramp20x_ksi_inr_01,
        benchmark.fedramp20x_ksi_inr_02,
        benchmark.fedramp20x_ksi_inr_03,
    ]
}

benchmark "fedramp20x_ksi_inr_01" {
    title       = "KSI-INR-01 Report incidents according to FedRAMP requirements and cloud service provider policies."
    description = "Report incidents according to FedRAMP requirements and cloud service provider policies."
    children = [
        benchmark.gitlab_fedramp20x_ksi_inr_01,
    ]
    tags = merge(local.all_ksi_inr_common_tags, {
        ksi_id   = "KSI-INR-01"
    })
}


benchmark "fedramp20x_ksi_inr_02" {
    title       = "KSI-INR-02 Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities."
    description = "Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities."
    children = [
        benchmark.gitlab_fedramp20x_ksi_inr_02,
    ]
    # Needs to leverage some ThreatAlert task definition.
    tags = merge(local.all_ksi_inr_common_tags, {
        ksi_id   = "KSI-INR-02"
    })
}

benchmark "fedramp20x_ksi_inr_03" {
    title       = "KSI-INR-03 Generate after action reports and regularly incorporate lessons learned into operations."
    description = "Generate after action reports and regularly incorporate lessons learned into operations."
    children = [
        benchmark.gitlab_fedramp20x_ksi_inr_03,
    ]
    # We can evaluate incident issue state which may be sufficient for this, but we might also want to evaluate state on a threatalert task.
    tags = merge(local.all_ksi_inr_common_tags, {
        ksi_id   = "KSI-INR-03"
    })
}



# GitLab specific benchmarks
benchmark "gitlab_fedramp20x_ksi_inr_01" {
  title       = "KSI-INR-01 GitLab"
  description = "Ensure that incident issues in GitLab are reported according to FedRAMP requirements and cloud service provider policies."
  tags        = merge(local.all_ksi_inr_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-INR-01"
  })
  children = [
    control.gitlab_ensure_external_reporting_process_documented_in_irp,
    control.gitlab_ensure_incident_issues_not_closed_without_issm_approval,
  ]
  # We currently don't express external reporting status in a manner which can be queried. We may need to ref an explicit playbook for this. 
  # There is not really a clean way to determine from incident metadata that can be queried if external reporting is warranted. May need to remain largely manual.
}

benchmark "gitlab_fedramp20x_ksi_inr_02" {
  title       = "KSI-INR-02 GitLab"
  description = "Ensure that incident issues in GitLab are logged and periodically reviewed for patterns or vulnerabilities."
  tags        = merge(local.all_ksi_inr_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-INR-02"
  })
  children = [
    control.gitlab_ensure_incident_issues_not_closed_without_issm_approval,
  ]
}


benchmark "gitlab_fedramp20x_ksi_inr_03" {
  title       = "KSI-INR-03 GitLab"
  description = "Ensure that incident issues in GitLab generate after action reports and that lessons learned are incorporated into operations."
  tags        = merge(local.all_ksi_inr_common_tags, {
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
    ksi_id   = "KSI-INR-03"
  })
  children = [
    control.gitlab_ensure_incident_issues_not_closed_without_completing_review,
  ]
}
