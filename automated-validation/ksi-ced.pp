locals {
  all_ksi_ced_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-CED"
  })
}

benchmark "fedramp20x_ksi_ced" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Cybersecurity Education (CED)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Cybersecurity Education (CED) based on infrastructure state"
    tags        = local.all_ksi_ced_common_tags
    children = [
        benchmark.fedramp20x_ksi_ced_01,
        benchmark.fedramp20x_ksi_ced_02,
    ]
}

benchmark "fedramp20x_ksi_ced_01" {
    title       = "KSI-CED-01 Ensure all employees receive security awareness training."
    description = "Ensure all employees receive security awareness training."
    children = [
        benchmark.gitlab_fedramp20x_ksi_ced_01,
    ]
    # Evaluate access modifications; closed access mods must ISSM approved. We'll take on good faith that every user has an access mod; validation of this will be considerably more complex and require reconciliation with Okta.
    # Will also rely on user and access review TD
    tags = merge(local.all_ksi_ced_common_tags, {
        ksi_id   = "KSI-CED-01"
    })
}

benchmark "fedramp20x_ksi_ced_02" {
    title       = "KSI-CED-02 Require role-specific training for high risk roles, including at least roles with privileged access."
    description = "Require role-specific training for high risk roles, including at least roles with privileged access."
    children = [
        benchmark.gitlab_fedramp20x_ksi_ced_02,
    ]
    # Will leverage user and access review TD
    tags = merge(local.all_ksi_ced_common_tags, {
        ksi_id   = "KSI-CED-02"
    })
}

# Gitlab specific benchmarks
benchmark "gitlab_fedramp20x_ksi_ced_01" {
  title       = "KSI-CED-01 GitLab"
  description = "Ensure that all privileged system users receive security awareness training."
  tags        = merge(local.all_ksi_ced_common_tags, {
    ksi_id   = "KSI-CED-01",
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
  })
  children = [
    control.gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval,
  ]
}

benchmark "gitlab_fedramp20x_ksi_ced_02" {
  title       = "KSI-CED-02 GitLab"
  description = "Ensure that role-specific training is provided for high risk roles."
  tags        = merge(local.all_ksi_ced_common_tags, {
    ksi_id   = "KSI-CED-02",
    service = "GitLab",
    plugin = "gitlab",
    threatalert_control = "true",
  })
  children = [
    control.gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval,
  ]
  # This may want some additional nuance, but it is a sufficiently blunt object to begin shaping with.
  # Could check either component definition or other element of documentation package for assertion of role-specific training.
}
