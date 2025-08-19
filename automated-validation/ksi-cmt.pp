locals {
  all_ksi_cmt_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-CMT"
  })
}

benchmark "fedramp20x_ksi_cmt" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Change Management (CMT)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Change Management (CMT) based on infrastructure state"
    tags        = local.all_ksi_cmt_common_tags
    children = [
        benchmark.fedramp20x_ksi_cmt_01,
        benchmark.fedramp20x_ksi_cmt_02,
        benchmark.fedramp20x_ksi_cmt_03,
        benchmark.fedramp20x_ksi_cmt_04,
        benchmark.fedramp20x_ksi_cmt_05,
    ]
}

benchmark "fedramp20x_ksi_cmt_01" {
    title       = "KSI-CMT-01 Log and monitor system modifications."
    description = "Log and monitor system modifications."
    children = [
        benchmark.gitlab_fedramp20x_ksi_cmt_01,
    ]
    # Daily reviews are load bearing for GitLab, as this is evidence of manual review of alerts including for system modifications.
    # Will need to write custom benchmarks for infra components, since this is done centrally in the armory. Moderate complexity; requires explicit opinions.
    tags = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-01"
    })
}

benchmark "fedramp20x_ksi_cmt_02" {
    title       = "KSI-CMT-02 Execute changes through redeployment of version controlled immutable resources."
    description = "Execute changes though redeployment of version controlled immutable resources rather than direct modification wherever possible."
    children = [
        benchmark.gcp_fedramp20x_ksi_cmt_02,
        benchmark.gitlab_fedramp20x_ksi_cmt_02,
    ]
    tags = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-02"
    })
}

benchmark "fedramp20x_ksi_cmt_03" {
    title       = "KSI-CMT-03 Implement automated testing and validation of changes prior to deployment."
    description = "Implement automated testing and validation of changes prior to deployment."
    children = [
        benchmark.gitlab_fedramp20x_ksi_cmt_03
    ]
    # Would require instance level visibility in CI/CD. High level of complexity; requires explicit opinions. Likely to be manual validation for some time yet.
    tags = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-03"
    })
}

benchmark "fedramp20x_ksi_cmt_04" {
    title       = "KSI-CMT-04 Have a documented change management procedure."
    description = "Have a documented change management procedure."
    children = [
        benchmark.gitlab_fedramp20x_ksi_cmt_04,
    ]
    tags = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-04"
    })
}

benchmark "fedramp20x_ksi_cmt_05" {
    title       = "KSI-CMT-05 Evaluate the risk and potential impact of any change."
    description = "Evaluate the risk and potential impact of any change."
    children = [
        benchmark.gitlab_fedramp20x_ksi_cmt_05,
    ]
    # Relies on change management process. Evaluate status of change issues. Initially just utilize ISSM approval or rejection of completed change requests as evidence.
    tags = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-05"
    })
}

# GitLab specific benchmarks
benchmark "gitlab_fedramp20x_ksi_cmt_01" {
    title       = "KSI-CMT-01 GitLab"
    description = "Log and monitor system modifications."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-01",
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
    })
    children = [
        control.gitlab_ensure_daily_review_tasks_not_closed_with_incomplete_checklist,
        control.gitlab_ensure_daily_review_tasks_are_completed_and_closed_on_time,
        control.gitlab_ensure_weekly_review_tasks_are_completed_on_time,
        control.gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist,
    ]
}

benchmark "gitlab_fedramp20x_ksi_cmt_02" {
    title       = "KSI-CMT-02 GitLab"
    description = "Execute changes through redeployment of version controlled immutable resources."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-02",
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
    })
    children = [
        control.gitlab_default_iac_branch_protected,
        control.terraform_lock_source_controlled_in_tf_repositories,
        control.terraform_defined_in_system_iac_project,
    ]
    # Clarification is needed as to the exact intent behind this- many resources will be mutable even if declared in terraform/other iac.
}
benchmark "gcp_fedramp20x_ksi_cmt_02" {
    title       = "KSI-CMT-02 GCP"
    description = "Execute changes through redeployment of version controlled immutable resources."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-02",
        service = "GCP",
        plugin  = "gcp",
        threatalert_control = "true",
    })
    children = []
    # This will be considerably more complex to assess in GitLab. 
}

benchmark "gitlab_fedramp20x_ksi_cmt_03" {
    title       = "KSI-CMT-03 GitLab"
    description = "Implement automated testing and validation of changes prior to deployment."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-03",
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
    })
    children = [
        control.gitlab_ensure_change_request_not_completed_without_testing
    ]
    # This really needs CI eval. Current implementation makes this difficult since it is not fully automated and is partially manual with cloud build.
}

benchmark "gitlab_fedramp20x_ksi_cmt_04" {
    title       = "KSI-CMT-04 GitLab"
    description = "Have a documented change management procedure."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-04",
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
    })
    children = [
        control.gitlab_ensure_source_controlled_change_management_process,
    ]
    # Change management process needs to be expanded to better document CI process expectations.
}

benchmark "gitlab_fedramp20x_ksi_cmt_05" {
    title       = "KSI-CMT-05 GitLab"
    description = "Evaluate the risk and potential impact of any change ."
    tags        = merge(local.all_ksi_cmt_common_tags, {
        ksi_id   = "KSI-CMT-05",
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
    })
    children = [
        control.gitlab_ensure_change_requests_not_closed_without_issm_approval_or_rejection,
        control.gitlab_ensure_all_change_requests_indicate_criticality,
        control.gitlab_ensure_all_change_requests_document_impact_analysis,
    ]
}