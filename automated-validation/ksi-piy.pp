locals {
  all_ksi_piy_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-PIY"
  })
}

benchmark "fedramp20x_ksi_piy" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Policy and Inventory (PIY)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Policy and Inventory (PIY) based on infrastructure state"
    tags        = local.all_ksi_piy_common_tags
    children = [
        benchmark.fedramp20x_ksi_piy_01,
        benchmark.fedramp20x_ksi_piy_02,
        benchmark.fedramp20x_ksi_piy_03,
        benchmark.fedramp20x_ksi_piy_04,
        benchmark.fedramp20x_ksi_piy_05,
        benchmark.fedramp20x_ksi_piy_06,
        benchmark.fedramp20x_ksi_piy_07,
    ]
}

benchmark "fedramp20x_ksi_piy_01" {
    title       = "KSI-PIY-01 Have an up-to-date information resource inventory or code defining all deployed assets, software, and services."
    description = "Have an up-to-date information resource inventory or code defining all deployed assets, software, and services."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_01
    ]
    # This can probably eval to true based on the fact that we are using steampipe and can read project information. Software and services may be more difficult to determine.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-01"
    })
}

benchmark "fedramp20x_ksi_piy_02" {
    title       = "KSI-PIY-02 Have policies outlining the security objectives of all information resources."
    description = "Have policies outlining the security objectives of all information resources."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_02
    ]
    # This will need to evaluate the status of component definitions under source control.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-02"
    })
}

benchmark "fedramp20x_ksi_piy_03" {
    title       = "KSI-PIY-03 Maintain a vulnerability disclosure program."
    description = "Maintain a vulnerability disclosure program."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_03
    ]
    # This cannot directly evaluate state of a vulnerability disclosure program UNLESS we expressed it as a threatAlert configuration under source control.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-03"
    })
}

benchmark "fedramp20x_ksi_piy_04" {
    title       = "KSI-PIY-04 Build security considerations into the SDLC and align with CISA Secure By Design."
    description = "Build security considerations into the Software Development Lifecycle and align with CISA Secure By Design principles."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_04,
        benchmark.gcp_fedramp20x_ksi_piy_04,
    ]
    # Cannot directly evaluate this unless we have a benchmark that evaluates the SDLC and Secure By Design principles.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-04"
    })
}

benchmark "fedramp20x_ksi_piy_05" {
    title       = "KSI-PIY-05 Document methods used to evaluate information resource implementations."
    description = "Document methods used to evaluate information resource implementations."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_05
    ]
    # This may need to ref a playbook or other source controlled documentation OR it may be able to introspect, since this is WHAT THIS BENCHMARK DOES.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-05"
    })
}

benchmark "fedramp20x_ksi_piy_06" {
    title       = "KSI-PIY-06 Have a dedicated staff and budget for security with executive support."
    description = "Have a dedicated staff and budget for security with executive support, commensurate with the size, complexity, scope, and risk of the service offering."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_06
    ]
    # This will have to be manual unless we can standardize a way to represent this in a queryable manner.
    # Need to assess outputs. State of findings. State of defined users. State of Okta users.
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-06"
    })
}

benchmark "fedramp20x_ksi_piy_07" {
    title       = "KSI-PIY-07 Document risk management decisions for software supply chain security."
    description = "Document risk management decisions for software supply chain security."
    children = [
        benchmark.gitlab_fedramp20x_ksi_piy_07
    ]
    # This would require some centralized risk register for software supply chain OR visibility into relevant repos and a structured way to present these decisions.
    # Likely best to maintain and check state on some centralized risk registry (may be able to use GitLab issues IF we represent these as finding issues)
    tags = merge(local.all_ksi_piy_common_tags, {
        ksi_id   = "KSI-PIY-07"
    })
}

# GitLab specific benchmarks
benchmark "gitlab_fedramp20x_ksi_piy_01" {
    title       = "KSI-PIY-01 GitLab"
    description = "Have an up-to-date information resource inventory or code defining all deployed assets, software, and services."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-01"
    })
    children = [
        control.gitlab_ensure_inventory_and_scan_review_not_closed_with_incomplete_checklist,
        control.gitlab_ensure_least_functionality_review_not_closed_with_incomplete_checklist,
    ]
    # This will likely need to check state of source controlled declarations in GitLab, but current gitlab plugin does not support querying arbitrary set of repositories.
    # If we expand the scope of the threatalert-svc-user to allow read for all repos then we could cross reference tenant declarations with repos, but this gets complex and brittle rapidly.
    # This is somewhat recursive in nature, since this is what the benchmark does.
}

benchmark "gitlab_fedramp20x_ksi_piy_02" {
    title       = "KSI-PIY-02 GitLab"
    description = "Have policies outlining the security objectives of all information resources."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-02"
    })
    children = [
        control.gitlab_ensure_roles_and_odps_defined,
    ]
    # This will likely need to check state of source controlled declarations in GitLab.
}

benchmark "gitlab_fedramp20x_ksi_piy_03" {
    title       = "KSI-PIY-03 GitLab"
    description = "Maintain a vulnerability disclosure program."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-03"
    })
    children = [
        control.gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist,
        control.gitlab_ensure_disclosure_program_component_definition_defined,
    ]
    # This cannot directly evaluate state of a vulnerability disclosure program UNLESS we expressed it as a threatAlert configuration under source control.
}

benchmark "gitlab_fedramp20x_ksi_piy_04" {
    title       = "KSI-PIY-04 GitLab"
    description = "Build security considerations into the Software Development Lifecycle and align with CISA Secure By Design principles."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-04"
    })
    children = []
    # This may need to ref a playbook or other source controlled documentation OR it may be able to introspect, since this is WHAT THIS BENCHMARK DOES.
}

benchmark "gitlab_fedramp20x_ksi_piy_05" {
    title       = "KSI-PIY-05 GitLab"
    description = "Document methods used to evaluate information resource implementations."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-05"
    })
    children = [
        control.gitlab_ensure_continuous_monitoring_playbook_documented,
    ]
    # This is ultimately somewhat recursive in nature, since this is what the benchmark does.
}

benchmark "gitlab_fedramp20x_ksi_piy_06" {
    title       = "KSI-PIY-06 GitLab"
    description = "Have a dedicated staff and budget for security with executive support, commensurate with the size, complexity, scope, and risk of the service offering. For the purposes of GitLab, this is assessed by the status of the declared security team and the effective management of findings."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-06"
    })
    children = [
        control.gitlab_ensure_security_analyst_active_within_last_3_days,
        control.gitlab_ensure_security_engineer_active_within_last_3_days,
        control.gitlab_ensure_issm_active_within_last_3_days,
        control.gitlab_ensure_vulnerability_issues_not_overdue_without_being_on_poam,
        control.gitlab_ensure_compliance_issues_not_overdue_without_being_on_poam,
    ]
}


benchmark "gitlab_fedramp20x_ksi_piy_07" {
    title       = "KSI-PIY-07 GitLab"
    description = "Document risk management decisions for software supply chain security."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GitLab",
        plugin  = "gitlab",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-07"
    })
    children = [
        control.gitlab_ensure_supply_chain_risk_exposure_level_defined,
        control.gitlab_ensure_source_controlled_supply_chain_risk_management_plan,
    ]
    # This would require some centralized risk register for software supply chain OR visibility into relevant repos and a structured way to present these decisions.
    # Likely best to maintain and check state on some centralized risk registry (may be able to use GitLab issues IF we represent these as finding issues)
}

# GCP specific benchmarks

benchmark "gcp_fedramp20x_ksi_piy_04" {
    title       = "KSI-PIY-04 GCP"
    description = "Build security considerations into the Software Development Lifecycle and align with CISA Secure By Design principles."
    tags        = merge(local.all_ksi_piy_common_tags, {
        service = "GCP",
        plugin  = "gcp",
        threatalert_control = "true",
        ksi_id   = "KSI-PIY-04"
    })
    children = [
        control.gcp_gcs_documentation_object_store_ssdf_attestation_exists,
    ]
}