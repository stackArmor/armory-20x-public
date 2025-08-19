locals {
  all_ksi_tpr_common_tags = merge(local.all_ksis_common_tags, {
    ksi_name = "KSI-TPR"
  })
}

benchmark "fedramp20x_ksi_tpr" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs) for Third-Party Information Resources (TPR)"
    description = "This benchmark assesses FedRAMP 20x KSIs for Third-Party Information Resources (TPR)"
    tags        = local.all_ksi_tpr_common_tags
    children = [
        benchmark.fedramp20x_ksi_tpr_01,
        benchmark.fedramp20x_ksi_tpr_02,
        benchmark.fedramp20x_ksi_tpr_03,
        benchmark.fedramp20x_ksi_tpr_04,
    ]
}

benchmark "fedramp20x_ksi_tpr_01" {
    title       = "KSI-TPR-01 Identify all third-party information resources."
    description = "Identify all third-party information resources."
    children = [
        control.gitlab_ensure_ssp_service_tables_exist_and_populated
    ]
    tags = merge(local.all_ksi_tpr_common_tags, {
        ksi_id   = "KSI-TPR-01"
    })
}

benchmark "fedramp20x_ksi_tpr_02" {
    title       = "KSI-TPR-02 Confirm FedRAMP authorization and secure configuration of third-party services."
    description = "Regularly confirm that services handling federal information or are likely to impact the confidentiality, integrity, or availability of federal information are FedRAMP authorized and securely configured."
    children = [
        control.gitlab_ensure_monthly_report_not_closed_with_incomplete_checklist
    ]
    tags = merge(local.all_ksi_tpr_common_tags, {
        ksi_id   = "KSI-TPR-02"
    })
}

benchmark "fedramp20x_ksi_tpr_03" {
    title       = "KSI-TPR-03 Identify and prioritize mitigation of potential supply chain risks."
    description = "Identify and prioritize mitigation of potential supply chain risks."
    children = [
        control.gitlab_ensure_supply_chain_risk_exposure_level_defined,
        control.gitlab_ensure_source_controlled_supply_chain_risk_management_plan,
    ]
    tags = merge(local.all_ksi_tpr_common_tags, {
        ksi_id   = "KSI-TPR-03"
    })
}

benchmark "fedramp20x_ksi_tpr_04" {
    title       = "KSI-TPR-04 Monitor third party software information resources for upstream vulnerabilities."
    description = "Monitor third party software information resources for upstream vulnerabilities, with contractual notification requirements or active monitoring services."
    children = [
        control.gitlab_ensure_vulnerability_issues_not_overdue_without_being_on_poam,
        control.gitlab_ensure_compliance_issues_not_overdue_without_being_on_poam,
        control.gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist,
    ] 
    tags = merge(local.all_ksi_tpr_common_tags, {
        ksi_id   = "KSI-TPR-04"
    })
}
