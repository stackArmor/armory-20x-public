# This file declares ThreatAlert-specific controls for GitLab
locals {
  gitlab_threatalert_common_tags = {
    service = "GitLab",
    threatAlert_control = "true",
  }
}

control "gitlab_ensure_incident_issues_not_closed_without_issm_approval" {
  title       = "Ensure GitLab incident issues are not closed without ISSM review and approval"
  description = "Incident issues should not be closed without ISSM review and approval. This control checks that no incidents are closed without documented approval in accordance with system procedures including external reporting requirements."
  query       = query.gitlab_ensure_incident_issues_not_closed_without_issm_approval
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_incident_issues_not_closed_without_issm_approval" {
  sql = <<-EOQ
    select
        web_url as resource,
        labels,
        case
            when labels @> '["ISSM::Approved"]' then 'ok'
            else 'alarm'
        end as status,
        case
            when labels @> '["ISSM::ReviewRequired"]' then web_url || ' is closed without ISSM review'
            when labels @> '["ISSM::Approved"]' then web_url || ' is closed with ISSM approval'
            when labels @> '["ISSM::Rejected"]' then web_url || ' is closed with ISSM rejection'
            else web_url || ' is closed, does not indicate ISSM review status and requires manual review'
        end as reason
    from gitlab_issue
    where project_id = ${var.gitlab_project_id}
        and state = 'closed'
        and labels @> '["incident"]'
  EOQ
}

control "gitlab_ensure_incident_issues_not_closed_without_completing_review" {
  title       = "Ensure GitLab incident issues are not closed without completing review"
  description = "Incident issues should not be closed without completing the review process. This control checks that no s are closed without completing the review process in accordance with system procedures."
  query       = query.gitlab_ensure_incident_issues_not_closed_without_completing_review
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_incident_issues_not_closed_without_completing_review" {
  sql = <<-EOQ
    select
        web_url as resource,
        labels,
        case
            when labels @> '["Incident::Review-Completed"]' then 'ok'
            else 'alarm'
        end as status,
        case
            when labels @> '["Incident::Resolved"]' then web_url || ' is closed but does not indicate review status'
            when labels @> '["Incident::Review-Scheduled"]' then web_url || ' is closed but indicates that review has not been completed'
            when labels @> '["Incident::Review-Completed"]' then web_url || ' is closed with review completed'
            else web_url || ' with labels ' || labels || ' does not indicate review status and requires manual review'
        end as reason
    from gitlab_issue
    where project_id = ${var.gitlab_project_id}
        and state = 'closed'
        and labels @> '["incident"]'
  EOQ
}


control "gitlab_ensure_vulnerability_issues_not_overdue_without_being_on_poam" {
  title       = "Ensure vulnerability issues tracked in GitLab are not overdue without being on Plan of Action and Milestones (POAM)"
  description = "Vulnerability issues should not be overdue without being documented in the Plan of Action and Milestones (POAM). This control checks that no vulnerability issues are overdue without being documented in the POAM."
  query       = query.no_overdue_vulnerability_issues_without_poam
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "no_overdue_vulnerability_issues_without_poam" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      case
          when labels @> '["POA&M"]' then 'ok'
          -- Check that due date is in the future
          when due_date > now() then 'ok'
          else 'alarm'
      end as status,
      case
          when due_date < now() and not labels @> '["POA&M"]' then web_url || ' is past due and not documented on POA&M'
          when due_date is null then web_url || ' is open but does not indicate a due date'
          when due_date < now() and labels @> '["POA&M"]' then web_url || ' is open and past due but documented on POA&M'
          when due_date > now() then web_url || ' is open and not past past due'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state = 'opened'
      and labels @> '["Vulnerability"]'
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}

control "gitlab_ensure_compliance_issues_not_overdue_without_being_on_poam" {
  title       = "Ensure compliance issues tracked in GitLab are not overdue without being on Plan of Action and Milestones (POAM)"
  description = "Compliance issues should not be overdue without being documented in the Plan of Action and Milestones (POAM). This control checks that no compliance issues are overdue without being documented in the POAM."
  query       = query.no_overdue_compliance_issues_without_poam
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "no_overdue_compliance_issues_without_poam" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      case
          when labels @> '["POA&M"]' then 'ok'
          -- Check that due date is in the future
          when due_date > now() then 'ok'
          else 'alarm'
      end as status,
      case
          when due_date < now() and not labels @> '["POA&M"]' then web_url || ' is past due and not documented on POA&M'
          when due_date is null then web_url || ' is open but does not indicate a due date'
          when due_date < now() and labels @> '["POA&M"]' then web_url || ' is open and past due but documented on POA&M'
          when due_date > now() then web_url || ' is open and not past past due'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state = 'opened'
      and (labels @> '["Compliance::AutomaticCheck"]' or labels @> '["Compliance::ManualCheck"]')
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}

control "gitlab_ensure_vulnerability_issues_assigned_to_finding_owner" {
  title       = "Ensure vulnerability issues in GitLab are assigned to a finding owner"
  description = "Vulnerability issues should be assigned to a finding owner. This control checks that no open vulnerability issues are not assigned to a finding owner."
  query       = query.gitlab_ensure_vulnerability_issues_assigned_to_finding_owner
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_vulnerability_issues_assigned_to_finding_owner" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      assignee_id,
      case
          when assignee_id is not null then 'ok'
          else 'alarm'
      end as status,
      case
          when assignee_id is null then web_url || ' is open but not assigned to a finding owner'
          else web_url || ' is open and assigned to a finding owner'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state = 'opened'
      and labels @> '["Vulnerability"]'
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}

control "gitlab_ensure_compliance_issues_assigned_to_finding_owner" {
  title       = "Ensure compliance issues in GitLab are assigned to a finding owner"
  description = "Compliance issues should be assigned to a finding owner. This control checks that no open compliance issues are not assigned to a finding owner."
  query       = query.gitlab_ensure_compliance_issues_assigned_to_finding_owner
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_compliance_issues_assigned_to_finding_owner" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      assignee_id,
      case
          when assignee_id is not null then 'ok'
          else 'alarm'
      end as status,
      case
          when assignee_id is null then web_url || ' is open but not assigned to a finding owner'
          else web_url || ' is open and assigned to a finding owner'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state = 'opened'
      and (labels @> '["Compliance::AutomaticCheck"]' or labels @> '["Compliance::ManualCheck"]')
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}

control "gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval" {
  title       = "Ensure GitLab access modifications are not closed without ISSM review and approval of access and validation of required training"
  description = "Access modifications should not be completed and closed without ISSM review and approval. This control checks that no access modifications are closed without documented approval in accordance with system policy and procedure."
  query       = query.gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_permanent_access_modifications_not_closed_without_issm_approval" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      state,
      case
          when state='closed' and not labels @> '["ISSM::Approved"]' then 'alarm'
          else 'ok'
      end as status,
      case
          when (state='closed' and not labels @> '["ISSM::Approved"]') then web_url || ' is closed without ISSM approval'
          when state='closed' and labels @> '["ISSM::Approved"]' then web_url || ' is closed with ISSM approval'
          when state='opened' then web_url || ' is open and in progress'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["AccessModification::Permanent"]'
  EOQ
}

control "gitlab_ensure_source_controlled_change_management_process" {
  title       = "Ensure a source controlled change management process is documented in GitLab"
  description = "Change management processes should be documented under source control in a centralized repository accessible to the system team."
  query       = query.gitlab_ensure_source_controlled_change_management_process
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_source_controlled_change_management_process" {
  sql = <<-EOQ
    select
      'playbooks/change-management.md' as resource,
      t.ref,
      t.commit_id,
      case
          when t.file_path is not null then 'ok'
          else 'alarm'
      end as status,
      case
          when t.file_path is not null then 'File exists: playbooks/change-management.md'
          else 'File missing: playbooks/change-management.md'
      end as reason
  from (
      select
          file_path,
          ref,
          commit_id
      from gitlab_project_repository_file
      where project_id = ${var.gitlab_project_id}
        and file_path = 'playbooks/change-management.md'
      limit 1
  ) t
  right join (select 1 as dummy) d on true
  EOQ
}

control "gitlab_ensure_change_requests_not_closed_without_issm_approval_or_rejection" {
  title       = "Ensure GitLab change requests are not closed without ISSM review and approval or rejection"
  description = "Change requests should not be closed without ISSM review and approval or rejection. This control checks that no change requests are closed without documented approval or rejection in accordance with system procedures."
  query       = query.gitlab_ensure_change_requests_not_closed_without_issm_approval_or_rejection
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_change_requests_not_closed_without_issm_approval_or_rejection" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      state,
      case
          when state='closed' and not labels @> '["ISSM::Approved"]' and not labels @> '["ISSM::Rejected"]' then 'alarm'
          else 'ok'
      end as status,
      case
          when (state='closed' and not labels @> '["ISSM::Approved"]' and not labels @> '["ISSM::Rejected"]') then web_url || ' is closed without ISSM approval or rejection'
          when state='closed' and labels @> '["ISSM::Approved"]' then web_url || ' is closed with ISSM approval'
          when state='closed' and labels @> '["ISSM::Rejected"]' then web_url || ' is closed with ISSM rejection'
          when state='opened' then web_url || ' is open and in progress'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state='closed'
      and (labels @> '["ConfigurationChange::Minor"]' or labels @> '["ConfigurationChange::Major"]')
  EOQ
}

control "gitlab_ensure_all_change_requests_indicate_criticality" {
  title       = "Ensure all GitLab change requests indicate criticality"
  description = "Change requests should indicate their criticality using scoped labels. This control checks that all change requests have a criticality label."
  query       = query.gitlab_ensure_all_change_requests_indicate_criticality
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_all_change_requests_indicate_criticality" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when labels @> '["C::4"]' or labels @> '["C::3"]' or labels @> '["C::2"]' or labels @> '["C::1"]' then 'ok'
          else 'alarm'
      end as status,
      case
          when labels @> '["C::4"]' then web_url || ' is labeled as Criticality 4'
          when labels @> '["C::3"]' then web_url || ' is labeled as Criticality 3'
          when labels @> '["C::2"]' then web_url || ' is labeled as Criticality 2'
          when labels @> '["C::1"]' then web_url || ' is labeled as Criticality 1'
          else web_url || ' with labels ' || labels || ' does not have a criticality label and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and (labels @> '["ConfigurationChange::Minor"]' or labels @> '["ConfigurationChange::Major"]')
  EOQ
}

control "gitlab_ensure_all_change_requests_document_impact_analysis" {
  title       = "Ensure all GitLab change requests document impact analysis"
  description = "Change requests should document impact analysis in the description field using defined section header. This control checks that all change requests have an impact analysis documented."
  query       = query.gitlab_ensure_all_change_requests_document_impact_analysis
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}
query "gitlab_ensure_all_change_requests_document_impact_analysis" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%## Impact Analysis%' then 'ok'
          else 'alarm'
      end as status,
      case
          when description like '%## Impact Analysis%' then web_url || ' has impact analysis documented in description'
          else web_url || ' with labels ' || labels || ' does not have impact analysis documented in description and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and (labels @> '["ConfigurationChange::Minor"]' or labels @> '["ConfigurationChange::Major"]')
  EOQ
}

control "gitlab_ensure_daily_review_tasks_not_closed_with_incomplete_checklist" {
  title       = "Ensure Threatalert daily review task issues are not closed with incomplete checklist"
  description = "ThreatAlert daily reviews define a checklist. Daily review task issues should not be closed without a completed checklist."
  query       = query.gitlab_ensure_daily_review_tasks_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_daily_review_tasks_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::daily"]'
      and labels @> '["Review"]'
      and state = 'closed'
  EOQ
}

control "gitlab_ensure_daily_review_tasks_are_completed_and_closed_on_time" {
  title       = "Ensure Threatalert daily review task issues are completed and closed on time"
  description = "ThreatAlert daily reviews should be completed and closed on time. This control checks that no daily review task issues are overdue."
  query       = query.gitlab_ensure_daily_review_tasks_are_completed_and_closed_on_time
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "low",
  })
}

query "gitlab_ensure_daily_review_tasks_are_completed_and_closed_on_time" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      due_date,
      case
          when due_date > now() then 'ok'
          when due_date <= now() - interval '1 day' then 'alarm'
          else 'ok'
      end as status,
      case
          when due_date is null then web_url || ' has no due date'
          when due_date > now() then web_url || ' is not overdue'
          when due_date <= now() - interval '1 day' then web_url || ' is overdue by more than one day and requires manual review'
          else web_url || ' is due in less than one day'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::daily"]'
      and labels @> '["Review"]'
      and state = 'opened'
  EOQ
}

control "gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist" {
  title       = "Ensure Threatalert weekly review task issues are not closed with incomplete checklist items"
  description = "ThreatAlert weekly reviews define a checklist. Weekly review task issues should not be closed without a completed checklist."
  query       = query.gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_weekly_review_tasks_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::weekly"]'
      and labels @> '["Review"]'
      and state = 'closed'
  EOQ
}

control "gitlab_ensure_weekly_review_tasks_are_completed_on_time" {
  title       = "Ensure Threatalert weekly review task issues are completed and closed on time"
  description = "ThreatAlert weekly reviews should be completed and closed on time. This control checks that no weekly review task issues are overdue."
  query       = query.gitlab_ensure_weekly_review_tasks_are_completed_on_time
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "low",
  })
}

query "gitlab_ensure_weekly_review_tasks_are_completed_on_time" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      due_date,
      case
          when due_date > now() then 'ok'
          when due_date <= now() - interval '1 week' then 'alarm'
          else 'ok'
      end as status,
      case
          when due_date is null then web_url || ' has no due date'
          when due_date > now() then web_url || ' is not overdue'
          when due_date <= now() - interval '1 week' then web_url || ' is overdue by more than one week and requires manual review'
          else web_url || ' is due in less than one week'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::weekly"]'
      and labels @> '["Review"]'
      and state = 'opened'
  EOQ
}

control "gitlab_ensure_rto_documented_in_criticality_analysis" {
  title       = "Ensure RTO is documented in source controlled criticality analysis for system."
  description = "The Recovery Time Objective (RTO) should be documented in the criticality analysis for the system. This control checks that the RTO is documented in the criticality analysis file."
  query       = query.gitlab_ensure_rto_documented_in_criticality_analysis
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_rto_documented_in_criticality_analysis" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/ssp_appendices/%criticality-analysis%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '\|.*\(RTO\).*?\|\s*\n\|[-| ]+\|\s*\n(?:.*\n)*?\|[^|]*\|[^|]*\|[^|]*\|[^|]*\S[^|]*\|[^|]*\|',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '\|.*\(RTO\).*?\|\s*\n\|[-| ]+\|\s*\n(?:.*\n)*?\|[^|]*\|[^|]*\|[^|]*\|[^|]*\S[^|]*\|[^|]*\|',
                  'n'
              ) is not null
          then 'RTO assertions present in: ' || filtered_files.path
          else 'RTO assertions not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'authorization-package/ssp_appendices/*criticality-analysis*.md' as resource,
      -- null as content,
      'alarm' as status,
      'No RTO found in authorization-package/ssp_appendices/*criticality-analysis*.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_rpo_documented_in_criticality_analysis" {
  title       = "Ensure RPO is documented in source controlled criticality analysis for system."
  description = "The Recovery Point Objective (RPO) should be documented in the criticality analysis for the system. This control checks that the RPO is documented in the criticality analysis file."
  query       = query.gitlab_ensure_rpo_documented_in_criticality_analysis
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_rpo_documented_in_criticality_analysis" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/ssp_appendices/%criticality-analysis%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '\|.*\(RPO\).*?\|\s*\n\|[-| ]+\|\s*\n(?:.*\n)*?\|[^|]*\|[^|]*\|[^|]*\|[^|]*\S[^|]*\|[^|]*\|',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '\|.*\(RPO\).*?\|\s*\n\|[-| ]+\|\s*\n(?:.*\n)*?\|[^|]*\|[^|]*\|[^|]*\|[^|]*\S[^|]*\|[^|]*\|',
                  'n'
              ) is not null
          then 'RPO assertions present in: ' || filtered_files.path
          else 'RPO assertions not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'authorization-package/ssp_appendices/*criticality-analysis*.md' as resource,
      -- null as content,
      'alarm' as status,
      'No RPO found in authorization-package/ssp_appendices/*criticality-analysis*.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_recovery_plan_documented_in_iscp" {
  title       = "Ensure recovery plan is documented in source controlled Information System Contingency Plan (ISCP) for system."
  description = "The recovery plan should be documented in the Information System Contingency Plan (ISCP) for the system. This control checks that the recovery plan is documented in the ISCP file."
  query       = query.gitlab_ensure_recovery_plan_documented_in_iscp
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_recovery_plan_documented_in_iscp" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/ssp_appendices/%iscp%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '## Recovery Procedures\s*\n((?:(?!^## ).*\n){10,})',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '## Recovery Procedures\s*\n((?:(?!^## ).*\n){10,})',
                  'n'
              ) is not null
          then 'Sufficiently detailed (10+) recovery procedures defined in: ' || filtered_files.path
          else 'Sufficiently detailed (10+) recovery procedures not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'authorization-package/ssp_appendices/*iscp*.md' as resource,
      'alarm' as status,
      'No result found for authorization-package/ssp_appendices/*iscp*.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_external_reporting_process_documented_in_irp" {
  title       = "Ensure external reporting process is documented in source controlled Incident Response Plan (IRP) for system."
  description = "The external reporting process should be documented in the Incident Response Plan (IRP) for the system. This control checks that the external reporting process is documented in the IRP file."
  query       = query.gitlab_ensure_external_reporting_process_documented_in_irp
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_external_reporting_process_documented_in_irp" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/ssp_appendices/%irp%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
      -- extract any content so that it can be evaluated in case of benchmark failure
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '### External Reporting Process\s*\n((?:(?!^### ).*\n){10,})',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '### External Reporting Process\s*\n((?:(?!^### ).*\n){10,})',
                  'n'
              ) is not null
          then 'Sufficiently detailed (10+ line) external reporting process defined in: ' || filtered_files.path
          else 'Sufficiently detailed (10+ line) external reporting process not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'authorization-package/ssp_appendices/*irp*.md' as resource,
      'alarm' as status,
      'No result found for authorization-package/ssp_appendices/*irp*.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_security_analyst_active_within_last_3_days" {
  title       = "Ensure security analyst is active within the last 3 days"
  description = "This control checks that the security analyst has been active in GitLab within the last 3 days."
  query       = query.gitlab_ensure_security_analyst_active_within_last_3_days
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_security_analyst_active_within_last_3_days" {
  sql = <<-EOQ
    select 
      web_url as resource,
      id,
      case
          when current_sign_in_at > now() - interval '3 days' then 'ok'
          else 'alarm'
      end as status,
      case
          when current_sign_in_at > now() - interval '3 days' then id || ' last signed in at ' || current_sign_in_at
          when current_sign_in_at is null then id || ' has no recorded activity'
          else id || ' last signed in at ' || current_sign_in_at || ' which is more than 3 days ago'
      end as reason
  from gitlab_user
  where id=${var.gitlab_security_analyst_id}
  EOQ
}

control "gitlab_ensure_issm_active_within_last_3_days" {
  title       = "Ensure ISSM is active within the last 3 days"
  description = "This control checks that the Information System Security Manager (ISSM) has been active in GitLab within the last 3 days."
  query       = query.gitlab_ensure_issm_active_within_last_3_days
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_issm_active_within_last_3_days" {
  sql = <<-EOQ
  select 
      web_url as resource,
      id,
      case
          when current_sign_in_at > now() - interval '3 days' then 'ok'
          else 'alarm'
      end as status,
      case
          when current_sign_in_at > now() - interval '3 days' then id || ' last signed in at ' || current_sign_in_at
          when current_sign_in_at is null then id || ' has no recorded activity'
          else id || ' last signed in at ' || current_sign_in_at || ' which is more than 3 days ago'
      end as reason
  from gitlab_user
  where id=${var.gitlab_issm_id}
  EOQ
}

control "gitlab_ensure_security_engineer_active_within_last_3_days" {
  title       = "Ensure security engineer is active within the last 3 days"
  description = "This control checks that the security engineer has been active in GitLab within the last 3 days."
  query       = query.gitlab_ensure_security_engineer_active_within_last_3_days
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_security_engineer_active_within_last_3_days" {
  sql = <<-EOQ
  select 
      web_url as resource,
      id,
      case
          when current_sign_in_at > now() - interval '3 days' then 'ok'
          else 'alarm'
      end as status,
      case
          when current_sign_in_at > now() - interval '3 days' then id || ' last signed in at ' || current_sign_in_at
          when current_sign_in_at is null then id || ' has no recorded activity'
          else id || ' last signed in at ' || current_sign_in_at || ' which is more than 3 days ago'
      end as reason
  from gitlab_user
  where id=${var.gitlab_security_engineer_id}
  EOQ
}

control "gitlab_ensure_continuous_monitoring_playbook_documented" {
  title       = "Ensure continuous monitoring playbook is documented in GitLab"
  description = "The continuous monitoring playbook should be documented in GitLab. This control checks that the playbook exists and defines a sufficiently detailed overview."
  query       = query.gitlab_ensure_continuous_monitoring_playbook_documented
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_continuous_monitoring_playbook_documented" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'playbooks/%continuous-monitoring%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
      -- extract any content so that it can be evaluated in case of benchmark failure
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '# Overview\s*\n((?:(?!^# ).*\n){10,})',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '# Overview\s*\n((?:(?!^# ).*\n){10,})',
                  'n'
              ) is not null
          then 'Sufficiently detailed (10+ line) monitoring overview defined in: ' || filtered_files.path
          else 'Sufficiently detailed (10+ line) monitoring overview not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'playbooks/continuous-monitoring.md' as resource,
      'alarm' as status,
      'No result found for playbooks/continuous-monitoring.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_inventory_and_scan_review_not_closed_with_incomplete_checklist" {
  title       = "Ensure Threatalert inventory and scan review task issues are not closed with incomplete checklist"
  description = "ThreatAlert inventory and scan reviews define a checklist to guide completion for all requirements. Inventory and scan review task issues should not be closed without a completed checklist."
  query       = query.gitlab_ensure_inventory_and_scan_review_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_inventory_and_scan_review_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::weekly"]'
      and labels @> '["Review"]'
      and state = 'closed'
  EOQ
}

control "gitlab_ensure_least_functionality_review_not_closed_with_incomplete_checklist" {
  title       = "Ensure Threatalert least functionality review task issues are not closed with incomplete checklist"
  description = "ThreatAlert least functionality reviews define a checklist to guide completion for all requirements. Least functionality review task issues should not be closed without a completed checklist."
  query       = query.gitlab_ensure_least_functionality_review_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_least_functionality_review_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["Review"]'
      and state = 'closed'
      and title like '%Least Functionality%'
  EOQ
}

control "gitlab_ensure_disclosure_program_component_definition_defined" {
  title       = "Ensure Threatalert disclosure program component definition is documented in GitLab"
  description = "The disclosure program component definition should be documented in GitLab. This control checks that the component definition exists and defines a sufficiently detailed overview."
  query       = query.gitlab_ensure_disclosure_program_component_definition_documented
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_disclosure_program_component_definition_documented" {
  sql = <<-EOQ
  -- Need to first filter files from the repository that match the path pattern
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/component_definition_registry/%disclosure%program%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
      -- extract any content so that it can be evaluated in case of benchmark failure
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '## description\s*\n((?:(?!^## ).*\n){2,})',
                  'n'
              ) is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(
                  convert_from(decode(rf.content, 'base64'), 'UTF8'),
                  '## description\s*\n((?:(?!^## ).*\n){2,})',
                  'n'
              ) is not null
          then 'Disclosure program defined in: ' || filtered_files.path
          else 'Disclosure program not found in: ' || filtered_files.path
      end as reason
  from filtered_files
  -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  -- If no matches for anything above, show a single alarm result
  select
      'authorization-package/component_definition_registry/*disclosure*program*.md' as resource,
      'alarm' as status,
      'No result found for authorization-package/component_definition_registry/*disclosure*program*.md' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_harden_and_review_network_and_system_configurations" {
  title       = "Ensure network and system configurations are hardened and reviewed"
  description = "Network and system configurations should be hardened and reviewed to ensure security. This control checks that all relevant issues are closed with appropriate labels."
  query       = query.gitlab_harden_and_review_network_and_system_configurations
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_harden_and_review_network_and_system_configurations" {
  sql = <<-EOQ
    select
      'Boundary Traffic Flow Review' as resource,
      count(*) as total_reviews,
      case
          when count(*) < 1 then 'alarm'
          else 'ok'
      end as status,
      case
          when count(*) < 1 then 'No ISSM approved network reviews found in the last 90 days'
          else 'Found ' || count(*) || ' ISSM approved network reviews in the last 90 days'
      end as reason
    from gitlab_issue
    where project_id = ${var.gitlab_project_id}
      and state='closed'
      and (labels @> '["ISSM::ReviewRequired"]' and labels @> '["Review"]' and labels @> '["ISSM::Approved"]')
      and title ilike '%Boundary Traffic Flow Review%'
      and due_date >= now() - interval '90 days'
  EOQ
}

control "gitlab_ensure_documented_process_for_monitoring_vulnerabilities" {
  title       = "Ensure documented process for monitoring vulnerabilities"
  description = "There should be a documented process for monitoring vulnerabilities in GitLab. This control checks that the process is defined and documented."
  query       = query.gitlab_ensure_documented_process_for_monitoring_vulnerabilities
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_documented_process_for_monitoring_vulnerabilities" {
  sql = <<-EOQ
    -- Need to first filter files from the repository that match the path pattern
    with filtered_files as (
        select path
        from gitlab_project_repository
        where path like 'playbooks/%finding-management%.md'
        and project_id = 1
    )
    select
        filtered_files.path as resource,
        -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
        -- extract any content so that it can be evaluated in case of benchmark failure
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    '# Purpose\s*\n((?:(?!^# ).*\n){3,})',
                    'n'
                ) is not null
            then 'ok'
            else 'alarm'
        end as status,
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    '# Purpose\s*\n((?:(?!^# ).*\n){3,})',
                    'n'
                ) is not null
            then 'Sufficiently detailed (3+ line) purpose defined in: ' || filtered_files.path
            else 'Sufficiently detailed (3+ line) purpose not found in: ' || filtered_files.path
        end as reason
    from filtered_files
    -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
    left join gitlab_project_repository_file rf
        on filtered_files.path = rf.file_path
        where rf.project_id = 1
        and rf.file_path = filtered_files.path
    union all
    -- If no matches for anything above, show a single alarm result
    select
        'playbooks/finding-management.md' as resource,
        'alarm' as status,
        'No result found for playbooks/finding-management.md' as reason
    where not exists (
        select 1 from filtered_files
    )
  EOQ
}

control "gitlab_ensure_change_request_not_completed_without_testing" {
  title       = "Ensure change requests are not completed without testing"
  description = "Change requests should not be completed without testing. This control checks that all change requests have appropriate test result assertions."
  query       = query.gitlab_ensure_change_request_not_completed_without_testing
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_change_request_not_completed_without_testing" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      --state,
      case
          when description like '%[x] [Test Change]%' then 'ok'
          when description like '%[x] Test Change%' then 'ok'
          when description like '%[X] [Test Change]%' then 'ok'
          when description like '%[X] Test Change%' then 'ok'
          else 'alarm'
      end as status,
      case
          when description like '%[x] [Test Change]%' then web_url || ' has confirmed testing was completed for this CR'
          when description like '%[x] Test Change%' then web_url || ' has confirmed testing was completed for this CR'
          when description like '%[X] [Test Change]%' then web_url || ' has confirmed testing was completed for this CR'
          when description like '%[X] Test Change%' then web_url || ' has confirmed testing was completed for this CR'
          else web_url || ' with labels ' || labels || ' does NOT confirm testing was completed for this CR'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and (labels @> '["ConfigurationChange::Minor"]' or labels @> '["ConfigurationChange::Major"]')
      and (labels @> '["change::complete"]')      
  EOQ
}

control "gitlab_ensure_roles_and_odps_defined" {
    title = "Ensure roles and Organizationally Defined Parameters (ODPs) defined in source controlled documentation"
    description = "Roles and Organizationally Defined Parameters (ODPs) define the security objectives for the system. They should be source controlled in a machine readable format within GitLab."
    query = query.gitlab_ensure_roles_and_odps_defined
    tags = merge(local.gitlab_threatalert_common_tags, {
        severity = "moderate",
    })
}

query "gitlab_ensure_roles_and_odps_defined" {
    sql = <<-EOT
    -- Need to first filter files from the repository that match the path pattern
    with filtered_files as (
        select path
        from gitlab_project_repository
        where path like 'authorization-package/policies_procedures/%odps%.yaml'
        and project_id = ${var.gitlab_project_id}
    )
    select
        filtered_files.path as resource,
        -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    'odps:\s*\n((?:(?!odps:).*\n){2,})',
                    'n'
                ) is not null
            then 'ok'
            else 'alarm'
        end as status,
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    'odps:\s*\n((?:(?!odps:).*\n){2,})',
                    'n'
                ) is not null
            then 'Organizationally Defined Parameters defined in: ' || filtered_files.path
            else 'Organizationally Defined Parameters not found in: ' || filtered_files.path
        end as reason
    from filtered_files
    -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
    left join gitlab_project_repository_file rf
        on filtered_files.path = rf.file_path
        where rf.project_id = ${var.gitlab_project_id}
        and rf.file_path = filtered_files.path
    union all
    -- If no matches for anything above, show a single alarm result
    select
        'authorization-package/policies_procedures/%odps%.yaml' as resource,
        'alarm' as status,
        'No result found for authorization-package/policies_procedures/%odps%.yaml' as reason
    where not exists (
        select 1 from filtered_files
    )
    EOT
}

control "gitlab_ensure_ssp_service_tables_exist_and_populated" {
  title       = "Ensure required service tables exist and are populated in SSP"
  description = "Checks that both Leveraged FedRAMP-Authorized Services and External Systems and Services Not Having FedRAMP Authorization tables exist in the SSP and contain data."
  query       = query.gitlab_ensure_ssp_service_tables_exist_and_populated
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_ssp_service_tables_exist_and_populated" {
  sql = <<-EOQ
  with filtered_files as (
      select path
      from gitlab_project_repository
      where path like 'authorization-package/ssp/%ssp%.md'
      and project_id = ${var.gitlab_project_id}
  )
  select
      filtered_files.path as resource,
      case
          when
              regexp_match(convert_from(decode(rf.content, 'base64'), 'UTF8'), '\\| CSP/CSO Name \\(Name on FedRAMP Marketplace\\) \\|.*\\n\\|.*\\n(\\|.*\\n)+', 'n') is not null
              and regexp_match(convert_from(decode(rf.content, 'base64'), 'UTF8'), '\\| System/ Service/ API/CLI Name \\(Non-FedRAMP Cloud Services\\) \\|.*\\n\\|.*\\n(\\|.*\\n)+', 'n') is not null
          then 'ok'
          else 'alarm'
      end as status,
      case
          when
              regexp_match(convert_from(decode(rf.content, 'base64'), 'UTF8'), '\\| CSP/CSO Name \\(Name on FedRAMP Marketplace\\) \\|.*\\n\\|.*\\n(\\|.*\\n)+', 'n') is not null
              and regexp_match(convert_from(decode(rf.content, 'base64'), 'UTF8'), '\\| System/ Service/ API/CLI Name \\(Non-FedRAMP Cloud Services\\) \\|.*\\n\\|.*\\n(\\|.*\\n)+', 'n') is not null
          then 'Both required tables exist and are populated in: ' || filtered_files.path
          else 'One or both required tables missing or empty in: ' || filtered_files.path
      end as reason
  from filtered_files
  left join gitlab_project_repository_file rf
      on filtered_files.path = rf.file_path
      where rf.project_id = ${var.gitlab_project_id}
      and rf.file_path = filtered_files.path
  union all
  select
      'authorization-package/ssp/%ssp%.md' as resource,
      'alarm' as status,
      'No SSP file found for required tables.' as reason
  where not exists (
      select 1 from filtered_files
  )
  EOQ
}

control "gitlab_ensure_source_controlled_account_management_process" {
  title       = "Ensure a source controlled account management process is documented in GitLab"
  description = "Account management processes should be documented under source control in a centralized repository accessible to the system team."
  query       = query.gitlab_ensure_source_controlled_account_management_process
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_source_controlled_account_management_process" {
  sql = <<-EOQ
    select
      'playbooks/account-management.md' as resource,
      t.ref,
      t.commit_id,
      case
          when t.file_path is not null then 'ok'
          else 'alarm'
      end as status,
      case
          when t.file_path is not null then 'File exists: playbooks/account-management.md'
          else 'File missing: playbooks/account-management.md'
      end as reason
  from (
      select
          file_path,
          ref,
          commit_id
      from gitlab_project_repository_file
      where project_id = ${var.gitlab_project_id}
        and file_path = 'playbooks/account-management.md'
      limit 1
  ) t
  right join (select 1 as dummy) d on true
  EOQ
}

control "gitlab_ensure_monthly_report_not_closed_with_incomplete_checklist" {
  title       = "Ensure Threatalert monthly report task issues are not closed with incomplete checklist"
  description = "ThreatAlert monthly report tasks define a checklist to guide completion for all requirements. Monthly report task issues should not be closed without a completed checklist."
  query       = query.gitlab_ensure_monthly_report_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_monthly_report_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::monthly"]'
      and labels @> '["Review"]'
      and state = 'closed'
      and title like '%Monthly Report%'
  EOQ
}

control "gitlab_ensure_supply_chain_risk_exposure_level_defined" {
  title       = "Ensure that supply chain risk exposure level is defined in source controlled documentation"
  description = "Checks that the Final Risk Exposure Level for Supply Chain Risk is defined in the source controlled documentation."
  query       = query.gitlab_ensure_supply_chain_risk_exposure_level_defined
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_supply_chain_risk_exposure_level_defined" {
  sql = <<-EOQ
    -- Need to first filter files from the repository that match the path pattern
    with filtered_files as (
        select path
        from gitlab_project_repository
        where path like 'authorization-package/supply_chain_risk_assessments/%assessment%.md'
        and project_id = ${var.gitlab_project_id}
    )
    select
        filtered_files.path as resource,
        -- convert_from(decode(rf.content, 'base64'), 'UTF8') as content,
        -- extract any content so that it can be evaluated in case of benchmark failure
        regexp_match(
            convert_from(decode(rf.content, 'base64'), 'UTF8'),
            '## Final Risk Exposure Level\s*\n((?:(?!^##).*\n){1,})',
            'n'
        ) as risk_exposure_level,
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    '## Final Risk Exposure Level\s*\n((?:(?!^##).*\n){1,})',
                    'n'
                ) is not null
            then 'ok'
            else 'alarm'
        end as status,
        case
            when
                regexp_match(
                    convert_from(decode(rf.content, 'base64'), 'UTF8'),
                    '## Final Risk Exposure Level\s*\n((?:(?!^##).*\n){1,})',
                    'n'
                ) is not null
            then 'Final risk exposure level defined in: ' || filtered_files.path
            else 'Final risk exposure level not found in: ' || filtered_files.path
        end as reason
    from filtered_files
    -- Left join with gitlab_project_repository_file to get the content (as it must have the path specified exactly)
    left join gitlab_project_repository_file rf
        on filtered_files.path = rf.file_path
        where rf.project_id = ${var.gitlab_project_id}
        and rf.file_path = filtered_files.path
    union all
    -- If no matches for anything above, show a single alarm result
    select
        'authorization-package/supply_chain_risk_assessments/%assessment%.md' as resource,
        null as risk_exposure_level,
        'alarm' as status,
        'No result found for authorization-package/supply_chain_risk_assessments/%assessment%.md' as reason
    where not exists (
        select 1 from filtered_files
    )
  EOQ
}

control "gitlab_ensure_source_controlled_supply_chain_risk_management_plan" {
  title       = "Ensure a source controlled supply chain risk management plan is documented in GitLab"
  description = "Supply chain risk management plans should be documented under source control in a centralized repository accessible to the system team."
  query       = query.gitlab_ensure_source_controlled_supply_chain_risk_management_plan
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_source_controlled_supply_chain_risk_management_plan" {
  sql = <<-EOQ
    with filtered_files as (
      select path
      from gitlab_project_repository
      where project_id = ${var.gitlab_project_id}
        and path like 'authorization-package/ssp_appendices/%supply-chain-risk-management-plan.md'
      limit 1
    )
    select
      coalesce(ff.path, 'authorization-package/ssp_appendices/%supply-chain-risk-management-plan.md') as resource,
      rf.ref,
      rf.commit_id,
      case
        when ff.path is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when ff.path is not null then 'File exists: ' || ff.path
        else 'Supply chain risk management plan file missing.'
      end as reason
    from filtered_files ff
    left join gitlab_project_repository_file rf
      on rf.file_path = ff.path and rf.project_id = ${var.gitlab_project_id}
    union all
    select
      'authorization-package/ssp_appendices/%supply-chain-risk-management-plan.md' as resource,
      null as ref,
      null as commit_id,
      'alarm' as status,
      'No file matching pattern found.' as reason
    where not exists (select 1 from filtered_files)
  EOQ
}

control "gitlab_ensure_ir_cp_testing_issue_not_closed_with_incomplete_checklist" {
  title       = "Ensure ThreatAlert IR and CP testing issue is not closed with incomplete checklist"
  description = "ThreatAlert IR and CP testing task defines a checklist to guide completion for all testing requirements. IR and CP testing issue should not be closed without a completed checklist."
  query       = query.gitlab_ensure_ir_cp_testing_issue_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_ensure_ir_cp_testing_issue_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::annual"]'
      and labels @> '["Review"]'
      and state = 'closed'
      and title like '%IT Contingency Plan and Incident Response Testing%'
  EOQ
}

control "gitlab_ensure_ir_cp_tabletop_issue_not_closed_with_incomplete_checklist" {
  title       = "Ensure ThreatAlert CP and IR tabletop issue is not closed with incomplete checklist"
  description = "ThreatAlert IR and CP tabletop task defines a checklist to guide completion for all high system tabletop requirements. IR and CP tabletop issue should not be closed without a completed checklist."
  query       = query.gitlab_ensure_ir_cp_tabletop_issue_not_closed_with_incomplete_checklist
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "moderate",
  })
}

query "gitlab_ensure_ir_cp_tabletop_issue_not_closed_with_incomplete_checklist" {
  sql = <<-EOQ
  select
      web_url as resource,
      labels,
      state,
      case
          when description like '%- [ ]%' then 'alarm'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then 'alarm'
          else 'ok'
      end as status,
      case
          when description like '%- [ ]%' then web_url || ' has incomplete checklist items'
          when description not ilike '%- [x]%' and description not like '%- [ ]%' then web_url || ' has no checklist items defined'
          when description ilike '%- [x]%' then web_url || ' has only completed checklist items'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and labels @> '["integration::threatalert"]'
      and labels @> '["periodicity::annual"]'
      and labels @> '["Review"]'
      and state = 'closed'
      and title like '%Incident Response Tabletop Exercise%'
  EOQ
}

control "gitlab_default_iac_branch_protected" {
  title       = "Ensure default IaC branch is protected"
  description = "The Infrastructure as Code (IaC) repository default branch should be protected to ensure changes are made in a controlled and auditable manner."
  query       = query.gitlab_default_iac_branch_protected
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "gitlab_default_iac_branch_protected" {
  sql = <<-EOQ
    select
      b.web_url as resource,
        b.protected,
        b.default,
        case
            when b.protected then 'ok'
            else 'alarm'
        end as status,
        case
            when b.protected then 'Default iac branch is protected'
            else 'Default iac branch is not protected'
        end as reason
    from gitlab_branch as b
    where project_id = ${var.subsystem_iac_project_id}
        and b.default = true
  EOQ
}

control "terraform_lock_source_controlled_in_tf_repositories" {
  title       = "Ensure Terraform lock file is source controlled in Terraform IaC repositories"
  description = "The Terraform lock file should be source controlled in the Terraform Infrastructure as Code (IaC) repositories to ensure consistent dependency management. Refer to https://developer.hashicorp.com/terraform/language/files/dependency-lock"
  query       = query.terraform_lock_source_controlled_in_tf_repositories
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "terraform_lock_source_controlled_in_tf_repositories" {
  sql = <<-EOQ
    select
      '.terraform.lock.hcl' as resource,
      project_id,
      case 
        when not exists (
          select 1 
          from gitlab_project_repository gpr_tf 
          where gpr_tf.project_id = gpr.project_id 
            and gpr_tf.name like '%.tf'
        ) then 'skip'
        when exists (
          select 1 
          from gitlab_project_repository gpr2 
          where gpr2.project_id = gpr.project_id 
            and gpr2.name = '.terraform.lock.hcl'
        ) then 'ok'
        else 'alarm'
      end as status,
      case
        when not exists (
          select 1 
          from gitlab_project_repository gpr_tf 
          where gpr_tf.project_id = gpr.project_id 
            and gpr_tf.name like '%.tf'
        ) then 'No Terraform files identified for this repository; lock file check skipped.'
        when exists (
          select 1 
          from gitlab_project_repository gpr2 
          where gpr2.project_id = gpr.project_id 
            and gpr2.name = '.terraform.lock.hcl'
        ) then 'Terraform lock file is present in the project.'
        else 'Terraform lock file is missing in the repository despite Terraform files existing.'
      end as reason
    from (select distinct project_id from gitlab_project_repository where project_id = ${var.subsystem_iac_project_id}) gpr
  EOQ
}

control "terraform_defined_in_system_iac_project" {
  title       = "Ensure Terraform is defined in the system IaC project"
  description = "The system Infrastructure as Code (IaC) project defined for the Armory system should define Terraform as the IaC tool to ensure consistent infrastructure management."
  query       = query.terraform_defined_in_system_iac_project
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}

query "terraform_defined_in_system_iac_project" {
  sql = <<-EOQ
    -- This is an Armory-specific opinionated control.
    with tf_file_count as (
      select 
        project_id,
        count(*) as tf_files
      from gitlab_project_repository
      where project_id = ${var.subsystem_iac_project_id}
        and name like '%.tf'
      group by project_id
    ),
    gitlab_project_details as (
      select 
        id,
        name
      from gitlab_project
      where id = ${var.subsystem_iac_project_id}
    )
    select
      p.name as resource,
      case 
        when coalesce(tf_files, 0) > 0 then 'ok'
        else 'alarm'
      end as status,
      case 
        when coalesce(tf_files, 0) > 0 then (coalesce(tf_files, 0)) || ' Terraform files detected in the repository.'
        else 'No Terraform files detected in the system IAC repository. This indicates an omission or misconfiguration either in the system declaration or implementation.'
      end as reason
    from tf_file_count
    right join gitlab_project_details p on tf_file_count.project_id = p.id
    EOQ
}

control "gitlab_identify_vulnerability_findings_due_within_7_days" {
  title       = "Identify GitLab vulnerability findings due within 7 days"
  description = "This control identifies GitLab vulnerability findings that are due within 7 days. If finding issues are due within 7 days without being on the POA&M this returns an info. If finding issues are overdue without being on the POA&M this returns an alarm."
  query       = query.gitlab_identify_vulnerability_findings_due_within_7_days
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}


query "gitlab_identify_vulnerability_findings_due_within_7_days" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      case
          when labels @> '["POA&M"]' then 'ok'
          when due_date < now() then 'alarm'
          when due_date <= now() + interval '7 days' then 'info'
          when due_date > now() + interval '7 days' then 'ok'
          else 'alarm'
      end as status,
      case
          when due_date is null then web_url || ' is open but does not indicate a due date'
          when due_date < now() and not labels @> '["POA&M"]' then web_url || ' is past due (' || due_date || ') and not documented on POA&M'
          when due_date < now() and labels @> '["POA&M"]' then web_url || ' is open and past due (' || due_date || ') but documented on POA&M'
          when due_date <= now() + interval '7 days' and not labels @> '["POA&M"]' then web_url || ' is due in under 7 days (' || due_date || ') and not documented on POA&M. Take care to ensure that remediation is escalated and completed in time.'
          when due_date > now() + interval '7 days' then web_url || ' is open and not past past due (due on ' || due_date || ')'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = ${var.gitlab_project_id}
      and state = 'opened'
      and labels @> '["Vulnerability"]'
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}


control "gitlab_identify_compliance_findings_due_within_7_days" {
  title       = "Identify GitLab compliance findings due within 7 days"
  description = "This control identifies GitLab compliance findings that are due within 7 days. If finding issues are due within 7 days without being on the POA&M this returns an info. If finding issues are overdue without being on the POA&M this returns an alarm."
  query       = query.gitlab_identify_compliance_findings_due_within_7_days
  tags        = merge(local.gitlab_threatalert_common_tags, {
    severity = "high",
  })
}


query "gitlab_identify_compliance_findings_due_within_7_days" {
  sql = <<-EOQ
    select
      web_url as resource,
      labels,
      case
          when labels @> '["POA&M"]' then 'ok'
          when due_date < now() then 'alarm'
          when due_date <= now() + interval '7 days' then 'info'
          when due_date > now() + interval '7 days' then 'ok'
          else 'alarm'
      end as status,
      case
          when due_date is null then web_url || ' is open but does not indicate a due date'
          when due_date < now() and not labels @> '["POA&M"]' then web_url || ' is past due (' || due_date || ') and not documented on POA&M'
          when due_date < now() and labels @> '["POA&M"]' then web_url || ' is open and past due (' || due_date || ') but documented on POA&M'
          when due_date <= now() + interval '7 days' and not labels @> '["POA&M"]' then web_url || ' is due in under 7 days (' || due_date || ') and not documented on POA&M. Take care to ensure that remediation is escalated and completed in time.'
          when due_date > now() + interval '7 days' then web_url || ' is open and not past past due (due on ' || due_date || ')'
          else web_url || ' with labels ' || labels || ' does not match expected criteria and requires manual review'
      end as reason
  from gitlab_issue
  where project_id = '${var.gitlab_project_id}'
      and state = 'opened'
      and (labels @> '["Compliance::AutomaticCheck"]' or labels @> '["Compliance::ManualCheck"]')
      and title ~* '${var.scope_regex_pattern}'
  EOQ
}
