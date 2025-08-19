# Controls defined in this file are dependent upon stackArmor's TSW steampipe plugin.

locals {
  tsw_threatalert_common_tags = {
    service = "TSW",
    plugin = "tsw",
    threatAlert_control = "true",
  }
}

control "tsw_ir_cp_tasks_not_overdue" {
  title       = "TSW IR/CP Tasks Not Overdue"
  description = "Ensure that incident response and contingency planning tasks are not overdue."
  tags        = merge(local.tsw_threatalert_common_tags, {
    severity = "moderate",
  })
  query       = query.tsw_ir_cp_tasks_not_overdue
}

query "tsw_ir_cp_tasks_not_overdue" {
  sql = <<-EOQ
    select
        task_name as resource,
        itsm_issue_id,
        frequency,
        due_date,
        control_ids,
        case
            when completed = 'false' and due_date < now() then 'alarm'
            when completed = 'false' and due_date >= now() then 'ok'
            else 'ok'
        end as status,
        case
            when completed = 'false' and due_date < now() then 'Task overdue: ' || task_name || ' (Due: ' || due_date || ')'
            when completed = 'false' and due_date >= now() then 'Task not overdue: ' || task_name || ' (Due: ' || due_date || ')'
            else 'Task completed: ' || task_name || ' (Due: ' || due_date || ')'
        end as reason
    from
        tsw_scheduled_tasks
    where
        task_name ilike '%incident%response%'
  EOQ
}