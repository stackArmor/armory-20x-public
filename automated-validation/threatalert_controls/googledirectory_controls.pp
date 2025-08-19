locals {
  googledirectory_threatalert_common_tags = {
    service = "Google Directory",
    threatAlert_control = "true",
  }
}

control "googledirectory_user_accounts_require_two_step_verification" {
  title       = "Google Directory User Accounts Require Two-Step Verification"
  description = "Ensure that all user accounts in Google Directory require two-step verification"
  tags        = merge(local.googledirectory_threatalert_common_tags, {
    severity = "high",
  })
  query       = query.googledirectory_user_accounts_require_two_step_verification
}

 query "googledirectory_user_accounts_require_two_step_verification" {
  sql = <<-EOQ
    select
        primary_email as resource,
        case
            when is_enforced_in_2sv = 'true' then 'ok'
            else 'alarm'
        end as status,
        case
            when is_enforced_in_2sv = 'true' then 'Two step verification is enforced for ' || primary_email
            else 'Two step verification is not enforced for ' || primary_email
        end as reason
    from
        googledirectory_user
  EOQ
}