# Controls defined in this file are dependent upon stackArmor's Nessus steampipe plugin.
locals {
  nessus_threatalert_common_tags = {
    service = "Nessus",
    plugin = "nessus",
    threatAlert_control = "true",
  }
}

control "nessus_scans_completed_within_last_7_days" {
  title       = "Nessus Scans Completed Within Last 7 Days"
  description = "Nessus scans should complete successfully at least once every 7 days. If an active scan completed longer than 7 days ago this is a finding."
  tags        = merge(local.nessus_threatalert_common_tags, {
    severity = "high",
  })
  query       = query.nessus_scans_completed_within_last_7_days
}

query "nessus_scans_completed_within_last_7_days" {
  sql = <<-EOQ
    select
        name as resource,
        type,
        status as completion_status,
        folder_name,
        last_modification_date,
        case
            when last_modification_date >= now() - interval '7 days' then 'ok'
            else 'alarm'
        end as status,
        case
            when last_modification_date >= now() - interval '7 days' then name || ' nessus scan completed successfully within the last 7 days'
            else name || ' nessus scan not completed successfully within the last 7 days'
        end as reason
    from
        nessus_scans
    where
        folder_name not in ('Trash')
        and name ~* '${var.scope_regex_pattern}'
  EOQ
}

control "nessus_rhel8_stig_fips_check_passing" {
  title       = "Ensure RHEL8 hosts comply with FIPS requirements"
  description = "RHEL 8 hosts must be configured to comply with FIPS requirements. This is determined by validating the results of STIG RHEL-08-010020 compliance checks from Nessus."
  tags        = merge(local.nessus_threatalert_common_tags, {
    severity = "high",
  })
  query       = query.nessus_rhel8_stig_fips_check_passing
}

query "nessus_rhel8_stig_fips_check_passing" {
  sql = <<-EOQ
    -- STIG RHEL-08-010020 - RHEL 8 must implement NIST FIPS-validated cryptography is used to ascertain the FIPS status of RHEL 8 hosts.
    with scope_scans as (
        select
            name as resource,
            type,
            id,
            status as completion_status,
            folder_name,
            last_modification_date
        from
            nessus_scans
        where
            folder_name not in ('Trash')
            and name ~* '${var.scope_regex_pattern}'
    )
    select
        host as resource,
        plugin_id,
        scan_id,
        plugin_name,
        compliance_benchmark_version,
        compliance_result,
        case
            when compliance_result = 'PASSED' then 'ok'
            else 'alarm'
        end as status,
        case
            when compliance_result = 'PASSED' then compliance_check_name || ' passed for host '|| host
            else compliance_check_name || ' failed for host ' || host
        end as reason
    from
        nessus_scan_compliance_findings
    where
        compliance_check_name like '%RHEL-08-010020%'
        and scan_id in (select id from scope_scans)
  EOQ
}

control "nessus_agents_older_than_7_days_must_have_recent_scan" {
  title       = "Nessus agents older than 7 days must have recent scan"
  description = "Nessus agents linked within the system must be scanned on a regular basis. If an agent is older than 7 days and has not been scanned within the last 7 days then this is a finding."
  tags        = merge(local.nessus_threatalert_common_tags, {
    severity = "high",
  })
  query       = query.nessus_agents_older_than_7_days_must_have_recent_scan
}

query "nessus_agents_older_than_7_days_must_have_recent_scan" {
  sql = <<-EOQ
    select
        name as resource,
        status as agent_status,
        platform,
        linked_on,
        last_scanned,
        last_connect,
        case
            when (last_scanned < now() - interval '7 days' and linked_on < now() - interval '7 days') then 'alarm'
            else 'ok'
        end as status,
        case
            when (last_scanned < now() - interval '7 days' and linked_on < now() - interval '7 days') then name || ' was linked more than 7 days ago and has not been scanned in over 7 days'
            else name || ' was last scanned on ' || last_scanned
        end as reason
    from
        nessus_agents
  EOQ
}