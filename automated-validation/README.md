# FedRAMP20x Powerpipe mod

This directory and its children define a FedRAMP 20x [powerpipe mod](https://powerpipe.io/docs/build/create-mod) written for stackArmor's Armory 20x pilot system deployed on GCP infrastructure.

[Steampipe](https://steampipe.io/) and [Powerpipe](https://powerpipe.io/) are open source solutions to enable near real time assessment of state for [cloud infrastructure](https://hub.steampipe.io/plugins/turbot/aws), [applications](https://hub.steampipe.io/plugins/turbot/trivy), [services](https://hub.steampipe.io/plugins/turbot/github) and more.

stackArmor has opted to utilize this ecosystem as a foundation for its 20x approach. [mod.pp](./mod.pp) defines the core mod.

## Goals

Transparency, accessibility, extensibility. Tight feedback loops. Faithful representation of system state in near real time.

We have chosen to use an open standard with mature, extensible and well supported open source tooling which can be deployed entirely within the authorization boundary to assert and test system state.

We desire to source control opinions which have traditionally been the domain of implementation statements and eliminate as much manual interpretation of these opinions and associated ambiguity as we reasonably can.

## How it works

Instead of writing an implementation statement that `all GCP compute disks are encrypted using CMKs` and then spending time manually proving this across an arbitrary set of projects at set intervals, or even validating using a script which presents results in JSON that then has to be interpreted and handled alongside the results of similar scripts, we can assert this as a Powerpipe control, adding whatever metadata we wish to the assertion and its associated query.

```hcl
control "gcp_compute_disk_encrypted_with_cmk" {
    title       = "Ensure that GCP compute disks are encrypted with customer-managed keys (CMK)"
    description = "GCP Compute disks should be encrypted with customer managed keys (CMK). If any disk with READY (usable) status is not encrypted with a CMK, it will fail the control."
    query       = query.gcp_compute_disk_encrypted_with_cmk
    tags = merge(local.gcp_threatalert_common_tags, {
        service = "GCP/Compute",
        severity = "high",
    })
}

query "gcp_compute_disk_encrypted_with_cmk" {
    sql = <<-EOQ
    select
        d.self_link as resource,
        d.name,
        d.size_gb,
        d.disk_encryption_key,
        (d.disk_encryption_key->>'kmsKeyName') as cmk_key,
        case
            when (d.disk_encryption_key->>'kmsKeyName') is not null and (d.disk_encryption_key->>'kmsKeyName') != '' then 'ok'
            else 'alarm'
        end as status,
        case
            when (d.disk_encryption_key->>'kmsKeyName') is not null and (d.disk_encryption_key->>'kmsKeyName') != '' then
                'Disk ' || d.name || ' is encrypted with CMK: ' || (d.disk_encryption_key->>'kmsKeyName')
            else
                'Disk ' || d.name || ' is NOT encrypted with CMK'
        end as reason 
    from gcp_compute_disk d
    where d.status = 'READY'
    EOQ
}
```

This control runs in seconds whether standalone or as part of a benchmark consisting of tens or hundreds of other controls. Results can be output to a variety of formats, or viewed as a dashboard natively using Powerpipe server.

# Prerequisites
Use of this solution requires that Steampipe and Powerpipe be installed and configured on the system. While the mod may be initialized and updated without Steampipe and Powerpipe being fully configured it will not be usable without [further configuration](#using-the-mod).

## Initializing the mod
From the same directory as this readme, execute:

```bash
powerpipe mod install
```

## Updating the mod
From the same directory as this readme, execute:
```bash
powerpipe mod update
```
Changes to the mod will be reflected in updates to [.mod.cache.json](./.mod.cache.json)

# Using the mod
This mod is designed to run using the steampipe service managed by `threatalert security toolbox` (TST) and the variables file written by the service. While it is *possible* to launch and run this mod outside of the TST context, the configuration required to accomplish this successfully is outside the scope of this document.

When using TST, the `run-powerpipe` job will launch the steampipe service with the requisite environment variables, and write the `variables.ppvar` file required for powerpipe to query infrastructure and application configurations. The job takes optional arguments to run benchmarks as well, or can be used simply to configure steampipe and write variables.

Once steampipe is correctly configured and running as a service, it is also possible to run powerpipe directly as detailed in the following examples. All examples presume execution from the mod directory.

```bash
# Run the server so benchmarks can be viewed using a browser. This requires steampipe to be running as a service and be correctly configured. While it is possible to configure manually, this solution is designed to run using the steampipe service managed by TST
powerpipe server --var-file ../variables.ppvar
```

```bash
# Run the fedramp-20x-ksis benchmark
powerpipe benchmark run fedramp20x-ksis --var-file ../variables.ppvar
```
## Exporting benchmark results

Outputs can be delivered in [multiple formats](https://powerpipe.io/docs/reference/cli/benchmark). JSON and steampipe snapshot JSON (.pps.json) are provided as examples. Steampipe json structure is more terse and considerably smaller (typically between 30% and 50% of the size of standard JSON exports)
```bash
# Run benchmark and output results to a JSON file (verbose, more human readable, preserves hierarchical relationships, used for submission)
powerpipe benchmark run fedramp20x-ksis --var-file ../variables.ppvar --output json > fedramp20x-ksi-results.json
```

```bash
# Run benchmark to export in pps formatted json (terse, less human readable, does not preserve hierarchical relationships)
powerpipe benchmark run fedramp20x-ksis --var-file ../variables.ppvar --output pps > fedramp20x-ksi-results.pps.json
```

## Importing benchmark results
It does not appear possible to import benchmark results to a local instance of powerpipe server. This is instead a feature of [Turbot Pipes](https://turbot.com/pipes) which is their SaaS offering and thus is not viable for use in authorized systems.

# Mod Structure
This mod is organized across a number of distinct files, directories and subdirectories. Navigating the mod requires understanding the purpose of each. 

### .powerpipe

This directory is automatically created and managed by Powerpipe. It contains cached copies of mod dependencies required for running benchmarks and compliance checks. The structure typically includes:

- `mods/`: Contains downloaded mods, organized by source (e.g., GitHub).
- Nested folders (e.g., `github.com/turbot/steampipe-mod-gcp-compliance@v1.2.2/`): Each represents a specific version of a mod, including its files and documentation.
- These files are used internally by Powerpipe and are not manually edited. Any changes to controls defined in these files would require making changes to the upstream mod repository.

Generally, this folder is not interacted directly; it is updated automatically when  `powerpipe mod install` or `powerpipe mod update` are run in the environment. It would normally be excluded from source control, but is included in the submission repository for full transparency regarding assessment mechanisms. 

### okta

This directory contains controls, queries, and configuration files for assessing Okta environments against the [Okta Security Technical Implementation Guide (STIG)](https://sec.okta.com/articles/2025/05/oktas-new-stig/) and stackArmor’s opinionated Okta implementation. Key contents include:

- [okta-stig.pp](./okta/okta-stig.pp): Okta STIG benchmark declaration. Note that not all STIGs are currently represented; additional functionality will need to be added to the [steampipe okta plugin](https://hub.steampipe.io/plugins/turbot/okta) to enable fully automated validation.
- [okta_stig-v1-r1.yaml](./okta/okta_stig-v1-r1.yaml): STIG reference file.
- [stig-controls.pp](./okta/okta-stig.pp): Control definitions.
- [variables.pp](./okta/variables.pp): Variable declarations for Okta benchmarks.
- [queries](./okta/queries/README.md): Reference SQL queries
- [README.md](./okta/README.md): Overview and documentation for Okta controls and requirements.

This directory is currently embedded in the 20x mod but upon completion and approval it is planned to be open-sourced and published to the [Powerpipe hub](https://hub.powerpipe.io/) for consumption by other organizations interested in automating checks against the Okta STIG.

### threatalert_controls

This folder contains [Powerpipe control definitions](https://powerpipe.io/docs/build/writing-controls) for various platforms and tools used within the system.

- [gcp_controls.pp](./threatalert_controls/gcp_controls.pp): Google Cloud Platform custom controls created specifically for the environment configuration. 
  - Controls focus on specific configuration data from the hyperscale provider to demonstrate technical KSI compliance. 
- [gitlab_controls.pp](./threatalert_controls/gitlab_controls.pp): Controls for GitLab security and operational checks.
  - Within Armory20x, GitLab functions as the Information Technology Service Management (ITSM) tool as well as the host for system IAC repositories. The queries are designed to collect information on KSIs that focus on operational and management requirements of KSIs, as well as some technical details. 
- [googledirectory_controls.pp](./threatalert_controls/googledirectory_controls.pp): Controls for Google Directory user and group policies.
  - Utilized for ensuring MFA is implemented enforced for GCP users.
- [nessus_controls.pp](./threatalert_controls/nessus_controls.pp): Controls for Nessus vulnerability and compliance scans.
  - Designed to poll the Nessus scanner to obtain information around host FIPS configurations based on STIG benchmark results, as well as ensuring scans are running within the environment on expected schedules. Note that this is dependent upon a stackArmor developed Nessus steampipe plugin. The population of controls is the minimal set for pilot program submission- it is expected that this control population will undergo considerable growth, and that similar plugins and control sets will be developed for other scanners as required.
- [tsw_controls.pp](./threatalert_controls/tsw_controls.pp): Controls for ThreatAlert Security Workbench® operational checks and finding lifecycle manager.
  - TSW is a proprietary application deployed within the system whish automates aspects of Continuous Monitoring (ConMon) including task scheduling and oversight as well as finding ingestion, normalization and tracking. Control set is minimally viable for pilot program submission; it is expected that this control set will be developed on an ongoing basis. Note that this is dependent upon a stackArmor developed TSW steampipe plugin.

These files are used to benchmark and assess the security posture of each platform, and gather machine-readable results that are utilized as the inputs of the ThreatAlert® Security Workbench KSI dashboard. 

### .pp files

- [mod.pp](./mod.pp): Declares the core Powerpipe mod for FedRAMP20x, specifying required dependencies (such as the GCP compliance mod).
- [variables.pp](./variables.pp): Defines mandatory variables for the mod, such as project IDs, bucket names, and user IDs, which must be provided for benchmarks and controls to run.
- `ksi-ced.pp`, `ksi-cmt.pp`,`ksi-cna.pp`, `ksi-iam.pp`, `ksi-inr.pp`, `ksi-mla.pp`, `ksi-piy.pp`, `ksi-rpl.pp`, `ksi-svc.pp`, `ksi-tpr.pp`:  Each of these files defines benchmarks which define control relationships to a specific FedRAMP 20x KSI (Key Security Indicator) family. 
- [ksis.pp](./ksis.pp) : Declares the top level `fedramp20x-ksis` benchmark.