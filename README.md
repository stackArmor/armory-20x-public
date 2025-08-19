# stackArmor 20x Pilot Program Final Submission

<img src="images/stackAmor-logo.webp" alt="stackArmor-logo.webp" width="80%">


This repository contains the final submission for stackArmor's participation in the FedRAMP 20x Pilot Program. It consists of documentation, code, and artifacts to prove FedRAMP 20x Key Security Indicators (KSIs) status and support assessment and authorization of the Armory20x tenant.

## Quick links

- KSI Dashboard (public): https://stackarmor.github.io/armory-20x-public/
- Benchmark results (JSON): [./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-results.json](./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-results.json)
- System declaration (YAML): [./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-system-declaration.yaml](./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-system-declaration.yaml)
- Automated validation (Powerpipe mod): [./automated-validation/README.md](./automated-validation/README.md)
- 3PAO attestation and details: [./3pao-attestation/README.md](./3pao-attestation/README.md)

## Armory20x Overview

<img src="images/logo-armory-20x.png" alt="logo-armory-20x" width="80%">

Armory20x is a purpose-built solution hosted on Google Cloud Platform (GCP) that provides cloud service providers (CSPs) and independent software vendors (ISVs) a deployment landing zone within an Armory20x tenant to deploy workloads that store, process, and/or transmit federal data categorized at the FedRAMP 20x Low baseline.

The tenant leverages the security and General Support System (GSS) services of [The Armory | FedRAMP Marketplace](https://marketplace.fedramp.gov/products/FR2513256853) to provide a known-secure deployment location, leveraging a majority of GCP FedRAMP authorized native cloud and in-boundary security services, for CSPs seeking authorization under 20x.

- As part of the FedRAMP 20x Pilot, CSPs must report their Key Security Indicator (KSI) status as defined by the [FedRAMP 20x Key Security Indicators | FedRAMP.gov](https://www.fedramp.gov/20x/standards/ksi/). Armory20x leverages stackArmor's automated assessment solution to provide status for all required KSIs for a CSP deployed within a 20x tenant.
- Tenants are heavily customizable, allowing Armory20x customers to deploy workloads that are suited to their particular application and service needs.
- stackArmor personnel assist CSPs/ISVs with deploying services in a manner that meets FedRAMP 20x KSI requirements and helps ensure an authorizable status under the 20x program.

## Armory20x Repository Description

stackArmor has submitted this public-facing repository to provide the details and evidentiary requirements for the FedRAMP 20x program. The following sections provide a description of the structure and purpose of the GitHub repository. 

### Repository structure (overview)

- `automated-validation/` — Powerpipe mod and controls used to assess system state.
- `ksi-assessment-output/` — Machine-readable KSI benchmark outputs and system declaration.
- `3pao-attestation/` — Publicly shareable 3PAO attestations and supporting artifacts.
- `images/` — Logos and images used by the README/site.
- `index.html` + `assets/` — Static site for the KSI dashboard

### automated-validation

The [automated-validation](./automated-validation/README.md) directory defines the [Powerpipe](https://powerpipe.io/) mod used to assess system state in near real time.

### ksi-assessment-output

Benchmark outputs are source controlled for public consumption in this directory. Two files are provided for this initial release.

The [system-declaration.yaml](./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-system-declaration.yaml) file declares the attributes of the system being assessed. This machine-readable declaration informs the automated configuration of Steampipe and Powerpipe to assess the defined scopes. The declaration itself is source controlled within the system authorization boundary; the artifact provided here is a curated subset of the full declaration.

The [benchmark results JSON](./ksi-assessment-output/fedramp20x-ksis-Armory-fr20x-results.json) file provides a comprehensive, machine-readable status report for FedRAMP 20x Key Security Indicators (KSIs). This file is a [Powerpipe benchmark JSON output](https://powerpipe.io/docs/run/benchmark/output-format).

#### Structure overview

##### Summary

The key data is the summary of findings, with counts for each status type:

- `ok`: Controls passed (compliant)
- `alarm`: Controls failed (non-compliant or requiring attention)
- `skip`: Controls not applicable or skipped
- `error`: Controls that encountered errors during evaluation — within the GCP context this often occurs if APIs are not enabled in a project
- `info`: Informational results

##### Groups and benchmarks

Results are organized into nested groups representing logical categories (e.g., FedRAMP 20x KSI benchmark as a whole, benchmarks per KSI, etc.). Each group contains:

- `group_id`: Unique identifier for the group
- `title`: Human-readable name for the group
- `description`: Detailed description of the group and its purpose
- `tags`: Used for filtering and categorization (e.g., fedramp20x, ksi_name, category)
- `summary`: Summary of status counts for that group

##### Nesting

Groups are nested in the output and take the following hierarchical structure: 
- `root`: Overall summary of the results. 
- `benchmark main`: Summary of the overall benchmark results. 
- `benchmark domain`: Summary of the results for each KSI domain (e.g., ksi-ced, ksi-cmt, etc.)
- `benchmark ksi`: Summary of the results for each KSI (e.g., ksi-ced-01, ksi-cmt-01, etc.)
- `benchmark control`: Individual controls run against each KSI, with detailed results. The results retrieve the data that was evaluated in determining the status of the check. 

### assets

stackArmor has developed the ThreatAlert® Security Workbench (TSW) KSI Dashboard presented via [GitHub Pages](https://stackarmor.github.io/armory-20x-public/) to provide a comprehensive overview of KSI status across all platforms and services within the Armory20x tenant. This directory contains assets for the dashboard.

The dashboard presents the benchmark results source controlled in this repository. It provides an interactive view of KSI status, allowing stakeholders to easily monitor their security and compliance posture.

## 3PAO Assessment Process 

stackArmor selected [Kratos | FedRAMP Marketplace](https://marketplace.fedramp.gov/assessors/137255) as its Third-Party Assessment Organization (3PAO) for the Armory20x assessment and validation. The partnership aimed to validate stackArmor's approach for evaluating and reporting status for the [FedRAMP Key Security Indicators (KSIs)](https://github.com/FedRAMP/docs/blob/main/FRMR.KSI.key-security-indicators.json).

Timeline summary:

- 2025-07-21: Kickoff meeting; documentation package provided.
- 2025-07-21–23: Access provisioning for Kratos assessors.
- 2025-07-23: System overview and deep dive.
- 2025-07-24–28: Initial assessment activities.
- 2025-07-28: Sync meeting; milestones set.
- 2025-08-01: KSI results provided; 2025-08-06: updated results provided.
- 2025-08-07: Initial validation results from Kratos.
- 2025-08-08: stackArmor response and additional artifacts submitted.
- 2025-08-11: Final sync meeting.
- 2025-08-14: Final environment walkthrough and evidence collection.
- 2025-08-18: Final validation report and [3PAO 20x attestation](./3pao-attestation/Letter-of-Attestation-for-StackArmor-Armory20x-Final.pdf).

See full details in [3pao-attestation/README.md](./3pao-attestation/README.md).

## 20x And Beyond 

We will continue to update this repository as we address findings from Kratos and progress through the FedRAMP 20x authorization process. This repo also serves as a collaboration hub for 3PAOs, the PMO, and other stakeholders. Our long-term aim is to reach what we call `total equilibrium` where automation fully validates all KSIs and benchmark results stand alone without any additional artifacts.

To reduce audit burden, our approach focuses on establishing trust in repeatable, automated benchmarks that assert KSI status, similar to audit assurance practices. We’ll keep expanding coverage and integrating additional services to increase the scope and depth of validations. When trust across all validations is established, our target is met: **a complete, fully automated information system assessment.**


#### Legal Statement
*The stackArmor Armory20x offering is powered by the ThreatAlert(R) ATO Accelerator and Security Platform. Its use is governed by the ThreatAlert(R) License Agreement https://stackarmor.com/accelerators/threatalert-gss/threatalert-license-agreement/. All third-party copyrights and trademarks are acknowledged.*