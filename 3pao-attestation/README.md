# 3PAO attestation and validation details

This directory organizes publicly shareable 3PAO attestations and supporting artifacts for the Armory20x FedRAMP 20x Pilot. See the high-level timeline in the root [README](../README.md#3pao-assessment-process); detailed steps are captured below for completeness.

## Assessment process (detailed)

stackArmor selected [Kratos | FedRAMP Marketplace](https://marketplace.fedramp.gov/assessors/137255) as its Third-Party Assessment Organization (3PAO) for the Armory20x assessment and validation. The partnership aimed to validate stackArmor's approach for evaluating and reporting status for the [FedRAMP Key Security Indicators (KSIs)](https://github.com/FedRAMP/docs/blob/main/FRMR.KSI.key-security-indicators.json). The assessment process proceeded as follows:

**Step 1 — Kickoff meeting — 2025-07-21**

- Conducted with representatives from both stackArmor and Kratos to establish:
	- Rules of Engagement for the assessment;
	- assumed timelines; and
	- assessment plan.

**Step 2 — stackArmor provides Armory20x Documentation Package — 2025-07-21**

- stackArmor provided machine- and human-readable versions of the Armory20x Authorization Package in the Kratos Box repository.

**Step 3 — Kratos access provisioning — 2025-07-21 to 2025-07-23**

- stackArmor provisioned five Kratos assessment team members with the following access:
	- GitHub repository (internal clone of public-facing repo)
	- Read-only access to Armory20x system services

**Step 4 — System overview/deep dive — 2025-07-23**

- stackArmor performed a thorough walkthrough of both the system services and the GitHub repo.
- The Kratos assessment team engaged stackArmor subject matter experts (SMEs) to ensure complete understanding of scope and deployment.

**Step 5 — Initial assessment activities — 2025-07-24 through 2025-07-28**

- Kratos assessors gathered information on the environment and GitHub repo, evaluated system configurations, and reviewed the structure and quality of the KSI queries running in the environment.

**Step 6 — Sync meeting — 2025-07-28**

- First sync meeting between stackArmor and Kratos
	- Updated schedule assumptions
	- stackArmor answered initial questions based on Kratos' information gathering
	- Assessment milestones were set

**Step 7 — KSI results provided — 2025-08-01**

- stackArmor provided the results of the KSI benchmarks running in the environment to Kratos.

**Step 8 — Updated KSI results provided — 2025-08-06**

- stackArmor enhanced queries in the environment to further automate KSIs and provided an updated results file to Kratos.

**Step 9 — Kratos provides initial validation results — 2025-08-07**

- Kratos provided their initial feedback after analysis of the environment and queries. The analysis contained: 
	- **Missing Automation Scripts**
		- Entries marked as **FALSE** indicate that no automation scripts currently exist for these KSIs. Please provide supporting evidence for manual validation in these cases.
	- **Insufficient Scripts**
		- **FALSE** entries represent scripts that, based on our assessment, do not sufficiently meet the intent of the associated KSI. These should be reviewed and either updated or replaced with revised versions.
	- **Outstanding Questions**
		- This column includes questions arising from our script validation exercise. Kindly provide responses or additional context to address these queries.
	- **Failed Evidence Validation**
		- **FALSE** entries indicate that the submitted evidence did not meet validation requirements. Please note that multiple entries may exist for a single KSI if multiple scripts were reviewed. We ask that you reassess the evidence and submit corrected or supplementary documentation where necessary.
	- **Responses and Artifact Submission**
		- Kindly use these columns to provide your responses, as well as any updated or additional artifacts required for re-validation.

**Step 10 — stackArmor provides response to initial validation results — 2025-08-08**

- stackArmor provided written responses to all areas where **FALSE** was indicated in the Initial Validation Results.
- stackArmor provided written responses to all questions in the Initial Validation Results.
- stackArmor uploaded additional traditional artifacts (e.g., screenshots, process documents, tickets) to Kratos Box to demonstrate implementation of some non-automated aspects of the system.

**Step 11 — Sync meeting — 2025-08-11**

- Second sync meeting between Kratos and stackArmor
	- Discussed final timeline assumptions
	- Coordinated final steps

**Step 12 — Final environment walkthrough and evidence collection — 2025-08-14**

- stackArmor and Kratos met to walk through the environment and collect final evidence validations for any areas that could not be fully validated via queries and evidence already provided.

**Step 13 — Final attestation and validation report — 2025-08-18**

- Kratos finalized the FedRAMP 20x Pilot Program Assessment by providing the following: 
	- **Final Validation Report** — using the same format as the Initial Validation Results
	- [3PAO 20x attestation letter](./Letter-of-Attestation-for-StackArmor-Armory20x-Final.pdf)