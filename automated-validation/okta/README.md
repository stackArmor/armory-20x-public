# Overview
Okta's [Security Technical Implementation Guide (STIG)](https://sec.okta.com/articles/2025/05/oktas-new-stig/) was released on 2025-05-09. 

Controls in this mod assess configuration for STIG compliance, as well as stackArmor's opinionated Okta implementation which goes beyond the configuration of the tenant to the operation of the tenant including user assignments, group structuring, etc. Control names clearly indicate whether the control is applicable to STIG or to stackArmor's opinionated implementation.

This mod is currently embedded in the 20x mod, but will be opensourced, published to the powerpipe hub, and imported alongside other benchmarks like gcp-compliance.

# Requirements
TODO- need to document specific Okta config requirements and assumptions. These are somewhat specific beyond what is documented for the steampipe plugin.