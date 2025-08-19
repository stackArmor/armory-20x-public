# This declares mandatory variables for the mod. These variables must be declared in a variables.ppvar file
variable "gitlab_project_id" {
  type        = string
  description = "The GitLab project ID to use for checks."
}

variable "bucket_name" {
  type        = string
  description = "The name of the bucket used for storing system documentation."
}

variable "gitlab_security_engineer_id" {
  type        = string
  description = "The GitLab security engineer ID to use for checks."
}

variable "gitlab_security_analyst_id" {
  type        = string
  description = "The GitLab security analyst ID to use for checks."
}
variable "gitlab_issm_id" {
  type        = string
  description = "The GitLab ISSM ID to use for checks."
}
variable "tst_install_directory" {
  type        = string
  description = "The installation directory for the ThreatAlert Security Toolbox. Used for targeting job temporal data."
  default     = "/opt/threatalert-security-toolbox"
}

variable "scope_regex_pattern" {
  type        = string
  description = "A regex pattern to match against scope names. Used for targeting scanner results and GitLab issues for subsystems."
}

variable "subsystem_iac_project_id" {
  type        = string
  description = "The GitLab project ID for the IAC subsystem. Used to enable evaluation of IAC under source control."
  default = "1"
}