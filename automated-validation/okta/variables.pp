# Variables used by the Okta STIG
# Max session idle time in minutes is 15 as per published STIG, but situations are frequently encountered where an AO insists on 10 minutes
# It is not uncommon for conflicting parameters to exist for this variable, and usually the most aggressive one must take precedence.

variable "okta_stig_max_session_idle_minutes" {
  type        = number
  description = "Maximum session idle time in minutes for Okta STIG."
  default     = 15
}