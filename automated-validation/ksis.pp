locals {
  all_ksis_common_tags = {
    type = "Benchmark"
    fedramp20x = "true"
    category = "Compliance"
  }
}

benchmark "fedramp20x-ksis" {
    title       = "FedRAMP 20x Key Security Indicators (KSIs)"
    description = "This benchmark assesses FedRAMP 20x Key Security Indicators (KSIs) based on infrastructure state"
    tags        = local.all_ksis_common_tags
    children = [
      benchmark.fedramp20x_ksi_ced,
      benchmark.fedramp20x_ksi_cmt,
      benchmark.fedramp20x_ksi_cna,
      benchmark.fedramp20x_ksi_iam,
      benchmark.fedramp20x_ksi_inr,
      benchmark.fedramp20x_ksi_mla,
      benchmark.fedramp20x_ksi_piy,
      benchmark.fedramp20x_ksi_rpl,
      benchmark.fedramp20x_ksi_svc,
      benchmark.fedramp20x_ksi_tpr
    ]
}
