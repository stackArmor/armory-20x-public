mod "fedramp20x" {
  title = "FedRAMP20x"
  require {
    mod "github.com/turbot/steampipe-mod-gcp-compliance" {
      version = "*"
    }
  }
}