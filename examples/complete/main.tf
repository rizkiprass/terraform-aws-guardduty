module "guardduty" {
  source = "../../"

  name                           = "test"
  enable_guardduty               = "true"
  enable_s3_logs                 = "false"
  enable_eks_protection          = "true"
  enable_malware_protection      = "true"
  enable_s3_protection           = "true"
  create_guardduty_finding_notif = "true"
  subscription                   = "rizkiprasetyapras@gmail.com"

  tags = {
    terraform = "yes"
  }

}