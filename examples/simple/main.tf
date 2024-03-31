module "guardduty" {
  source = "../../"

  name                           = "test"
  create_guardduty_finding_notif = "true"
  subscription                   = "example@gmail.com"

}