######################################################################
# Guardduty Detector
######################################################################

resource "aws_guardduty_detector" "detector" {
  enable = var.enable_guardduty

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_eks_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = var.tags
}

######################################################################
# SNS
######################################################################

resource "aws_sns_topic" "guardduty_topic" {
  count = var.create_guardduty_finding_notif ? 1 : 0
  name  = "${var.name}-guardduty-topic"
}

resource "aws_sns_topic_subscription" "guardduty_subscription" {
  count     = var.create_guardduty_finding_notif ? 1 : 0
  topic_arn = aws_sns_topic.guardduty_topic[count.index].arn
  protocol  = "email"
  endpoint  = var.subscription
}

######################################################################
# Cloudwatch Event Rule / Eventbridge
######################################################################

resource "aws_cloudwatch_event_rule" "guardduty_rule" {
  count       = var.create_guardduty_finding_notif ? 1 : 0
  name        = "${var.name}-guardduty-rule"
  description = "Guardduty Notification Findings"

  #  event_pattern = jsondecode(file("${path.module}/policy/guardduty_event_pattern.json"))
  event_pattern = file("${path.module}/policy/guardduty_event_pattern.json")
}

resource "aws_cloudwatch_event_target" "guardduty_event_target" {
  count = var.create_guardduty_finding_notif ? 1 : 0
  rule  = aws_cloudwatch_event_rule.guardduty_rule[count.index].name
  arn   = aws_sns_topic.guardduty_topic[count.index].arn

  input_transformer {
    input_paths = {
      "severity" : "$.detail.severity",
      "Account_ID" : "$.detail.accountId",
      "Finding_ID" : "$.detail.id",
      "Finding_Type" : "$.detail.type",
      "region" : "$.region",
      "Finding_description" : "$.detail.description"
    }
    input_template = <<EOF
{
  "Message": "AWS <Account_ID> has a severity <severity> GuardDuty finding type <Finding_Type> in the <region> region.",
  "Finding_Description": "<Finding_description>. For more details open the GuardDuty console at https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?search=id%3D<Finding_ID>"
}
EOF

  }
}

######################################################################
# Publish to S3
######################################################################
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "bucket_pol" {
  count = var.enable_s3_logs ? 1 : 0
  statement {
    sid = "Allow PutObject"
    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.gd_bucket[count.index].arn}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "kms_pol" {

  statement {
    sid = "Allow GuardDuty to encrypt findings"
    actions = [
      "kms:GenerateDataKey"
    ]

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket" "gd_bucket" {
  count = var.enable_s3_logs ? 1 : 0
  bucket        = "${var.name}-guardduty-logs-bucket"
  force_destroy = true
}

resource "aws_s3_bucket_acl" "gd_bucket_acl" {
  count  = var.enable_s3_logs ? 1 : 0
  bucket = aws_s3_bucket.gd_bucket[count.index].id
  acl    = "private"
}

resource "aws_s3_bucket_policy" "gd_bucket_policy" {
  count  = var.enable_s3_logs ? 1 : 0
  bucket = aws_s3_bucket.gd_bucket[count.index].id
  policy = data.aws_iam_policy_document.bucket_pol[count.index].json
}

resource "aws_kms_key" "gd_key" {
  count = var.enable_s3_logs ? 1 : 0
  description             = "Guardduty Key"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms_pol.json
}

resource "aws_guardduty_publishing_destination" "test" {
  count           = var.enable_s3_logs ? 1 : 0
  detector_id     = aws_guardduty_detector.detector.id
  destination_arn = aws_s3_bucket.gd_bucket[count.index].arn
  kms_key_arn     = aws_kms_key.gd_key[count.index].arn

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
  ]
}
