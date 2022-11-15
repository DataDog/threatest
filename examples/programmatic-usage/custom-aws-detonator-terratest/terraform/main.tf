# Code taken from https://github.com/DataDog/stratus-red-team/blob/main/v2/internal/attacktechniques/aws/defense-evasion/cloudtrail-stop/main.tf

resource "aws_cloudtrail" "trail" {
  name           = "sample-cloudtrail-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail.id
}

resource "random_string" "suffix" {
  length    = 16
  min_lower = 16
  special   = false
}

locals {
  bucket-name = "my-cloudtrail-bucket-${random_string.suffix.result}"
}
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.bucket-name
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${local.bucket-name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${local.bucket-name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

output "cloudtrail_trail_name" {
  value = aws_cloudtrail.trail.name
}