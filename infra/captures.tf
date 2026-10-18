# Captures archive (P1.6). A private bucket that only the instance can write to, under
# one prefix. Objects expire after the retention set in variables.tf. The local copy
# is removed by `lookalike-hunter archive` only after its upload has succeeded.

resource "random_id" "captures_bucket" {
  byte_length = 4
}

resource "aws_s3_bucket" "captures" {
  # Each exception below is a deliberate trade-off, not an oversight:
  # checkov:skip=CKV_AWS_21: versioning is off by design (mission): deleted captures must not persist.
  # checkov:skip=CKV_AWS_18: access logs add storage and a second log stream; revisit in P1.9.
  # checkov:skip=CKV_AWS_145: S3-managed encryption (AES256) is used: no KMS key to manage or pay for.
  # checkov:skip=CKV_AWS_144: single-region by design (cost); backups are P1.7.
  # checkov:skip=CKV2_AWS_62: no consumer reacts to new objects; the local archive command does the work.
  bucket = "lookalike-hunter-captures-${random_id.captures_bucket.hex}"

  tags = {
    Name = "lookalike-hunter-captures"
  }
}

resource "aws_s3_bucket_public_access_block" "captures" {
  bucket = aws_s3_bucket.captures.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Uploads belong to the bucket owner, so no object can be made public by its uploader.
resource "aws_s3_bucket_ownership_controls" "captures" {
  bucket = aws_s3_bucket.captures.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Encryption at rest with the S3-managed key: no key to manage, and no per-request charge.
resource "aws_s3_bucket_server_side_encryption_configuration" "captures" {
  bucket = aws_s3_bucket.captures.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "captures" {
  bucket = aws_s3_bucket.captures.id

  rule {
    id     = "expire-captures"
    status = "Enabled"

    filter {
      prefix = "captures/"
    }

    expiration {
      days = var.capture_retention_days
    }
  }

  # Daily database and dataset snapshots (P1.7) expire on their own schedule.
  rule {
    id     = "expire-backups"
    status = "Enabled"

    filter {
      prefix = "backups/"
    }

    expiration {
      days = var.backup_retention_days
    }
  }

  # A failed multipart upload would otherwise keep its parts, and be billed, forever.
  rule {
    id     = "abort-failed-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Refuse any request that does not use TLS.
data "aws_iam_policy_document" "captures_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.captures.arn,
      "${aws_s3_bucket.captures.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "captures" {
  bucket = aws_s3_bucket.captures.id
  policy = data.aws_iam_policy_document.captures_tls_only.json

  depends_on = [aws_s3_bucket_public_access_block.captures]
}

# The instance may add objects under the captures and backups prefixes. It may not read,
# list or delete them: expiry is the lifecycle rules' job, and cleanup is local.
resource "aws_iam_role_policy" "instance_put_captures" {
  name = "put-captures-and-backups-only"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "PutCapturesAndBackups"
      Effect = "Allow"
      Action = ["s3:PutObject"]
      Resource = [
        "${aws_s3_bucket.captures.arn}/captures/*",
        "${aws_s3_bucket.captures.arn}/backups/*",
      ]
    }]
  })
}
