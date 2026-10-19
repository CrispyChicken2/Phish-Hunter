# Observability (P1.9). The services log JSON lines to files under /var/log/lookalike-hunter
# (see deploy/), and the CloudWatch agent ships them here. Metric filters turn log events
# into numbers, and alarms watch those numbers. Alarms go to one SNS topic.

locals {
  metrics_namespace = "LookalikeHunter"
}

# One log group per service, all under /lookalike-hunter/ (the prefix the instance role may
# write to, instance.tf). Retention bounds the cost; the logs hold no secret.
resource "aws_cloudwatch_log_group" "service" {
  # checkov:skip=CKV_AWS_158: the default CloudWatch Logs encryption at rest applies. A KMS key is a
  # monthly charge outside the budget, and these logs hold no secret (secrets never reach them).
  # checkov:skip=CKV_AWS_338: 30 days is a deliberate retention (cost). Longer history is in S3 backups.
  for_each = toset(["watch", "archive", "backup"])

  name              = "/lookalike-hunter/${each.key}"
  retention_in_days = var.log_retention_days
}

# Counts each flush of the Certificate Transparency pipeline. A flush happens when a batch fills
# or the flush interval passes, and only when messages arrive. So no flush for 10 minutes means no
# certificate reached the pipeline (the stream is silent, or the watch process is down).
resource "aws_cloudwatch_log_metric_filter" "ct_flush" {
  name           = "ct-flush"
  log_group_name = aws_cloudwatch_log_group.service["watch"].name
  pattern        = "{ $.event = \"ct.flush\" }"

  metric_transformation {
    name      = "CtFlush"
    namespace = local.metrics_namespace
    value     = "1"
  }
}

# Counts watch cycles in which at least one stage (capture, classify, alert) raised.
resource "aws_cloudwatch_log_metric_filter" "failed_watch_cycle" {
  name           = "failed-watch-cycle"
  log_group_name = aws_cloudwatch_log_group.service["watch"].name
  pattern        = "{ ($.event = \"watch.cycle\") && ($.failed_stages >= 1) }"

  metric_transformation {
    name      = "FailedWatchCycles"
    namespace = local.metrics_namespace
    value     = "1"
  }
}

resource "aws_sns_topic" "alarms" {
  # checkov:skip=CKV_AWS_26: no KMS key, to keep the cost down. The messages are alarm names
  # and states, with no secret. A key set to the AWS-managed alias would stop CloudWatch from
  # publishing to the topic.
  name = "lookalike-hunter-alarms"
}

# The address is an owner's e-mail, so it is never in the repository. Pass it with
# TF_VAR_alarm_email or a git-ignored terraform.tfvars. Without it, the alarms still exist
# and show in the console, just with no e-mail. The owner must confirm the subscription link.
resource "aws_sns_topic_subscription" "alarm_email" {
  count = var.alarm_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# No certificate for 10 minutes. Missing data counts as breaching: a silent stream, or a dead
# watch process, both produce no flush at all.
resource "aws_cloudwatch_metric_alarm" "no_certificates" {
  alarm_name          = "lookalike-hunter-no-certificates"
  alarm_description   = "No Certificate Transparency flush for 10 minutes: no certificates reached the pipeline, or watch is down."
  namespace           = local.metrics_namespace
  metric_name         = "CtFlush"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# Three failed cycles in 30 minutes (at the default 5-minute interval, six cycles run).
resource "aws_cloudwatch_metric_alarm" "repeated_watch_failures" {
  alarm_name          = "lookalike-hunter-repeated-watch-failures"
  alarm_description   = "Three or more watch cycles with a failed stage in 30 minutes. Read the watch log group for the *_failed events."
  namespace           = local.metrics_namespace
  metric_name         = "FailedWatchCycles"
  statistic           = "Sum"
  period              = 1800
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# Root disk above 80% for 15 minutes. The database and captures share this disk. Missing data
# (agent not running) is not an alarm here, so an unfinished install does not page anyone.
resource "aws_cloudwatch_metric_alarm" "disk_full" {
  alarm_name        = "lookalike-hunter-disk-above-80"
  alarm_description = "Root disk above 80% for 15 minutes. The database and captures share it."
  namespace         = local.metrics_namespace
  metric_name       = "disk_used_percent"
  dimensions = {
    InstanceId = aws_instance.main.id
    path       = "/"
    fstype     = "xfs"
  }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
}

# The CloudWatch agent publishes the disk metric. PutMetricData takes no resource, so the
# only limit available is the namespace condition.
resource "aws_iam_role_policy" "instance_put_metrics" {
  # checkov:skip=CKV_AWS_355: PutMetricData does not support resource-level permissions. The
  # namespace condition is the limit.
  name = "put-own-metrics-only"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PutOwnNamespaceOnly"
      Effect   = "Allow"
      Action   = ["cloudwatch:PutMetricData"]
      Resource = "*"
      Condition = {
        StringEquals = { "cloudwatch:namespace" = local.metrics_namespace }
      }
    }]
  })
}
