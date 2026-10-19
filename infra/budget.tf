# Monthly cost budget (P1.10, ADR 0002). The budget already existed in the console, so it is
# imported, not created: see docs/deploy-aws.md. Its name cannot change without replacing the
# budget, so the name is kept as it is in the console.
#
# The alerts go to one address, which is never in the repository. The address is required
# (no default) so that a plan never removes the existing subscriber by mistake.

resource "aws_budgets_budget" "monthly" {
  name         = "My Monthly Cost Budget"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  time_period_start = "2026-10-01_00:00"
  time_period_end   = "2087-06-15_00:00"

  # As in the console: the primary billing view, unblended cost, and credits and refunds
  # left out of the spend. Without these, the budget would count refunds and credits.
  billing_view_arn = "arn:aws:billing::141538081016:billingview/primary"
  metrics          = ["UnblendedCost"]

  filter_expression {
    not {
      dimensions {
        key    = "RECORD_TYPE"
        values = ["Credit", "Refund"]
      }
    }
  }

  # Actual spend above 85% and above 100%, and forecast spend above 100%, as in the console.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 85
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
