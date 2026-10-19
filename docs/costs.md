# Monthly cost of the AWS deployment

Estimate for the design in `infra/` (single instance, see ADR 0001). Region `eu-north-1`
(Stockholm), on-demand, 730 hours a month, USD, before VAT.

The budget is USD 20 a month (ADR 0002, `infra/budget.tf`). Its alerts go to the owner at
85% and 100% of the limit, and at a forecast of 100%.

## How the prices were read

Every unit price below comes from the AWS Price List API (`aws pricing get-products`). The
calls are read-only and were made with the admin profile. Each price is matched on the usage type for Stockholm
(`EUN1-...`). The product description is shown next to each price, so the price
can be checked against the console. The owner should still confirm each one in the AWS
pricing calculator before relying on it.

Figures that are not from the price list are marked **assumption**. They are usage guesses
and must be replaced by measured values once the system has run for a month.

## Fixed monthly cost (independent of usage)

| Item | Unit price (source) | Quantity | Monthly |
|---|---|---|---:|
| EC2 `t4g.small`, Linux, on-demand | $0.0172 per hour ("On Demand Linux t4g.small Instance Hour", `EUN1-BoxUsage:t4g.small`) | 730 h | 12.56 |
| Public IPv4 address, in use | $0.005 per hour ("In-use public IPv4 address per hour", `EUN1-PublicIPv4:InUseAddress`) | 730 h | 3.65 |
| EBS gp3 root volume (encrypted) | $0.0836 per GB-month ("General Purpose (gp3) provisioned storage", `EUN1-EBS:VolumeUsage.gp3`) | 20 GB | 1.67 |
| CloudWatch custom metrics (disk, CtFlush, FailedWatchCycles) | $0.30 per metric-month, first 10,000 ("for the first 10,000 metrics", `EUN1-CW:MetricMonitorUsage`) | 3 | 0.90 |
| CloudWatch alarms, standard resolution | $0.10 per alarm-month ("per alarm metric month", `EUN1-CW:AlarmMonitorUsage`) | 3 | 0.30 |
| **Fixed subtotal** | | | **19.08** |

The three metrics come from `infra/logs.tf` (`LookalikeHunter` namespace). The three alarms
are no-certificates, repeated watch failures and disk above 80%.

The Terraform budget (`aws_budgets_budget`), the SNS topic, the S3 bucket with its
lifecycle rules, the IAM roles, the VPC and the security group are not billed at this scale.
The VPC has no NAT gateway, so there is no hourly charge for one. I haven't looked up the
price of the budget or of SNS e-mail in the price list, so their monthly figure is not
stated here. Check them in the calculator.

## Variable monthly cost (depends on usage)

Unit prices are from the price list. Quantities are **assumptions**.

| Item | Unit price (source) | Assumed quantity | Monthly |
|---|---|---|---:|
| S3 Standard storage, captures and backups | $0.023 per GB-month, first 50 TB ("per GB - first 50 TB / month", `EUN1-TimedStorage-ByteHrs`) | 10 GB | 0.23 |
| S3 write requests (PUT, COPY, POST, LIST) | $0.005 per 1,000 requests ("per 1,000 PUT, COPY, POST, or LIST requests", `EUN1-Requests-Tier1`) | 50,000 | 0.25 |
| CloudWatch Logs ingestion | $0.54 per GB ("custom log data ingested in Standard log class", `EUN1-DataProcessing-Bytes`) | 0.1 GB | 0.05 |
| CloudWatch Logs storage (30 days) | $0.028 per GB-month ("log storage", `EUN1-TimedStorage-ByteHrs`) | 0.1 GB | 0.00 |
| Data transfer out to the internet | $0.09 per GB, first 10 TB ("DataTransfer-Out-Bytes in EU (Stockholm)", `AWSDataTransfer`) | 5 GB | 0.45 |
| **Variable subtotal (assumed)** | | | **0.98** |

Data transfer in is not billed. Transfer between the instance and S3 in the same region is
not billed. The outbound traffic is mostly the visits to suspicious sites, the calls to the
Mistral API and the Discord messages.

The Mistral API and Discord are not AWS services and are not in this total. Mistral's
classification volume must be checked in its console. The paid Mistral tier needs the
owner's approval (mission rules).

## Total

| | USD per month |
|---|---:|
| Fixed | 19.08 |
| Variable, assumed | 0.98 |
| **Estimate** | **about 20.06** |

This is at the limit of the budget. ADR 0002 estimated about 18.90, before the monitoring
added in P1.9 (the three metrics and three alarms, about 1.20 a month). The public IPv4
price is now confirmed.

## Measured so far

On 2026-10-19 the budget showed an actual spend of USD 0.215 for October (read with
`aws budgets describe-budget`). That is a partial month, from the day the instance started,
and it does not yet show a full month of usage.

## What would bring the total below the budget

These are options for the owner to decide. None has been applied.

- **Use fewer alarms or metrics.** Dropping the disk metric and its alarm would save about
  0.40 a month. The disk is the most useful of the three, so this is not recommended.
- **Shorter log retention or fewer log lines.** Logs are small today. Measure them after a
  month before deciding.
- **Raise the budget to USD 25.** This is a decision, and ADR 0002 would need updating.

The alerts are set at 85% of the limit, which is USD 17. A total of about USD 20 would
send that alert every month, so the owner should decide the limit before relying on it.

## What to measure after one month

Replace each assumption with a measured value, using the commands below. Put the results
here, with the date.

```powershell
aws ce get-cost-and-usage --time-period Start=<first day>,End=<last day> --granularity MONTHLY --metrics UnblendedCost --profile PhishHunter-apply
aws s3 ls s3://<captures_bucket_name> --recursive --summarize --profile PhishHunter-apply
```

The second command lists the total size of the captures bucket.
