# ADR 0002: Cost ceiling of $15 per month

- **Status:** Proposed. Waiting for the owner to choose an option (see Decision).
- **Date:** 2026-10-17
- **Decided by:** project owner
- **Amends:** ADR 0001 (instance sizing and budget)

## Context

The owner's monthly budget for AWS is **$15**. The AWS account is on a **paid plan
with $0 of credits** (read-only query of the account plan, 2026-10-17), so no free-tier
hours apply. ADR 0001 showed that a 24/7 instance large enough for Chromium costs more
than $15 by itself.

The mission sets the rule for this project: spend the strict necessary, as a company
would. The cost must follow from the design, not the other way round, so this ADR
records the numbers first and then the options.

## Verified prices

Source: AWS Pricing API, EU (Stockholm) `eu-north-1`, on-demand, Linux. Monthly figures
use 730 hours.

| Item | Price | ~ per month |
|---|---|---:|
| t4g.nano (Graviton, 0.5 GiB RAM) | $0.0043/h | 3.14 |
| t4g.micro (Graviton, 1 GiB RAM) | $0.0086/h | 6.28 |
| t4g.small (Graviton, 2 GiB RAM) | $0.0172/h | 12.56 |
| EBS gp3 storage | $0.0836/GB-month | 1.67 for 20 GB |
| CloudWatch Logs ingestion | $0.54/GB | 0.54 per GB ingested |
| CloudWatch Logs storage | $0.028/GB-month | 0.03 per GB stored |
| S3 Standard storage | $0.023/GB-month | 0.46 for 20 GB |
| S3 PUT, COPY, POST, LIST | $0.005 per 1,000 requests | negligible at this volume |

**Not verified:** the public IPv4 address. My query of the pricing API returned no
result for it. AWS documents a charge per public IPv4 address per hour in every
region, but I have not confirmed the Stockholm rate, so the figure below is an
estimate of about $3.65/month at $0.005/hour. Confirm it before P1.10 writes it down.

## Options that fit or nearly fit $15

Monthly, rounded. Each row is the total for the stated design.

| Option | Design | EC2 | Storage | IPv4 (est.) | Other | Total | Fits $15? |
|---|---|---:|---:|---:|---:|---:|---|
| A | t4g.small 24/7 with capture, classify and alert | 12.56 | 1.67 | 3.65 | ~1 | ~18.9 | **No** |
| A' | Option A without a public IPv4 (IPv6-only egress, unverified) | 12.56 | 1.67 | 0 | ~1 | ~15.2 | **At the limit, no margin** |
| B | t4g.micro 24/7 for ingest, scoring, classify and alert. No Chromium on AWS | 6.28 | 1.67 | 3.65 | ~1 | ~12.6 | **Yes** |
| C | Option B, with capture run from the owner's PC, as the README already describes | same as B | | | | ~12.6 | **Yes** |
| D | Option B, plus a t4g.small started only for capture runs (e.g. 1 h/day = about $0.52/month) | ~13.1 | | | extra automation | ~13.1 | **Yes, if capture is short** |

"Other" covers logs, S3 storage and requests at a small volume. It is an estimate until
measured.

### Why A does not fit

A t4g.small is the smallest size with enough memory for the 2 GiB Chromium cap, and it
already costs $12.56 for compute. The public IPv4 address and the disk take it past $15
before any logs or screenshots. Only the unverified IPv6-only design (A') gets close, and
it has no margin for the first month of logs and screenshots.

### Why B fits, and what it gives up

A t4g.micro has 1 GiB of RAM. That is far below the capture container's 2 GiB cap, so
Chromium cannot run on it. Option B therefore moves capture out of AWS. It keeps the parts
that run all the time and need no browser: Certificate Transparency ingest, scoring,
classification through the Mistral API, and alerting. The memory of that stack on 1 GiB is
**not measured yet**, and that is the first thing to test.

The trade-off is latency. Captures happen when the capture step runs, not within minutes
of the certificate. The README says phishing sites are often gone within hours, so the
capture interval decides how much phishing the system can still see. That needs a number
from the owner before it is accepted.

## Other ideas

1. **One codebase, two profiles, not a long-lived branch.** A permanent second branch
   drifts from `main`, and every fix has to be made twice. Option: keep the local defaults
   in the code, and add `configs/aws.yaml` as an override (the config already accepts a
   `--config` path, so no code change is needed to load it). Deployment-only files live in
   `infra/`. This keeps "local" and "AWS" as two configurations of one project, which is
   how most companies run a staging and a production environment. A branch can still be
   used for a short experiment.
2. **Spot instances for capture (Option D).** Spot is much cheaper than on-demand, but
   AWS can interrupt it. Capture is retryable, so an interruption costs a re-capture, not
   data. The Spot price is not verified here, so no figure is claimed.
3. **Stop the host outside working hours.** Stopping ends compute charges only. The disk and
   IP address still bill, so the saving is small and the pipeline stops while it is off.
4. **IPv6-only egress (Option A').** Public IPv6 addresses carry no hourly charge. It works
   only if every outbound service the pipeline calls (Mistral API, container registry, GitHub
   for `git clone`, apt) is reachable over IPv6. Not checked, so it is not a plan.
5. **Poll Certificate Transparency logs directly from AWS Lambda.** This removes the
   always-on instance, but it replaces the ingest design and the local certstream server, and
   it has unknown volume and rate-limit costs. That is a redesign and needs its own ADR.

## Decision (for the owner)

Choose one of these:

1. **Option B, with capture on the owner's PC (recommended to start).** Lowest cost, about
   $12.6/month. Measure the t4g.micro memory first (P1.3), then decide how often capture runs.
2. **Option D.** Adds a capture host started for short runs, about $13.1/month. More
   automation and IAM, so a second ADR for the scheduler.
3. **Raise the budget** to fit Option A (about $19), or to fit A' if IPv6 works.

Whatever the choice, the project keeps one codebase with a configuration profile (idea 1),
unless the owner asks for a branch.

## Consequences

- Terraform and the instance size depend on the choice above.
- The budget of $15 is a limit, not a target. P1.10 must set the budget in Terraform,
  with the figures above and the unverified IPv4 price confirmed.
- Every figure in this ADR is from the pricing query or is marked as unverified. The
  unverified figures do not go into the README.
