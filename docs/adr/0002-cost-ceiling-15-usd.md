# ADR 0002: Cost ceiling of $15 per month

- **Status:** Accepted for option A (full pipeline on AWS, budget raised to $20 per
  month), chosen by the owner on 2026-10-17. Conditions below must pass before P1.3 is
  closed.
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

A t4g.small is the smallest size that can host the 2 GiB Chromium cap at all, and it
already costs $12.56 for compute. Correction: it does not hold the cap with room to spare.
The cap is a ceiling. The operating system, `certstream-server-go` and the Python
consumer also need memory from the same 2 GiB, so a full capture can run out of memory.
That is why option A below carries conditions. The public IPv4 address and the disk take it past $15
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

## Decision

**Option A, budget raised to $20 per month** (owner's choice, 2026-10-17). The full
pipeline, including Chromium capture, runs on one t4g.small. The estimate is about $18.90
per month, with the unverified IPv4 price included. $20 leaves a small margin for logs and
storage growth.

Conditions, all to be checked before P1.3 closes:

1. **arm64 capture image: verified.** `mcr.microsoft.com/playwright/python:v1.63.0-noble`
   has `linux/arm64` and `linux/amd64` manifests (`docker manifest inspect`). The uv image
   (`ghcr.io/astral-sh/uv:0.11.21`) and the certstream image
   (`0rickyy0/certstream-server-go:v1.10.1`) must be checked the same way. The capture
   container cannot be built here yet because the Docker daemon is off.
2. **Memory under real load.** Run a full capture cycle on the t4g.small and record peak
   memory. Add swap on the EBS volume (about 2 GiB) as a safety net against out-of-memory
   kills. Swap is slower, so it is a fallback, not a plan.
3. **CPU credits.** The t4g family is burstable. Record the credit balance under load
   during the same test.
4. **If the memory test fails:** fall back to option B, budget $15, with capture on the
   owner's PC. This is a new decision and needs its own note.

Not chosen: option B (cheaper, but no capture on AWS) and option D (more automation).
A' (IPv6-only) stays unverified and is not used.

Whatever the choice, the project keeps one codebase with a configuration profile (idea 1),
unless the owner asks for a branch.

## Consequences

- The budget becomes $20 in the Terraform budget resource (P1.10). The existing console
  budget is set to $15 and must be updated to match.
- The instance is t4g.small, not the t3.large in ADR 0001. ADR 0001 is amended by this note.
- Every figure in this ADR is from the pricing query or is marked as unverified. The
  unverified figures do not go into the README.
