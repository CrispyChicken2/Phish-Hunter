# ADR 0001: Single-instance deployment on EC2

- **Status:** Proposed. The budget is now $15/month, which rules out the instance sizes below. See ADR 0002 for the cost ceiling and the options that fit it.
- **Date:** 2026-10-17
- **Decided by:** project owner

## Context

Lookalike Hunter is a working pipeline on one machine. It has three parts with
different needs:

- Certificate Transparency ingest, which runs a local `certstream-server-go` and a
  Python consumer at roughly 1–2k certificates/s (README).
- DuckDB as the database. DuckDB allows a single writer, and `watch` is designed for
  one machine (`src/lookalike_hunter/watch.py`, `ingest/store.py`).
- Passive capture in a hardened Docker container, with a 2 GB memory cap and a 512
  PID cap, up to 20 captures per run (`docker-compose.yml`, `configs/default.yaml`).

Phase 1 must deploy this system to AWS without rewriting its storage layer. The
mission says to extend, not refactor, and records the single-writer limit as the
reason for this choice.

## Decision

Deploy the existing system unchanged on **one EC2 instance** in **eu-north-1**
(Stockholm), with these properties:

- **Network:** a dedicated VPC with one public subnet. The security group has **no
  ingress rules**. There is no NAT Gateway.
- **Access:** SSM Session Manager only. No SSH key. The dashboard stays bound to
  `127.0.0.1` and is reached through an SSM port-forward.
- **Services:** `certstream-server-go` and `lookalike-hunter watch` run as systemd
  units with automatic restart. Docker runs the capture container, as it does today.
- **Storage:** the DuckDB file on an encrypted EBS gp3 volume. Captures are synced
  to a private S3 bucket, and expire under a lifecycle rule. Nightly backups of the
  database and `datasets/eval.jsonl` go to S3.
- **Secrets:** `MISTRAL_API_KEY` and `LH_ALERT__WEBHOOK_URL` live in SSM Parameter
  Store as SecureString. Terraform creates only the read permission, never the value.
- **Metadata:** IMDSv2 required, hop limit 1, so containers cannot reach the instance
  metadata service. This is defence in depth on top of the browser-level block that
  already exists.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| SQS + ECS/Fargate + RDS (distributed) | Replaces DuckDB, which the mission forbids for this phase. RDS adds its own fixed monthly cost on top of compute. |
| Fargate for capture only | Separates capture from the database, so results must cross a network. That is a redesign of the handoff, and Fargate adds per-task cost. Deferred to the scale path below. |
| Lambda for capture | Chromium needs more time and memory than a Lambda invocation, and the capture container needs writable state. |
| Private subnet + NAT Gateway | A NAT Gateway has a fixed hourly charge plus per-GB processing. The mission forbids it for cost. A public subnet with no inbound rules gives egress without it. |
| SSH key access | The mission forbids it. SSM gives an audited session with no key to manage. |
| `t3.micro` or `t3.small` (1 GiB or 2 GiB RAM) | The capture container alone is capped at 2 GiB, before Python, `certstream-server-go` and the OS. Not viable. |
| `t4g` (Graviton, arm64) | Cheaper per hour, and the mission allows an instance chosen on justification. Not chosen yet: the capture image's arm64 build has not been tested here. It is a candidate to measure, not a decision. |

## Instance size and cost

Prices are on-demand, Linux, EU (Stockholm), from the AWS Pricing API (read-only query on
2026-10-17). Monthly figures assume 730 hours.

| Instance | RAM | vCPU | Type | $/hour | ~$/month |
|---|---|---|---|---:|---:|
| t3.small | 2 GiB | 2 | burstable | 0.0216 | 15.77 |
| t3.medium | 4 GiB | 2 | burstable | 0.0432 | 31.54 |
| t3.large | 8 GiB | 2 | burstable | 0.0864 | 63.07 |
| m7i.large | 8 GiB | 2 | fixed CPU | 0.1071 | 78.18 |

Storage: gp3 in Stockholm is $0.0836 per GB-month. A 30 GiB volume is about $2.51 per
month.

Not yet priced, and to be priced in P1.10 before any figure is written down: public
IPv4 address, S3 storage and requests, CloudWatch Logs ingestion and storage, and data
transfer out.

**Recommendation: `t3.large` (8 GiB).** It is the smallest size that holds the 2 GiB
capture cap, the Python consumer and `certstream-server-go` with headroom. `t3.medium`
is the cheapest size that might work. It is 4 GiB, and I would expect memory pressure
during a capture run, but that is a guess until measured. `m7i.large` costs more and
removes CPU-credit risk, which is not worth paying for before measurement.

**The budget conflict.** The account already has a monthly AWS Budget named "My
Monthly Cost Budget" with a $10 limit (read-only query, 2026-10-17). A 24/7 instance
of any size that can run the capture container costs more than $10 per month before
storage, IP address, logs and transfer. The $10 limit will be exceeded every month if
the instance runs continuously. The options are:

1. Raise the budget to the real figure once P1.10 has priced everything.
2. Run the instance only while measuring, and stop it otherwise. Stopping ends compute
   charges, but EBS and the IP address still bill, and the pipeline stops, so there is no
   continuous monitoring.
3. Accept a smaller instance and a reduced workload, and record the consequence (for
   example, fewer captures per run). This is a design change and needs a new ADR.

## Limits

- **No redundancy.** One instance is one failure domain. If it stops, ingestion and
  capture stop until it is back. Certificates issued while it is down are not
  ingested by this pipeline. Recovering them would need a separate backfill design.
- **Single writer.** DuckDB cannot be shared across machines. Adding a second
  consumer means changing storage.
- **CPU credits.** A `t3` instance accrues credits while idle and spends them under
  load. Sustained Chromium load can exhaust the balance and throttle the instance.
  Unlimited mode avoids throttling but bills the excess. The P1 acceptance test must
  record the credit balance under real load.
- **Disk.** Captures grow until expired. The 80% disk alarm is the only guard until the
  retention rule is measured.
- **Throughput.** One Python consumer is already known to drop certificates during
  backlog replay (README). This ADR does not change that.

## Security notes

- No inbound port is opened. Access is through SSM, which is logged by AWS.
- The capture container keeps every existing protection. This ADR does not change
  `docker-compose.yml`.
- The instance profile is the least-privilege role defined in P1.8, not an
  administrator role.
- S3 buckets are private with Block Public Access enabled.

## What would change at larger scale

This is a path, not a decision. Each step needs its own ADR.

1. Replace DuckDB with a server database, so several consumers can write.
2. Put a queue (SQS) between ingest and capture, so capture can scale on its own.
3. Run capture as separate workers (ECS/Fargate or EC2 Auto Scaling). The container
   is already isolated from the database, so this moves the boundary rather than
   removing it.
4. Add a second availability zone for the ingest path.

## Consequences

- The deployment is simple to explain and to destroy: one instance, one VPC, one
  bucket set.
- The cost is set by the budget decision above, not by the architecture.
- The instance size is provisional. P1.3 and the measurement under load decide the
  final size, and the decision is recorded by a new ADR or by amending this one.
