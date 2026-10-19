# Status: phase 2 plan (AWS deployment and phishing measurement)

Last updated: 2026-10-19. Kept current by each PR in this plan.

## Baseline (Phase 0)

Checked on `main` at `5b7c26c`:

| Check | Command | Result |
|---|---|---|
| Lint | `uv run ruff check .` | All checks passed |
| Format | `uv run ruff format --check .` | 73 files already formatted |
| Types | `uv run mypy src tests` (`strict = true` in `pyproject.toml`) | Success, 69 source files |
| Tests | `uv run pytest -q` | 351 passed, 1 skipped |

`make check` is the same three steps plus lint, run through `make`. `make` is not
installed on the development machine (Windows), so the commands above were run
directly. CI runs the same commands, not `make`. Installing `make` locally is a
convenience, not a gap in the checks.

## What exists

- Ingestion of Certificate Transparency through a local `certstream-server-go`
  (`docker-compose.yml`, service `certstream`).
- Scoring: dnstwist variants, homoglyph skeleton, token typos, combosquats
  (`src/lookalike_hunter/scoring/`, `variants/`).
- Passive capture in a hardened container: non-root, all capabilities dropped,
  `no-new-privileges`, read-only root filesystem, memory and PID caps, browser
  sandbox enabled. `seccomp=unconfined` is a known, documented trade-off
  (`docker-compose.yml`, README).
- Result handoff: the host validates every container result before it becomes a row
  (`capture/handoff.py`).
- VLM classification (`classify/`, Mistral, default `ministral-8b-latest`) and a stub
  backend.
- Measured evaluation (`eval/`), model comparison (`compare-models`), labelled dataset
  (`datasets/eval.jsonl`, rules in `docs/labelling-protocol.md`).
- Feed reader for OpenPhish (`eval/feeds.py`). Its brand filter deliberately does not
  use the Scorer.
- Webhook and JSONL alerting (`alert/`), a Streamlit labelling dashboard
  (`dashboard/`), and the `watch` loop (`watch.py`).
- CI (`.github/workflows/ci.yml`): ruff, format check, mypy, pytest. Actions are pinned
  to commit SHAs and permissions are `contents: read`.

## What this plan adds

- **Phase 1:** the existing system deployed unchanged on one EC2 instance, described
  in Terraform under `infra/`, with an ADR, a runbook, and a cost estimate. No inbound
  port, SSM access only, secrets in SSM Parameter Store, captures archived to a private
  S3 bucket, nightly backups, least-privilege IAM, CloudWatch logs and alarms.
  Terraform runs `plan` only. The user runs `apply`.
- **Phase 2:** a fast-capture timer for phishing feed entries; a cloaking comparison
  between two vantage points (AWS and the home PC); bootstrap confidence intervals and
  an exact McNemar test; updated measured results once at least 30 phishing sites are
  labelled.
- **Phase 3 (if time allows):** a `rescore` command; a vendored Chrome seccomp profile
  in place of `seccomp=unconfined`, with a test that the sandbox starts; an egress proxy
  against DNS rebinding (ADR first, user approval before implementation).

## Ticket list

Status: `todo`, `doing`, `review` (PR open), `done`, `blocked`.
⏸ marks a checkpoint where work stops until the user reviews.

### Phase 0: status

| ID | Ticket | Status | Notes |
|---|---|---|---|
| P0.1 | Verify `make check` equivalent on `main` and write this file | done | Ticket list approved by the owner on 2026-10-19. `make check` equivalent passes on `main` (ruff, format, mypy, pytest) |

### Phase 1: AWS deployment

| ID | Ticket | Status | Notes |
|---|---|---|---|
| P1.0 | ADR 0001: single-instance deployment (why, cost, limits, scale path) | done | `docs/adr/0001-single-instance-deployment.md`, still Proposed, amended by ADR 0002 (option A, budget $20). ADR 0002 is accepted (2026-10-17). ⏸ The owner accepts or rejects ADR 0001 |
| P1.1 | Terraform skeleton: provider and version pins, variables, tags, no credentials in code; `make tf-plan` | done | Done: `infra/`, `make tf-fmt`, `make tf-validate`, `make tf-plan`. Local `validate` blocked by an x509 error (antivirus, likely), so it runs in CI. Local state, as decided |
| P1.2 | Network: small VPC, one public subnet, no ingress rule, no NAT Gateway | done | Done in `infra/network.tf`. Checkov: 9 passed, 0 failed, 4 skipped with reasons in the code (public IP, open egress, SG not yet attached, no flow logs). `validate`/`plan` need CI or your login |
| P1.3 | EC2 instance: type justified in ADR; IMDSv2 required, hop limit 1; encrypted EBS volume for DuckDB; no SSH key | done | Done in `infra/instance.tf`: t4g.small, arm64 Amazon Linux 2023, encrypted 20 GB gp3, IMDSv2 hop 1, SSM-only role. Checkov: 22 passed, 0 failed. `plan` blocked locally: the Terraform plugin connection fails with x509 (antivirus HTTPS scanning, same cause as the SSL error). Read-only login works (`PhishHunter-plan`, ViewOnlyAccess) |
| P1.4 | Provisioning: user_data installs Docker and uv, clones the repo at a pinned commit, creates systemd units for certstream and `watch` with restart | done | Done in `infra/provision.sh.tftpl`: 2 GiB swap, Docker, uv (checksum-verified), pinned commit `6e3925c`, certstream unit (localhost only), `watch` unit installed but not started (P1.5). Changing user_data replaces the instance (intended while the DB is empty). Checkov: 22 passed, 0 failed. A plan will show the instance being replaced |
| P1.5 | Secrets: IAM read permission on two named SSM SecureString parameters; values entered by hand; read at service start, never on disk in clear or in logs | done | Terraform never reads the values (keeps them out of state) |
| P1.6 | Captures: private S3 bucket (Block Public Access, encryption, versioning off), sync timer, expiry lifecycle, local purge after archive | done | Code: `src/lookalike_hunter/archive.py`, `lookalike-hunter archive` (deletes a local copy only after its upload succeeded; skips links and the job folder; archives captures older than 6 h). Infra: `infra/captures.tf` (bucket with a random suffix, PAB, owner-enforced, AES256, TLS-only, 90-day expiry, multipart cleanup, instance may only PutObject under `captures/`). Timer: `deploy/`, installed by hand (see manual changes). Applied and running: the archive timer runs every 30 min. On 2026-10-19 the first run archived 28 captures, and its log reached CloudWatch. |
| P1.7 | Backups: daily snapshot of DuckDB and `datasets/eval.jsonl` to S3 | done | Code: `src/lookalike_hunter/backup.py`, `lookalike-hunter backup`. The database is exported through a read-only connection (a consistent snapshot, not a file copy), packed, uploaded under `backups/`. The dataset is uploaded if present. Failures are raised, nothing is deleted. Timer: daily 03:00 UTC, in `deploy/`. S3 keeps 30 days (`backup_retention_days`). Applied and tested 2026-10-18: `database-20261018T203132Z.tar.gz` (1.2 MB) in S3. Not yet tested: restoring from a backup. The dataset is skipped until `eval.jsonl` exists on the instance |
| P1.8 | IAM: least-privilege instance role (bucket prefixes, named SSM parameters, CloudWatch Logs, SSM core) | done | Done and applied 2026-10-19. Log question closed 2026-10-19: the instance created a real log stream in `/lookalike-hunter/archive` with the agent (the simulator denial was a simulator artifact). Earlier: the AWS-managed SSM policy (which allowed reading every SSM parameter) was replaced by the minimum Session Manager actions; a live session still opens (`ssm-user`). Verified with the policy simulator: the instance reads its two named secrets only; PutObject only under captures/ and backups/; no list, read or delete on the bucket. Trust limited to this account. Open: the simulator allows `logs:DescribeLogStreams` on the log group but denies `logs:PutLogEvents` and `logs:CreateLogStream`, although the policy lists all three. To be checked against a real log group in P1.9 | | No wildcard without a written reason |
| P1.9 | Observability: JSON logs to CloudWatch Logs; alarms for no certificate in 10 min, repeated failed `watch` cycles, disk > 80% | done | Code: `infra/logs.tf` (3 log groups under `/lookalike-hunter/`, 2 metric filters, 3 alarms, SNS topic, optional e-mail), `cloudwatch:PutMetricData` limited to the `LookalikeHunter` namespace in `infra/logs.tf`. Instance: `deploy/` (agent config, unit redirects to `/var/log/lookalike-hunter/*.log`, `watch` drop-in, logrotate, steps in `deploy/README.md`). Terraform applied 2026-10-19 from a saved plan: 10 added, 0 changed, 0 destroyed. Agent installed and running on the instance 2026-10-19. Verified: disk metric dimensions match the alarm, and the archive log stream arrived in CloudWatch. Checkov 3.3.29: 92 passed, 0 failed. Local `validate` blocked (provider plugin, as in P1.1). Verified 2026-10-19: `watch` runs on the instance and its logs reach CloudWatch (stream on `/lookalike-hunter/watch`). The `no-certificates` alarm is `OK`. Not yet done: the alarm e-mail subscription (optional), and the repeated-failures alarm has not been seen firing (no failures to test with) |
| P1.10 | Cost: `aws_budgets_budget` with e-mail alert (variable); `docs/costs.md` itemised with assumptions | done | Budget: the existing "My Monthly Cost Budget" is imported into Terraform (`infra/budget.tf`), limit USD 20, monthly, the three alerts unchanged, sent to the address in `TF_VAR_budget_alert_email`. Applied 2026-10-19 (1 changed: tags added and alerts rewritten with the same values). Read back: alerts and limit unchanged, status HEALTHY. `docs/costs.md` written: unit prices from the AWS Price List, usage figures marked as assumptions. Estimate about USD 20.06 a month, at the limit (see the document). The owner keeps the limit at USD 20 (confirmed 2026-10-19, matches AWS). ⏸ The owner checks the figures in the pricing calculator |
| P1.11 | CI: `terraform fmt -check`, `terraform validate`, checkov or tfsec; no AWS credentials in CI | done | `infra` job in `.github/workflows/ci.yml`, read-only permissions, actions pinned to SHAs, checkov 3.3.29 pinned. First CI run 2026-10-18: both jobs passed. Warnings to fix later: Node.js 20 actions (setup-uv, setup-terraform), and `ubuntu-latest` moves to Ubuntu 26 on 2026-10-19 |
| P1.12 | `terraform plan` runs cleanly; plan output attached to the PR | done | Plan passed 2026-10-18 (11 to add). Applied by the owner with the admin login: 11 added, 0 changed, 0 destroyed. Instance running; checked read-only: t4g.small, IMDSv2 required with hop limit 1, encrypted 20 GB gp3. Instance IDs are in the Terraform state, not in git. ⏸ for the owner's review and the SSM connection test |
| P1.13 | `docs/deploy-aws.md` runbook (prerequisites, secrets, apply, verify, dashboard tunnel, code update, destroy); README section and cloud diagram | done | Runbook written 2026-10-19; its "Known gaps" section lists what it does not cover. The owner reviewed it on 2026-10-19 and found no problems. The section 6 checks were not run by the owner, so they are still unverified. README "Deploying on AWS" section and cloud diagram written |

### Phase 2: measurement

| ID | Ticket | Status | Notes |
|---|---|---|---|
| P2.1 | Fast capture of phishing feed entries: timer, brand selection without the Scorer, existing dataset capture path; feed terms and refresh rate documented | todo | Terms of the OpenPhish feed must be read and quoted in the doc, not assumed |
| P2.2 | Vantage-point concept in `CONTEXT.md`; record the vantage point with each capture | todo | Possible minimal schema change, explained in the PR |
| P2.3 | Cloaking comparison command: two capture sets, reports unreachable on one side, different content, different verdict | todo | ⏸ after P2.1 to P2.3 |
| P2.4 | 95% bootstrap confidence intervals on accuracy and macro F1 in `evaluate` | review | `eval/stats.py`: percentile bootstrap, 10,000 resamples, fixed seed. Shown in each arm's report. Macro F1 leaves out a class missing from a resample (documented). Tests in `tests/test_stats.py` |
| P2.5 | Exact McNemar test in `compare-models`, replacing the coin-flip argument | review | `eval/stats.py`: exact two-sided binomial test on the disagreements, printed for every pair of models. The README example gives p = 0.6875 (computed, not hand-typed). The README coin-flip sentence is replaced. Not run on a live model comparison yet (needs Mistral calls) |
| P2.6 | Updated results: rerun `evaluate` and `compare-models`, update "Measured results" and correct contradicted claims | blocked | Waits for at least 30 phishing sites captured and labelled, validated by the user in the dashboard |

### Phase 3: security limitations (if time allows, in this order)

| ID | Ticket | Status | Notes |
|---|---|---|---|
| P3.1 | `rescore` command: recompute stored Matches after the weights change | todo | |
| P3.2 | Vendored Chrome seccomp profile replacing `seccomp=unconfined`; sandbox kept enabled; a test proves the sandbox starts | todo | Strengthens the container. It does not weaken it |
| P3.3 | Egress proxy against DNS rebinding: resolve once, check the address, connect to that address | todo | ADR first; ⏸ user approval before implementation |

## Manual changes on the instance (not yet in Terraform)

These were applied by hand over SSM, because a change in the setup script replaces
the instance and deletes the database. Each one must be turned into code or into the
runbook (P1.13) before the instance is ever rebuilt:

| Change | Why | Where it lives |
|---|---|---|
| Docker Compose v5.6.0 plugin (`/usr/libexec/docker/cli-plugins/docker-compose`), checksum-verified | the capture step runs `docker compose` | not in the setup script |
| Docker Buildx v0.38.0 plugin (`docker-buildx`), checksum-verified | `docker compose build` needs buildx 0.17+ | not in the setup script |
| ACL on `/var/lib/lookalike-hunter/captures` for uid 1001 (the capture container's user) and uid 993 (the host's `lookalike`) | the container could not read job files | not in the setup script |
| The watch process runs commit `6523718` (the failure counter fix) | the setup script still pins `6e3925c` | `repo_commit` in Terraform, to update at the next rebuild |
| Archive timer and service from `deploy/` in `/etc/systemd/system`, enabled every 30 min (P1.6) | the setup script is not changed, since that would replace the instance | `deploy/` in the repository |
| Drop-in `/etc/systemd/system/lookalike-archive.service.d/bucket.conf` with the bucket name | the bucket name is kept out of git | Terraform output `captures_bucket_name` |
| The watch process and the archive run commit `d80e905` | P1.6 code | `repo_commit` in Terraform, to update at the next rebuild |
| CloudWatch agent installed with `dnf` and configured with `fetch-config` (P1.9) | the setup script is not changed, since that would replace the instance | `deploy/README.md`, `deploy/cloudwatch-agent.json` |
| `/var/log/lookalike-hunter` created; archive, backup and watch logs go to files there (`StandardError=append:`), via the unit files and the `watch` drop-in (P1.9) | same | `deploy/*.service`, `deploy/lookalike-watch.service.d/logs.conf` |
| logrotate for those files (P1.9) | same | `deploy/logrotate-lookalike-hunter` |

## Standing rules (from the mission)

- Terraform: `plan` only. Never `apply` or `destroy`.
- No AWS CLI command that creates, modifies or deletes a resource.
- No switch to the paid Mistral tier without approval.
- Passive collection only: no interaction with visited sites.
- No existing protection of the capture container is weakened.
- Never push to `main` directly. Never merge our own PR.
- Every new figure in the docs comes from a command.

## Open decisions (to settle in ADRs)

- Remote Terraform state: local file, or an S3 backend with a bucket created outside
  Terraform.
- Instance type: must hold Chromium (2 GB container cap, up to 20 captures per run)
  plus the Python consumer at 1–2k certificates/s.
- Capture retention: default duration for the S3 lifecycle rule.
- AWS region: `eu-north-1` (Stockholm), set by the user.

## Actions for the user (not for the agent)

- [ ] **P1.12 (before `terraform plan`):** create a read-only AWS profile on your PC
      (`aws configure sso` or `aws configure --profile lh-plan`, policy
      `ReadOnlyAccess`). Keys are typed into your terminal only, never pasted in chat
      or committed. Tell the agent the profile name.
- [x] **Budget:** raised to $20/month, option A (ADR 0002, accepted 2026-10-17). The
      console budget still says $15 and must be updated in P1.10.
- [ ] **ADR 0002 conditions:** arm64 check of the other two images, memory and CPU-credit
      test under load, swap. Owner's fallback if the memory test fails: option B at $15.
- [x] **P1.10 budget e-mail:** given privately, kept out of the repo (see the
      `*.tfvars` rule in `.gitignore`).
- [x] **P1.10:** decided: Terraform manages the existing AWS Budget (imported, applied 2026-10-19).
- [x] **P1.5 (after P1.12):** (Mistral key checked: HTTP 200 on the instance. Webhook tested on the instance: HTTP 204 from Discord, 2026-10-19. The first webhook was no longer valid afterwards, so a new one was created and stored in SSM the same day, and `watch` was restarted to read it. The message was received in Discord.) enter `MISTRAL_API_KEY` and `LH_ALERT__WEBHOOK_URL` into
      SSM Parameter Store as SecureString, by hand.
- [ ] **P1.12:** run `terraform apply` yourself. The agent never applies.
- [ ] **P1.13:** check that the backup service has its bucket drop-in (`LH_BACKUP__BUCKET`):
      `systemctl show lookalike-backup -p Environment` on the instance. The drop-in is not in the
      repository, so note its path here once it is confirmed.
- [x] **P1.9:** `terraform apply` done 2026-10-19 (10 added). No e-mail subscription yet: add
      `TF_VAR_alarm_email` and apply again once `watch` runs, then confirm the link AWS sends.
- [ ] **P1.9, on the instance:** copy the files in `deploy/` and install the agent, as in
      `deploy/README.md`. Then check the agent is running and the three log streams appear.
- [ ] **P1.9:** the `no-certificates` alarm will fire until `watch` is started (P1.5). Expect it.
