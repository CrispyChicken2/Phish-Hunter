# Deploying Lookalike Hunter on AWS

This is the runbook for the single-instance deployment (ADR 0001, budget ADR 0002). It
covers prerequisites, secrets, applying the infrastructure, checking it, daily use, code
updates, the dashboard, and destroying everything.

Read the warnings first. Each section says which commands change things and which only
read.

## Warnings

- **Costs money.** About the budget in ADR 0002 (USD 20 a month). The itemised estimate
  is in `docs/costs.md` (P1.10, not yet written).
- **Terraform never runs on its own.** Run `plan` first, read it, then `apply` the saved
  plan. No script in this repository applies anything.
- **The database lives on the instance's disk.** Replacing the instance deletes it. Any
  change to `user_data` or to `repo_commit` in Terraform replaces the instance. Do not
  do that without a backup and a decision (see "Updating the code").
- **Secrets never go in git, in `*.tfvars` committed to the repository, or in the chat.**
  Enter them with the hidden-input commands below.
- **Destroying is irreversible.** See "Destroying everything".

## 1. Prerequisites (on your PC, Windows PowerShell)

| What | Why | Check |
|---|---|---|
| AWS CLI v2 | talks to AWS and starts the SSM session | `aws --version` |
| Session Manager plugin | needed by `aws ssm start-session` | `session-manager-plugin` runs |
| Terraform 1.9 or newer (CI uses 1.16.6) | applies `infra/` | `terraform version` |
| SSO profile `PhishHunter-plan` | read-only, for `plan` | `aws sso login --profile PhishHunter-plan` |
| SSO profile `PhishHunter-apply` | admin, for `apply`, the secrets and the session | `aws sso login --profile PhishHunter-apply` |

The read-only profile cannot read everything Terraform refreshes. If `plan` reports
`AccessDenied`, either add the missing read action to the permission set (the way
P1.12 did), or run `plan` with `-refresh=false` and say so in the PR. Never widen the
admin profile for this.

The commands below assume the repository folder is the current folder.

## 2. Secrets (SSM Parameter Store, entered by hand)

Two values, created by you and never stored by Terraform:

| Parameter | Content |
|---|---|
| `/lookalike-hunter/mistral-api-key` | the Mistral API key |
| `/lookalike-hunter/alert-webhook-url` | the Discord (or Slack) webhook URL |

Enter one at a time. The prompt hides the value, and nothing is printed or saved:

```powershell
$k = Read-Host "Mistral API key" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($k))
aws ssm put-parameter --name /lookalike-hunter/mistral-api-key --type SecureString --overwrite --value $plain --profile PhishHunter-apply
Remove-Variable plain, k
```

Replace the name and the prompt for the webhook. Check that a value exists, without
reading it:

```powershell
aws ssm describe-parameters --parameter-filters "Key=Name,Option=Equals,Values=/lookalike-hunter/mistral-api-key" --profile PhishHunter-apply --query "Parameters[0].LastModifiedDate" --output text
```

The instance reads the values when a service starts, and only then. After you change a
value, restart the service that uses it.

## 3. Infrastructure: plan, then apply

```powershell
$env:AWS_PROFILE = "PhishHunter-plan"
$env:TF_VAR_budget_alert_email = "you@example.com"   # required: the budget's alert address
terraform -chdir=infra init -input=false
terraform -chdir=infra plan -input=false -no-color -refresh=false -out="$env:TEMP\lh.tfplan"
```

Two things to know about this plan:

- `TF_VAR_budget_alert_email` is required, so a plan can never remove the budget's
  existing alert address. Set it in every new PowerShell window. Never commit it.
- `-refresh=false` is there because the read-only profile cannot read the budget, the
  bucket policy, the role's inline policies and a few other settings. Without the
  refresh, the plan compares the code with Terraform's state only, so it does not see
  changes made by hand in the console. For a full check, run the same plan with the
  admin profile and without `-refresh=false`. A plan only reads; it never changes AWS.

The plan is saved outside the repository. Before applying, check that it:

- says `0 to change` and `0 to destroy`, unless you know why;
- does not replace `aws_instance.main` (the line `must be replaced` must not appear);
- lists only the resources you expect.

Apply the saved file, with the admin profile:

```powershell
$env:AWS_PROFILE = "PhishHunter-apply"
terraform -chdir=infra apply "$env:TEMP\lh.tfplan"
```

Useful outputs, which are ids, not secrets:

```powershell
terraform -chdir=infra output -raw instance_id
terraform -chdir=infra output -raw captures_bucket_name
```

The alarm e-mail is optional. To add it, set `TF_VAR_alarm_email` to your address before
the plan (`$env:TF_VAR_alarm_email = "you@example.com"`), and confirm the subscription
link AWS e-mails you. Don't commit the address.

## 4. Connect to the instance

```powershell
aws ssm start-session --target <instance_id> --profile PhishHunter-apply
```

Then `sudo -i` for a root shell. There is no SSH key and no open port.

## 5. Set-up that Terraform does not do

The instance's first-boot script (`infra/provision.sh.tftpl`) installs Docker, uv, the
code at a pinned commit, and the certstream service. Everything below is copied or typed
by hand, because changing the script would replace the instance. Each file is in the
repository under `deploy/`, and `deploy/README.md` explains each step. The manual changes
are also listed in `docs/STATUS.md`.

1. **Capture archive and backup timers** (`deploy/lookalike-archive.*`,
   `deploy/lookalike-backup.*`). Copy to `/etc/systemd/system/`, then
   `systemctl daemon-reload` and `systemctl enable --now` the `.timer` units.
2. **Bucket names**, which are kept out of git. Create a drop-in for each service:
   - `/etc/systemd/system/lookalike-archive.service.d/bucket.conf` with
     `[Service]` and `Environment=LH_ARCHIVE__BUCKET=<captures_bucket_name>`;
   - the same for the backup service with `LH_BACKUP__BUCKET`. **This drop-in is not
     in the repository yet** and is not listed in `docs/STATUS.md`. Check it exists
     with `systemctl show lookalike-backup -p Environment`. If it doesn't, create it.
3. **Log files and the CloudWatch agent** (P1.9): `deploy/README.md`, and
   `docs/STATUS.md`.
4. **The watch service**: `lookalike-watch.service` and its log drop-in. It is started
   by hand after the secrets are in place (section 2). Check whether it starts on boot
   with `systemctl is-enabled lookalike-watch`. If it prints `disabled`, decide whether
   you want it to start on boot, then run `systemctl enable lookalike-watch` yourself.

## 6. Verify

On the instance:

```
systemctl is-active lookalike-certstream lookalike-watch
systemctl list-timers --no-pager
ls -l /var/log/lookalike-hunter/
```

From your PC (read-only profile where it works, otherwise the admin profile):

```powershell
aws logs describe-log-streams --log-group-name /lookalike-hunter/watch --profile PhishHunter-apply
aws cloudwatch describe-alarms --profile PhishHunter-apply --query "MetricAlarms[].[AlarmName,StateValue]" --output table
```

Expected: a log stream named after the instance id in each group, and the alarms `OK`
or `INSUFFICIENT_DATA` while the setup is young. `ALARM` on `no-certificates` means
`watch` is not running or no certificates arrive.

To test the webhook without printing it, run this on the instance:

```
W=$(aws ssm get-parameter --name /lookalike-hunter/alert-webhook-url --with-decryption --query Parameter.Value --output text --region eu-north-1)
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d '{"content":"test"}' "$W"
unset W
```

`204` means Discord accepted it. Check the channel.

## 7. Daily use

| Task | Command on the instance |
|---|---|
| service status | `systemctl status lookalike-watch` |
| recent watch events | `tail -n 50 /var/log/lookalike-hunter/watch.log` (the journal only holds systemd's own lines: the services log to files) |
| recent feed fetches (P2.1) | `tail -n 20 /var/log/lookalike-hunter/feed.log` |
| run the archive now | `systemctl start lookalike-archive.service` |
| run a backup now | `systemctl start lookalike-backup.service` |
| restart watch after a secret change | `systemctl restart lookalike-watch` |

The logs also go to CloudWatch, in the groups `/lookalike-hunter/watch`, `archive` and
`backup`, for 30 days.

## 8. Updating the code

Two ways, and only one is safe for the database:

- **Recommended, no instance replacement:** on the instance, fetch and check out the new
  commit, sync the dependencies, and restart the services:

  ```
  runuser -u lookalike -- git -C /opt/lookalike-hunter fetch origin
  runuser -u lookalike -- git -C /opt/lookalike-hunter checkout --detach <new commit>
  runuser -u lookalike -- env HOME=/var/lib/lookalike-hunter bash -c 'cd /opt/lookalike-hunter && uv sync --locked --no-dev'
  runuser -u lookalike -- env HOME=/var/lib/lookalike-hunter bash -c 'cd /opt/lookalike-hunter && docker compose --profile tools build capture'
  systemctl restart lookalike-watch
  ```

  The `build` line matters: `docker compose run` builds the capture image only when
  none exists, so without it the container keeps running the code of its first build
  while the host runs the new one. It takes a few minutes, mostly the browser layer.

  Git runs as `lookalike`, the owner of the checkout: run as root, git refuses a
  repository owned by another user ("detected dubious ownership"). The fetch also
  accepts the rewritten history of 2026-10-19, since a fetch overwrites the copy of
  the remote branch.

  Record the commit you now run in `docs/STATUS.md` (the manual-changes table).
  Caveat: the new commit must be pushed to GitHub first, and the code must be reviewed
  and merged on `main` before it is used.

- **Only with a decision:** changing `repo_commit` or `user_data` in Terraform replaces
  the instance and deletes the database. Make a backup first (the daily backup, or run
  `systemctl start lookalike-backup.service`) and check it exists in S3.

## 9. Dashboard: review and label on your PC

There is no dashboard on the instance. To review findings and label them, copy the
latest nightly backup and the screenshots to your PC, and run the dashboard there.
Tested 2026-10-22. Use `PhishHunter-apply`: the `plan` permission set can list objects
but not read them (403). Downloading changes nothing in AWS.

```powershell
aws sso login --profile PhishHunter-apply
$b = terraform -chdir=infra output -raw captures_bucket_name
$latest = (aws s3 ls "s3://$b/backups/" --profile PhishHunter-apply | Select-String "database-" | Select-Object -Last 1).ToString().Split()[-1]
New-Item -ItemType Directory -Force dataws | Out-Null
aws s3 cp "s3://$b/backups/$latest" dataws\ --profile PhishHunter-apply
tar -xzf "dataws\$latest" -C dataws
uv run python -c "import duckdb; duckdb.connect('data/aws/lookalike.duckdb').execute('''IMPORT DATABASE 'data/aws/export' ''')"
aws s3 sync "s3://$b/captures" dataws\captures --exclude "*" --include "*.png" --profile PhishHunter-apply
$env:LH_DB_PATH = "data/aws/lookalike.duckdb"
$env:LH_CAPTURE__OUTPUT_DIR = "data/aws/captures"
uv run --extra dashboard streamlit run src/lookalike_hunter/dashboard/app.py
```

`data/` is ignored by git. Labels go to `datasets/eval.jsonl` for sites our scoring
found, and to the git-ignored `datasets/feed/openphish-live.jsonl` for feed sites (the
feed's terms, `docs/feed-data.md`). Captures from the last 6 hours are still on the
instance, not yet archived, and the database copy is from the last nightly backup.

## 10. Destroying everything

Do this only when you decide to remove the deployment. Nothing here runs by itself.

1. **Back up.** Run `systemctl start lookalike-backup.service` and check the new object
   in the captures bucket's `backups/` prefix. A restore was tested on 2026-10-22 (section 9). Keep
   a copy of the database elsewhere if you need it.
2. **Empty the captures bucket.** It is not set to be emptied on destroy, so Terraform
   cannot delete a non-empty bucket. This removes every capture, so do it on purpose:

   ```powershell
   aws s3 rm s3://<captures_bucket_name> --recursive --profile PhishHunter-apply
   ```

3. **Destroy.** Plan the destruction first and read it, with the admin profile:

   ```powershell
   terraform -chdir=infra plan -destroy -input=false -no-color -out="$env:TEMP\lh-destroy.tfplan"
   terraform -chdir=infra apply "$env:TEMP\lh-destroy.tfplan"
   ```

4. **Remove what Terraform does not manage.** The two SSM parameters (`aws ssm
   delete-parameter`) and any AWS Budget created by hand are not in Terraform's state.
   Delete them by hand if you want them gone.

Do not use `terraform destroy` without the plan step.

## Known gaps (as of 2026-10-19)

- Budget and `docs/costs.md`: P1.10, not done.
- Restoring a database backup: not tested.
- Dashboard on the instance: not set up.
- The backup bucket drop-in is not in the repository.
- `repo_commit` in Terraform (`6e3925c`) no longer exists on GitHub: the history was
  rewritten on 2026-10-19 to remove feed-derived lines. Its replacement is `6423d72`.
  The running instance still has the old objects locally and is not affected. A
  rebuild needs `repo_commit` set to `6423d72` in the same planned change (section 8).
  The instance's current commit is `fff65b6` in the new history.
