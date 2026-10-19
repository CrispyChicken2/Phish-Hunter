# deploy/: files for the instance

These files are copied to the instance by hand. Changing the setup script would replace the
instance and its database, so they are not in `user_data`. The copies on the instance are
listed as manual changes in `docs/STATUS.md`. The runbook (P1.13) will replace this list.

## Units and drop-ins (archive, backup, watch)

| File in repo | Copy to the instance |
|---|---|
| `lookalike-archive.service` | `/etc/systemd/system/lookalike-archive.service` |
| `lookalike-backup.service` | `/etc/systemd/system/lookalike-backup.service` |
| `lookalike-watch.service.d/logs.conf` | `/etc/systemd/system/lookalike-watch.service.d/logs.conf` |

Then, as root: `install -d -m 0755 /var/log/lookalike-hunter`, `systemctl daemon-reload`, and
restart `lookalike-watch` if it is running (the drop-in changes where its logs go).

## CloudWatch agent (P1.9)

```sh
dnf install -y amazon-cloudwatch-agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/lookalike-hunter/deploy/cloudwatch-agent.json
```

The agent needs the instance role to allow `logs:*` on `/lookalike-hunter/*` and
`cloudwatch:PutMetricData` in the `LookalikeHunter` namespace. Both are in `infra/`.
Terraform must create the log groups first (`infra/logs.tf`).

Check the agent: `amazon-cloudwatch-agent-ctl -a status` should say `running`. Its own log is
`/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log`. Look there for `AccessDenied`.

## Log rotation (P1.9)

Copy `logrotate-lookalike-hunter` to `/etc/logrotate.d/lookalike-hunter`.
Test it with `logrotate -d /etc/logrotate.d/lookalike-hunter` (dry run, changes nothing).
