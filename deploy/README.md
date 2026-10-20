# deploy/: files for the instance

These files are copied to the instance by hand. Changing the setup script would replace the
instance and its database, so they are not in `user_data`. The copies on the instance are
listed as manual changes in `docs/STATUS.md`, and the runbook is `docs/deploy-aws.md`.

All commands below run as root on the instance (`sudo -i` in a Session Manager shell).

## Units and drop-ins (archive, backup, watch)

| File in repo | Copy to the instance |
|---|---|
| `lookalike-archive.service` | `/etc/systemd/system/lookalike-archive.service` |
| `lookalike-backup.service` | `/etc/systemd/system/lookalike-backup.service` |
| `lookalike-watch.service.d/logs.conf` | `/etc/systemd/system/lookalike-watch.service.d/logs.conf` |

Then `install -d -m 0755 /var/log/lookalike-hunter`, `systemctl daemon-reload`, and restart
`lookalike-watch` if it is running (the drop-in changes where its logs go).

The services write their logs to `/var/log/lookalike-hunter/<service>.log`, not to the
journal: `journalctl -u lookalike-watch` shows only systemd's own lines. Read the file with
`tail -f /var/log/lookalike-hunter/watch.log`.

## CloudWatch agent (P1.9)

The agent config is copied to the agent's own folder, because the repository checkout on
the instance may be at an older commit that does not have this file:

```sh
dnf install -y amazon-cloudwatch-agent
# paste deploy/cloudwatch-agent.json into this file:
#   /opt/aws/amazon-cloudwatch-agent/etc/lookalike-agent.json
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/lookalike-agent.json
```

Running `fetch-config` again after editing the file reloads it. Terraform must create each
log group first (`infra/logs.tf`): the instance role cannot create log groups.

Check the agent: `amazon-cloudwatch-agent-ctl -a status` should say `running`. Its own log
is `/opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log`. Look there for
`AccessDenied`.

## Log rotation (P1.9)

Copy `logrotate-lookalike-hunter` to `/etc/logrotate.d/lookalike-hunter`.
Test it with `logrotate -d /etc/logrotate.d/lookalike-hunter` (dry run, changes nothing).

## Phishing feed (P2.1)

The timer only fetches the feed. The `watch` service captures the fresh Feed entries itself,
a few per cycle, so the instance must run a commit that has this feature
(`watch.feed_entries_path` in `configs/aws.yaml`). Order matters:

1. Update the code on the instance (see `docs/deploy-aws.md`, section 8), then restart
   `lookalike-watch`.
2. Copy `lookalike-feed.service` and `lookalike-feed.timer` to `/etc/systemd/system/`.
3. `systemctl daemon-reload`, then `systemctl enable --now lookalike-feed.timer`.
4. Add the feed entry of `cloudwatch-agent.json` to the agent config and run
   `fetch-config` again (after Terraform has created `/lookalike-hunter/feed`).

Check: `systemctl list-timers lookalike-feed.timer`, `tail /var/log/lookalike-hunter/feed.log`,
and `wc -l /var/lib/lookalike-hunter/feed-entries.jsonl`.
