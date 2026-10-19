# Feed-derived data: where it lives and why

This document covers the OpenPhish community feed (`https://openphish.com/feed.txt`) and any
other feed whose terms restrict redistribution.

**This is an engineering safeguard, not a legal opinion.** It keeps feed-derived data out
of the public repository, so the repository does not redistribute it. Whether the owner's
use of the feed is permitted is a question for the owner and the feed's terms.

## What the terms say

From the OpenPhish [Terms of Use](https://openphish.com/terms.html), read on 2026-10-19:

- "The Services are provided solely for your personal use." Research use is allowed, but
  the Services may not support business operations.
- Commercial use is prohibited without prior written consent.
- Redistribution: "Except as expressly permitted by OpenPhish in writing, you agree not
  to license, sell, rent, lease, transfer, assign, distribute." The terms also bar making
  obtained information available "to any third party".

The terms do not state a refresh interval. OpenPhish's
[phishing feeds page](https://openphish.com/phishing_feeds.html) gives the community feed's
update frequency as 12 hours.

## Where the data lives

| Data | Location | In git? |
|---|---|---|
| Labelled sites from our own alerts and calibration | `datasets/eval.jsonl` | yes |
| Labelled sites from the OpenPhish feed | `datasets/feed/` | **no** (ignored by `.gitignore`) |
| Feed candidates fetched by the timer (P2.1) | `/var/lib/lookalike-hunter/feed-candidates.jsonl` on the instance | **no** (not in the repository) |
| Captures of feed sites | the capture folder on the instance, then the private S3 bucket | **no** (the bucket is private) |

**How the timer works (P2.1).** `deploy/lookalike-feed.timer` runs every 6 hours. It
fetches the feed, keeps entries that mention a configured brand (a plain substring search,
with no Scorer), and appends them to the candidates file. Then it captures up to 20
candidates that have no screenshot yet. The candidates file is unlabelled, so the
evaluation refuses to read it. A person must label a site before it can enter
`datasets/feed/`. The command refuses any output path under `datasets/`, so the tracked
folder cannot receive feed candidates by mistake.

The evaluation reads `datasets/eval.jsonl` and every file in `datasets/feed/`, once per
site (`eval/dataset.py`, `load_all_datasets`).

## What the repository publishes

- Aggregate figures only: counts, rates and intervals, as the evaluation reports them.
- No feed URL and no feed-derived hostname in tracked files.

## Known gap: git history

On 2026-10-19 the history was rewritten (with the owner's approval) to remove the 27
feed-derived lines from every commit. The commit count is unchanged (144), but 98
commits have new hashes; the instance and Terraform references are listed in
`docs/STATUS.md`. The remote has no other branch.

Copies that existed before the rewrite are outside the repository's control: other clones,
any copy in a backup, and GitHub's cached pages until they expire. The backup bundle made
for the rewrite, in the Windows temp folder, also contains the lines; delete it once the
rewrite is verified.

## Effect on reproducing the results

Without the local feed file, the repository holds 51 labelled sites instead of 78, so
`lookalike-hunter evaluate` run from a clean checkout gives different numbers from the
README. Running it with the local `datasets/feed/` file gives the same numbers.

## Open decisions for the owner

1. Ask OpenPhish in writing for permission to publish feed-derived data (optional; this
   would allow restoring the lines to the repository).
2. Delete the backup bundle in the Windows temp folder (`lookalike-backup-before-rewrite.bundle`).
3. Decide whether the S3 bucket may keep captures of feed sites (the bucket is private).
