# Lookalike Hunter

Detect brand-impersonating domains (typosquatting, homoglyphs, combosquatting) from
Certificate Transparency logs as soon as their certificate is issued, then triage them
with a vision-language model. **Defensive use only.**

> Status: Day 4 of 4 — ingestion, scoring, passive capture, VLM classification, a
> measured evaluation, alerting and a review dashboard. See `CONTEXT.md` for the
> domain vocabulary (Candidate, Match, Alert, Verdict…).

```
CT logs ──► scoring ──► Alerts ──► headless capture ──► VLM ──► Verdicts ──► notify
            (names)               (screenshot + DOM)   (vision)           └─► dashboard
```

## Quick start

```bash
make install          # uv sync --all-extras (Python 3.12)
make check            # ruff + mypy --strict + pytest
make replay           # offline: score the bundled CT fixture into data/lookalike.duckdb
uv run lookalike-hunter alerts
```

### Live Certificate Transparency

The public `certstream.calidog.io` server accepted websocket connections but sent no
messages when checked (2026-09-18), so the project runs its own
[certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go) locally:

```bash
make ct-up            # docker compose up -d certstream  (ws://localhost:8080/)
make run              # lookalike-hunter ingest --source certstream
uv run lookalike-hunter alerts --limit 20
```

Expect roughly 1–2k certificates/s. On startup the server replays a backlog faster
than a single Python consumer reads it and skips some certificates for "slow clients";
this settles once the backlog is drained.

### TLS-intercepting antivirus or proxy

If your antivirus or proxy re-signs HTTPS traffic (Avast Web Shield does), the
certstream container fails with `x509: certificate signed by unknown authority`.
Either disable HTTPS scanning, or export the interceptor's root CA as PEM into
`docker/local-ca/` and add a (gitignored) `docker-compose.override.yml`:

```yaml
services:
  certstream:
    environment:
      SSL_CERT_DIR: /etc/ssl/certs:/local-ca
    volumes:
      - ./docker/local-ca:/local-ca:ro
```

### Capture and classify

```bash
# Visit pending alerts from the hardened container and store screenshots.
docker compose run --rm capture capture --limit 10

# Turn captures into verdicts (stub backend needs no API key).
uv run lookalike-hunter classify
uv run lookalike-hunter verdicts --label phishing
```

`capture` is the one command that runs attacker code, so it refuses to start
outside the capture container. `--outside-container` overrides that; it puts a
browser exploit, if a page carries one, on your own machine.

To use a real vision model, put your key in `.env` (never in the YAML):

```bash
echo "MISTRAL_API_KEY=..." > .env
uv run lookalike-hunter models          # what this key can actually call
```

then set `classify.backend: mistral` in `configs/default.yaml`. One key gives access
to every model on the account, so the model is chosen by name per request.

Not every listed model is usable: on the free tier the `ministral-*` family answers
normally (3b: 750 req/min, 8b: 188, 14b: 30) while `mistral-small`/`mistral-medium`
return 429 with `x-ratelimit-limit-req-minute: 0` until pay-as-you-go is enabled.
The default is `ministral-8b-latest`: its accuracy is indistinguishable from the
14b on this dataset, and it is faster with a far higher rate limit (see Models
under Measured results).

The `stub` backend classifies from DOM signals alone, needs no key, and is the
baseline the VLM is compared against on Day 3.

### Alerting

```bash
uv run lookalike-hunter alert           # announce new phishing verdicts, once each
```

Only `phishing` verdicts at or above `alert.min_confidence` are announced, and each
one once: `alerted_at` is set only after a sink accepted it, so a delivery failure
is retried on the next run. Findings are appended to `data/alerts.jsonl`. To also
post to Slack, Discord or Teams, put the webhook URL in `.env`. The URL is a
credential (whoever holds it can post to the channel), so it is never put in the
YAML and never written to a log or error message:

```bash
echo "LH_ALERT__WEBHOOK_URL=https://hooks.slack.com/services/..." >> .env
```

The message is built so the chat client acts on none of it: URLs and hostnames
are defanged (`hxxps://evil[.]com`), and the `<`, `>` and `@` that Slack and
Discord read as mentions and links are neutralised, because the evidence
sentence repeats text from the hostile page.

### Dashboard

```bash
make dashboard          # http://localhost:8501
```

A review queue: each finding with its label, the model's evidence, the defanged
final URL and the screenshot taken in the container. It opens the database
read-only, so it can stay open while ingestion writes. `.streamlit/config.toml`
binds it to `127.0.0.1` (it has no login and shows live phishing findings) and
turns off Streamlit's usage telemetry. Streamlit is an optional extra
(`uv sync --extra dashboard`), so the capture image does not carry it.

## Visiting hostile sites safely

The browser is the only component that runs attacker-controlled content, so it is
treated as expendable:

| Layer | Measure |
|---|---|
| Container | Separate image, non-root `pwuser`, all capabilities dropped, `no-new-privileges`, read-only root filesystem + tmpfs, 2 GB memory and 512 PID caps, only `./data` mounted |
| Browser | Chromium sandbox **enabled** (Playwright disables it by default), fresh context per site, 15 s timeout, downloads refused, dialogs auto-dismissed |
| Behaviour | Never fills a form, never submits credentials, never follows links: load, screenshot, read the DOM, leave |
| Network | Non-`http(s)` schemes refused; every request's host is resolved and blocked if it is loopback, private, link-local or cloud metadata, so a redirect cannot make our browser probe your LAN. WebSockets go through the same check (Playwright's request filter does not see them), and WebRTC's direct UDP is disabled, since a STUN server at a private address would otherwise reach the LAN; both bypasses were reproduced before being closed and are regression-tested |
| Launch | `capture` refuses to run outside the container unless told `--outside-container` |

What the browser leaves behind is treated as hostile too, because the host reads it:

| Output | Measure |
|---|---|
| Page source | Saved as `.html.txt`, so a double-click opens a text editor rather than running the kit from `file://` |
| Stored paths | The database is written from inside the container. A screenshot path is resolved, symlinks included, and refused unless it lands under the capture directory, so a tampered row cannot make the host upload `~/.ssh/id_rsa` to the model API or show it in the dashboard |
| Terminal | Control characters stripped from everything printed |
| Notifications | Defanged and stripped of chat markup (see Alerting) |
| Dashboard | Hostile text rendered as plain text: Markdown would turn `[x](url)` into a link and `![](url)` into a request to the attacker's server. Bound to localhost |
| Reports | Model and page text wrapped in Markdown code spans that cannot be closed |

Docker's default seccomp profile blocks the user namespaces Chromium's sandbox
needs, so the compose service sets `seccomp=unconfined`: it is one filter or the
other. The renderer executes the attacker's content and Chromium confines it with
a stricter, purpose-built filter, so the browser sandbox wins. Vendoring a Chrome
seccomp profile would give both and is the right follow-up.

**What this does not hide:** the site owner sees your IP address and knows someone
looked. Use a VPN if that matters.

## How scoring works

Every hostname in every certificate is a *Candidate*. It is scored against each brand
in `configs/default.yaml`:

| Signal | Weight | Example |
|---|---|---|
| Known dnstwist Variant of an official domain | 1.0 | `paypa.com` |
| Typo of a token (Damerau-Levenshtein ≥ 0.8, tokens ≥ 6 chars) | 0.9 × sim | `paypall-secure.com` |
| Token in registered label (after homoglyph skeleton) | 0.6 | `paypal-shop.com`, `pаypal.com` |
| Token in subdomain | 0.5 | `paypal.com.verify.top` |
| + homoglyph used / sensitive keyword (×2 max) / free DV issuer | +0.1 / +0.1 / +0.05 | |

The strongest base signal wins and bonuses are added. Keywords alone never produce a
Match. Scores ≥ `store_floor` (0.4) are stored; ≥ `alert_threshold` (0.7) are Alerts.
Every stored Match keeps its feature vector as JSON, so each score can be explained.

Any value can be overridden via env, e.g. `LH_SCORING__ALERT_THRESHOLD=0.8`.

Confusable collapsing comes in two levels. Rules that *create* letters (`i`/`l`,
`rn` -> `m`) only apply to whole words, because searching them as substrings makes
any word ending in `l` followed by `cloud` read as `icloud`. Unambiguous confusables
(Cyrillic `а`, `1` -> `l`) are safe anywhere in a name.

## Measured results

Evaluated on 78 labelled sites (64 judgeable; 14 excluded as unknown, being
Cloudflare challenges or empty frames). Dataset and labels are in
`datasets/eval.jsonl`; regenerate with `lookalike-hunter evaluate`.

| | Scoring only | Scoring + VLM |
|---|---|---|
| Sites judged | 64 | 39 (25 excluded, no usable capture) |
| Accuracy | 9.4% | **61.5%** |
| Macro F1 | 0.081 | **0.326** |
| `parked` precision | 0.00 | **0.90** |
| `parked` recall | 0.00 | 0.69 |
| `legitimate` precision | 0.10 | 0.60 |

**What this says.** The name-based filter alone is close to useless for triage: 58
of its 64 judgements are wrong, and almost everything it alerts on turns out to be
a parking page. It *cannot* do better by construction, because a parked lookalike
and a live phishing page have identical names. Looking at the screenshot is what
separates them, and it does so with 90% precision on the parked class. That is the
entire argument for the vision step, and it is the number that supports it.

**What this does not say.** Phishing recall for the VLM arm is unmeasured: every
phishing site in the dataset was taken down before it could be captured, so that
arm has zero phishing support. The comparison above is about suppressing false
alarms, not about catching attacks.

### By population

The aggregate above mixes two different populations, which flatters neither arm.
Split by where each site came from:

| Source | Sites | Scoring only | Scoring + VLM |
|---|---:|---:|---:|
| Certificate Transparency alerts | 30 | **0.0%** | **63.3%** |
| Seeded hard negatives | 7 | 14.3% | 42.9% |
| Phishing feed | 27 (2 reachable) | 18.5% | 100% |

The first row is the one that matters, because it is what this pipeline actually
produces. Of the 30 sites it alerted on, **not one was phishing**: they were
parking pages, brand-owned infrastructure and unrelated businesses. Name-based
scoring is therefore 0% accurate on its own output, and looking at the page
recovers 63%.

The feed row is the structural blind spot. Certificate Transparency publishes
certificates, and a phishing page on `github.io`, `pages.dev` or an S3 bucket
never gets one of its own: it is covered by the platform's wildcard. Those sites
cannot appear in this pipeline's input at all, so no threshold, scoring rule or
model reaches them. Catching them would need a second ingestion source, which is
a different tool rather than a tuning change.

### Models

Same sites, same captures, same labels; only the model changes.

| Model | Judged | Accuracy | Macro F1 | ms/site | Tokens |
|---|---:|---:|---:|---:|---:|
| `ministral-3b-latest` | 39 | 46.2% | 0.270 | 1035 | 73002 |
| `ministral-8b-latest` | 39 | **61.5%** | **0.326** | 1386 | 72576 |
| `ministral-14b-latest` | 39 | 56.4% | 0.324 | 2418 | 11375 |

**The accuracy differences here are not significant.** 8b and 14b disagree on 6
of 39 sites, 4 in 8b's favour and 2 in 14b's: a net difference of 2 sites, which
a coin flip reproduces most of the time. Read as "no measurable accuracy
difference", not as "8b is better".

The latency difference is real and consistent (1386 vs 2418 ms/site), as is the
rate limit (188 vs 30 requests/minute). The default is `ministral-8b-latest` on
those grounds: with accuracy tied, throughput decides, and throughput is a
security property here too, since a slower classifier means longer before an
analyst sees the alert and phishing kits live hours.

Settling the accuracy question needs a larger dataset; on 39 sites it cannot be
settled. Cost is $0 on the free tier; prices are configurable so a paid run
reports a real figure instead of implying one.

### The alert threshold

The configured 0.7 was chosen by eye on one sample. Measured, it is not the best
value on this dataset:

| Threshold | Alerts | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|
| 0.40 | 40 | 0.175 | 0.280 | **0.215** |
| 0.70 (configured) | 35 | 0.086 | 0.120 | 0.100 |
| 0.80 | 25 | 0.000 | 0.000 | 0.000 |

Every value is poor, because this dataset is deliberately hostile: most phishing in
it is hosted on `github.io`, `pages.dev` or S3, where the hostname carries no brand
lookalike at all and no threshold can help. The honest conclusion is that the
threshold is the wrong knob for that failure, not that 0.4 is a good setting.

## Honesty about the benchmark

- **The labels were assigned by the same agent that wrote the system.** That is
  recorded per entry (`labelled_by`, `label_basis`) rather than left implicit. A
  benchmark whose ground truth comes from the author of the system under test
  deserves the caveat in the open; `docs/labelling-protocol.md` states the rules
  used, so the labels can be audited or redone.
- **Two labels changed once the final URL was read.** `isupport-appie-mxn.com`
  renders a pixel-perfect iCloud sign-in page and redirects to Apple's real site;
  `imprentamorales.maicrosoft.eu` shows a password form on a Microsoft typosquat and
  is a Spanish printer's own ERP. Both are legitimate; both look like phishing in a
  screenshot.
- **The dataset is small and hostile**, drawn from what this pipeline actually meets
  plus seeded hard negatives. It is not a general phishing benchmark.
- **Feed-sourced phishing labels rest on the feed listing**, not on a screenshot,
  because the sites were gone before capture. `label_basis` marks those entries.

## Known limitations

Names alone cannot settle every case, which the measurement confirms:

- Legitimate domains that are genuine dnstwist variants, e.g. `livee.com` (a variant
  of Microsoft's `live.com`) or `hicloud.net`, score as known Variants.
- Surnames and words that collide with short brand tokens, e.g. `amell.family`.
- Brand-owned infrastructure that looks like combosquatting, e.g.
  `microsoft-falcon.net` and `webshell.dodsuite.office365.us`, which is Microsoft's
  own US-government cloud.
- **Phishing hosted on a legitimate platform is invisible to name-based scoring.**
  Most live phishing in the evaluation sat on `github.io`, `pages.dev` or S3, whose
  hostnames contain no lookalike and which are partly on the brands' own allowlists.
  No threshold reaches them; a different signal would be needed.
- **Phishing sites disappear fast.** Of 34 feed-sourced sites, 25 were already taken
  down when captured, which is why the vision arm has no phishing support.
- **A stored Match keeps its first score.** After the scoring weights change, rows
  written earlier are not rescored, so `alerts` can show figures the current
  configuration would not produce. The evaluation is unaffected: it rescores from
  the hostname rather than reading those rows.

Operationally: about 2% of certificates are skipped when the local CT server outruns
the consumer. Ctrl+C and SIGTERM (as sent by `docker stop`) both flush buffered
Matches before exiting.

Security caveats that hardening does not remove:

- **DNS rebinding** can still defeat the private-address check, since Chromium
  resolves each host again after we do. Closing it properly needs an egress proxy
  that resolves once, checks the address and connects to that same address.
- **The capture container has `./data` mounted read-write**, including the DuckDB
  file the host opens. The host no longer trusts the file paths in it, but someone
  who escaped both Chromium's sandbox and the browser process could still write
  false rows or a deliberately malformed database file. Splitting the mounts, so
  the container writes captures and a results file the host imports, would remove
  that.
- **Captures are never pruned**, so disk use grows without bound.
- **A page's own text reaches the classifier prompt.** It is fenced and labelled
  as untrusted data, but cannot be made injection-proof: a page can still talk the
  model into a wrong label.
- **Captures from before 2026-10-02 are saved as `.html`.** Open those only in a
  text editor.
