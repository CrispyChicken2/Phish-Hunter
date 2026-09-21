# Lookalike Hunter

Detect brand-impersonating domains (typosquatting, homoglyphs, combosquatting) from
Certificate Transparency logs as soon as their certificate is issued, then triage them
with a vision-language model. **Defensive use only.**

> Status: Day 2 of 4 — ingestion, scoring, passive capture and VLM classification.
> Evaluation and the dashboard follow. See `CONTEXT.md` for the domain vocabulary
> (Candidate, Match, Alert, Verdict…).

```
CT logs ──► scoring ──► Alerts ──► headless capture ──► VLM ──► Verdicts
            (names)               (screenshot + DOM)   (vision)
```

## Quick start

```bash
make install          # uv sync (Python 3.12)
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

To use a real vision model, put your key in `.env` (never in the YAML):

```bash
echo "MISTRAL_API_KEY=..." > .env
uv run lookalike-hunter models          # what this key can actually call
```

then set `classify.backend: mistral` and `classify.model` in `configs/default.yaml`.
One key gives access to every model on the account, so the model is chosen by name
per request. The `stub` backend classifies from DOM signals alone and is the
baseline the VLM is compared against on Day 3.

## Visiting hostile sites safely

The browser is the only component that runs attacker-controlled content, so it is
treated as expendable:

| Layer | Measure |
|---|---|
| Container | Separate image, non-root `pwuser`, all capabilities dropped, `no-new-privileges`, read-only root filesystem + tmpfs, 2 GB memory and 512 PID caps, only `./data` mounted |
| Browser | Chromium sandbox **enabled** (Playwright disables it by default), fresh context per site, 15 s timeout, downloads refused, dialogs auto-dismissed |
| Behaviour | Never fills a form, never submits credentials, never follows links: load, screenshot, read the DOM, leave |
| Network | Non-`http(s)` schemes refused; every request's host is resolved and blocked if it is loopback, private, link-local or cloud metadata, so a redirect cannot make our browser probe your LAN |

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

## Known limitations

Names alone cannot settle every case; these are what the Day 2 vision model is for:

- Legitimate domains that are genuine dnstwist variants, e.g. `livee.com` (a variant
  of Microsoft's `live.com`) or `hicloud.net` (Huawei), score as known Variants.
- Surnames and words that collide with short brand tokens, e.g. `amell.family`.
- Brand-owned infrastructure that looks like combosquatting, e.g. `microsoft-falcon.net`.

Operationally: about 2% of certificates are skipped when the local CT server outruns
the consumer, and SIGTERM (as sent by `docker stop`) is not yet handled gracefully, so
up to one flush interval of Matches can be lost. Ctrl+C is handled.
