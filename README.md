# Lookalike Hunter

Detect brand-impersonating domains (typosquatting, homoglyphs, combosquatting) from
Certificate Transparency logs as soon as their certificate is issued, then triage them
with a vision-language model. **Defensive use only.**

> Status: Day 1 of 4 — ingestion, variant generation and scoring. Capture, VLM
> classification, evaluation and the dashboard follow. See `CONTEXT.md` for the
> domain vocabulary (Candidate, Match, Alert, Variant…).

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
