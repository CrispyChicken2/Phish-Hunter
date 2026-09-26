# Labelling protocol

Ground truth for the evaluation dataset. Follow it literally: the point is that a
second person, applying these rules to the same screenshots, would produce the same
labels. A benchmark whose labels depend on who assigned them measures nothing.

## The rule that matters most

**Label what the page shows, not what the domain name suggests, and not what a feed
says.** A domain called `paypal-secure-login.com` serving a registrar parking page is
`parked`. A feed listing a site as phishing is evidence that it *was* phishing when
the feed saw it, not that it is phishing in the screenshot in front of you.

Feed membership is recorded in `source` as provenance. If we adopted the feed's
verdict, the evaluation would measure agreement with the feed rather than accuracy,
and the phishing class would be circular.

## Labels

| Label | Assign when the screenshot shows | Typical give-aways |
|---|---|---|
| `phishing` | A page imitating a brand to obtain credentials, payment or identity data | Brand logo or styling on a domain the brand does not own; a login or payment form; "verify your account" urgency |
| `parked` | No real content | Registrar placeholder, "this domain is for sale", ads-only page, default web-server page (nginx/Apache/IIS), blank page, or an HTTP error page such as 403 or 404 |
| `legitimate` | A real site that is not impersonating the brand | An unrelated business whose name merely resembles the brand; the brand's own site; infrastructure belonging to the brand |
| `unreachable` | The capture failed: DNS error, connection refused, timeout | Assign from the capture status, not from a screenshot |
| `unknown` | The page renders but genuinely cannot be judged | Non-Latin text you cannot read, a CAPTCHA or interstitial, a blank frame with no other signal |

## Procedure

1. Open the capture's screenshot. If there is no screenshot because the capture
   failed, the label is `unreachable`.
2. Ask: is anything on this page trying to make me believe it belongs to a brand?
   If yes and it solicits data, it is `phishing`.
3. If the page has no substantive content, it is `parked`. An error page counts as
   parked: there is nothing there.
4. Otherwise it is `legitimate`.
5. Use `unknown` only when 2 to 4 genuinely cannot be decided. If you find yourself
   reaching for it often, the protocol needs fixing, not the label.
6. Set `expected` on the line and leave `suggestion`, `source` and `note` untouched:
   they record where the candidate came from and why it was interesting.

## Edge cases, decided in advance

- **Brand infrastructure** (`microsoft-falcon.net`): `legitimate`. It belongs to the
  brand, even though the name looks like combosquatting.
- **A different company that happens to collide** (`hicloud.net`, Huawei):
  `legitimate`. Resembling a brand is not impersonating it.
- **A parked domain that is obviously intended for phishing later**: `parked`. We
  label what is there now; predicting intent is not measurable.
- **A login form for something else entirely** (a webmail with no brand imitation):
  `legitimate`. A login form alone is not phishing.
- **A redirect to the brand's real site**: `legitimate`, and note the redirect.
- **A page that renders after a long delay**, captured mid-load: re-capture before
  labelling; do not guess from a blank frame.

## Honesty rules

- Label before looking at what the system predicted. Seeing the prediction first
  makes agreement feel like correctness.
- When a label is a genuine coin-flip, write why in `note`. Those entries are the
  most informative ones in the error analysis.
- Never change a label to make a metric look better. If a label was wrong, fix it and
  say so in the commit message.

## Phishing hosted on a legitimate platform

The feed contains entries such as `something.github.io`, `x.pages.dev` and
`s3.<region>.amazonaws.com`. These are real phishing pages served from platforms
that belong to someone else, and they are deliberately kept in the dataset.

Label the page, as always: if the screenshot shows a credential-stealing imitation,
it is `phishing`, even though the hostname is legitimately GitHub's or Amazon's.

Our Scorer cannot flag these: the hostname contains no brand lookalike, and in the
AWS case the domain is on the brand's own allowlist. They will therefore count as
misses, which is correct. Removing them would hide a real limitation of name-based
detection rather than measure it.
