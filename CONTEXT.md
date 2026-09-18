# Lookalike Hunter — Domain Glossary

**Brand**
An organisation we protect. Defined by its tokens (e.g. `paypal`), its official domains (never flagged), and optional negative tokens that neutralise innocent collisions (e.g. `pineapple` for `apple`).

**Certificate**
A leaf certificate observed in a Certificate Transparency log. One Certificate names many hostnames (SANs).

**Candidate**
One hostname taken from one Certificate, wildcard prefix stripped. The unit of analysis: everything downstream (scoring, capture, classification) is per Candidate.

**Registered domain**
The part of a Candidate a registrant actually buys (eTLD+1, e.g. `evil.co.uk`). Brand ownership is decided at this level.

**Skeleton**
The Candidate rewritten so visually confusable characters collapse to one canonical ASCII form (`раураl` → `paypal`, `paypa1` → `paypal`). Comparisons against a Brand happen on the Skeleton.

**Variant**
A lookalike registered domain generated in advance from a Brand's official domain (typo, homoglyph, bitsquat, TLD swap…). Being a known Variant is one signal, not the verdict.

**Combosquat**
A Candidate that contains a Brand token plus other words (`paypal-secure-login.com`). Cannot be enumerated as Variants; only detectable by scoring.

**Match**
A (Candidate, Brand) pair whose score is above the storage floor, persisted with the features that explain the score.

**Alert**
A Match whose score is above the alert threshold. Only Alerts are sent to capture and classification.

**Verdict** *(Day 2)*
The classification of an Alert's live site: `phishing`, `parked`, `legitimate` or `unreachable`.
