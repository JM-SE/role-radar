# Design

Broad collector responses remain transient. `ProfileIntakeDecision` is evaluated before deduplication and persistence using source-scoped evidence only. Accepted rows carry the canonical safe application URL and intake proof in the dedup checkpoint.

Extracted facts are evaluated by `ProductEligibilityDecision`. A valid current-run decision and score are necessary for delivery. Historical jobs receive purpose-tagged reprocessing checkpoints and are review-only.

Delivery selection orders all valid jobs deterministically, optionally enriching from a valid deep evaluation. Formatter batches greedily at five items and Telegram UTF-16 limits. All parts reserve in one transaction; recipient/job uniqueness preserves at-most-once delivery across runs.
