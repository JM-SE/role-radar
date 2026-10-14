# Profile-first MVP delivery

## Why
Product persistence and delivery currently admit broad results, gate notification on deep `apply` outputs, and limit a run to one five-item message. This contradicts the profile-first MVP.

## Change
- Admit only source rows with sufficient compatible role, remote, region, hard-constraint, and safe-link evidence before persistence.
- Replace feedback eligibility with `product-eligibility-v1` for extracted jobs and historical review.
- Deliver every eligible unseen current-run job using multipart Telegram; deep evaluation enriches but never gates delivery.
- Expose historical product-eligible jobs only through scoped review.

The prior `profile-aware-remote-eligibility` change is superseded by this proposal; its completed implementation and TDD evidence remain unchanged.
