# Review offers with an unconfirmed location

Use `GET /jobs/location-unconfirmed` to review role-compatible offers whose only unresolved intake reason is unknown geography. These observations stay separate from canonical jobs: they have no score, are not eligible matches, and are not selected for Telegram notifications.

## Quick path

1. Request the review list for the active profile, or pass an explicit `profile_id` when more than one profile is active.
2. Open the `application_url` and assess the posting yourself; the endpoint does not approve or promote an offer.
3. A later normal acquisition refreshes an observation, removes it when the offer no longer qualifies, or stores it as a canonical job once geography is confirmed.

```bash
curl -sS "http://127.0.0.1:8000/jobs/location-unconfirmed?profile_id=<PROFILE_ID>&limit=50"
```

## Response

The endpoint returns a paginated JSON array. Each item contains:

| Field | Meaning |
|---|---|
| `id` | Stable review-observation identifier |
| `title`, `company`, `location` | Posting details; location may be null or inconclusive |
| `source_id`, `external_id` | Source identity for the observed posting |
| `source_url`, `application_url` | Canonicalized source and application links |
| `reason_code` | Always `region_unknown` |
| `first_seen_at`, `last_seen_at` | First and latest normal-acquisition observations |

`limit` defaults to 50 and accepts 1–200; `offset` defaults to 0. If `profile_id` is omitted, the API uses the sole active profile. A missing profile returns 404; an ambiguous or invalid profile selection returns 409.

## Review-only boundary

- An observation is recorded only when the profile intake result has exactly the `region_unknown` reason and a valid application URL. Other rejections, invalid links, and known incompatibilities remain excluded.
- Review observations are stored separately from jobs and scores. The response has no `eligible` or score field, and these rows do not enter the ordinary jobs list or notification selection.
- Results are filtered by the current profile ID, version, schema version, and canonical hash. A changed profile does not display observations bound to an older version.
- A later normal observation refreshes a still-uncertain posting or removes it when it becomes eligible, invalid, or otherwise no longer qualifies.
- Canary runs do not create, update, or remove review observations.
