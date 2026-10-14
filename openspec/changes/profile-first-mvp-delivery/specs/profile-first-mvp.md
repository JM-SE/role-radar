# Profile-first MVP specification

## Intake
### Scenario: incompatible transient job
- **WHEN** a collector returns a job with unknown or incompatible role, remote policy, region, hard constraint, or unsafe application link
- **THEN** it is counted as `profile_rejected` and no Job, source reference, run checkpoint, extraction, score, deep evaluation, feedback item, or notification item is written.

## Delivery
### Scenario: more than five eligible jobs
- **WHEN** a run has twelve eligible unseen current-run jobs
- **THEN** all twelve are reserved in ordered multipart batches with ranks local to each part and no historical job is reserved.

### Scenario: unavailable deep evaluation
- **WHEN** an eligible job has no deep evaluation
- **THEN** it is delivered using its preliminary score and empty deep detail fields.

## Review
### Scenario: historical calibration
- **WHEN** the operator requests `feedback review --scope reprocessed --limit 20`
- **THEN** only valid reprocessed product-eligible history is presented and no label changes admission or delivery policy.
