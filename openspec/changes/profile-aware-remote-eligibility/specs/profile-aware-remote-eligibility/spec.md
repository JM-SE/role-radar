# Profile-Aware Remote Eligibility Specification

## Purpose

Ensure only jobs with known, profile-compatible remote and region facts reach feedback, without narrowing acquisition or removing human control.

## Requirements

### Requirement: Post-extraction eligibility boundary

The system MUST evaluate profile-aware remote eligibility after extraction and before a job becomes a feedback candidate. Feedback ordering, summaries, and rendering MUST operate only on eligible jobs.

#### Scenario: Newly extracted eligible job reaches feedback

- GIVEN a newly acquired job has completed extraction
- AND its extracted facts satisfy the active profile's eligibility rules
- WHEN feedback candidates are selected
- THEN the job MUST be eligible for feedback consideration

#### Scenario: Eligibility is not decided before extraction

- GIVEN an acquired job has not completed extraction
- WHEN feedback candidates are selected
- THEN the job MUST NOT be treated as eligible

### Requirement: Evidence completeness and conflict handling

A job MUST have a known remote policy and either a known canonical region or an explicit worldwide designation to be eligible. The system MUST exclude a job from feedback when its remote policy is unknown, its region is unknown without an explicit worldwide designation, or relevant extraction evidence is conflicting or ambiguous.

#### Scenario: Unknown remote policy is excluded

- GIVEN a job has no known remote policy
- WHEN eligibility is evaluated
- THEN the job MUST be excluded from feedback

#### Scenario: Unknown region is excluded

- GIVEN a job has a known remote policy
- AND its region is unknown
- AND it is not explicitly worldwide
- WHEN eligibility is evaluated
- THEN the job MUST be excluded from feedback

#### Scenario: Conflicting evidence is excluded

- GIVEN a job has conflicting or ambiguous evidence for its remote policy, region, or worldwide designation
- WHEN eligibility is evaluated
- THEN the job MUST be excluded from feedback

### Requirement: Exact profile-region or worldwide eligibility

A job with complete, non-conflicting facts MUST be eligible only when its canonical region exactly matches one of the active profile's canonical regions or the job is explicitly worldwide. The system MUST NOT infer broader, neighboring, fuzzy, or implicit geographic matches.

#### Scenario: Exact canonical region matches

- GIVEN a job has a known remote policy and canonical region
- AND that region exactly equals one of the active profile's canonical regions
- WHEN eligibility is evaluated
- THEN the job MUST be eligible

#### Scenario: Different region does not match

- GIVEN a job has a known remote policy and canonical region
- AND that region does not exactly equal any active profile region
- WHEN eligibility is evaluated
- THEN the job MUST be excluded from feedback

#### Scenario: Explicit worldwide job matches

- GIVEN a job has a known remote policy
- AND the job is explicitly designated worldwide
- WHEN eligibility is evaluated for a profile with at least one region
- THEN the job MUST be eligible regardless of which profile region is active

### Requirement: Broad acquisition remains unchanged

The system MUST NOT use profile-aware remote eligibility to filter collectors, source queries, acquisition inputs, parent pools, or acquisition quotas. An ineligible job MUST remain in the acquired corpus and MAY become eligible after later extraction or profile changes.

#### Scenario: Ineligible job remains acquired

- GIVEN a job has been acquired broadly
- AND the job is excluded from feedback by profile-aware eligibility
- WHEN acquisition records are inspected
- THEN the job and its immutable acquisition observations MUST remain present

#### Scenario: Acquisition does not apply feedback eligibility

- GIVEN an active profile has restrictive region values
- WHEN an acquisition cycle collects its parent pool
- THEN profile-aware feedback eligibility MUST NOT narrow that parent pool

### Requirement: Existing jobs are reprocessed before reacquisition

The system MUST reprocess the current job corpus with the same eligibility rules used for newly extracted jobs before starting the next acquisition cycle. Reacquisition MUST remain blocked until that reprocessing is complete for the applicable active profile and policy identity.

#### Scenario: Current corpus is processed first

- GIVEN current jobs have not all been evaluated under the applicable profile and policy identity
- WHEN reacquisition is requested
- THEN reacquisition MUST NOT start
- AND the remaining current jobs MUST be eligible for reprocessing

#### Scenario: Reacquisition resumes after completion

- GIVEN every current job has reached a terminal eligibility outcome under the applicable profile and policy identity
- WHEN reprocessing completion is confirmed
- THEN the next acquisition cycle MAY start under its existing gates

#### Scenario: Current and new jobs use one rule

- GIVEN one current job is reprocessed and one newly acquired job completes extraction with equivalent facts
- WHEN eligibility is evaluated against the same active profile and policy identity
- THEN both jobs MUST receive the same eligibility outcome

### Requirement: Reprocessing is restart-safe and observable

Reprocessing MUST preserve completed outcomes across interruption, MUST safely resume remaining work without treating partial completion as complete, and MUST expose progress sufficient to distinguish pending, completed, eligible, and excluded jobs. Exclusions MUST expose a reason, including unknown or conflicting facts when applicable.

#### Scenario: Interrupted reprocessing resumes safely

- GIVEN reprocessing stops after some current jobs reach terminal outcomes
- WHEN reprocessing restarts with the same applicable profile and policy identity
- THEN completed outcomes MUST remain accounted for
- AND processing MUST continue for jobs that lack a terminal outcome
- AND reacquisition MUST remain blocked until no required jobs are pending

#### Scenario: Progress and exclusions are observable

- GIVEN reprocessing is running or complete
- WHEN its status is inspected
- THEN the status MUST report pending and completed progress
- AND completed progress MUST distinguish eligible and excluded outcomes
- AND each excluded outcome MUST provide an eligibility reason

### Requirement: Feedback remains human-controlled

Eligibility MUST only determine whether a job may be presented for feedback. The system MUST preserve existing human-controlled feedback decisions, refinement, consent, authorization, gate, profile/version/hash, journal, and budget boundaries, and MUST NOT automatically mutate a profile from an eligibility outcome.

#### Scenario: Eligible job still awaits human feedback

- GIVEN a job is eligible and appears in feedback
- WHEN no human feedback decision has been made
- THEN the system MUST NOT infer or submit a human decision

#### Scenario: Eligibility does not mutate the profile

- GIVEN a job is included in or excluded from feedback
- WHEN its eligibility outcome is recorded
- THEN the active profile MUST NOT be automatically changed

#### Scenario: Existing controls remain enforced

- GIVEN an eligible job reaches a workflow protected by an existing consent, authorization, gate, hash, journal, or budget check
- WHEN that workflow is attempted
- THEN the existing check MUST still be enforced

## Acceptance Criteria

- Every feedback candidate has completed extraction and passed eligibility for the applicable active profile and policy identity.
- Unknown, ambiguous, or conflicting remote and region facts fail closed.
- Eligibility accepts only exact canonical profile-region matches or explicit worldwide jobs.
- Current jobs complete restart-safe, observable reprocessing before reacquisition resumes.
- Acquisition coverage and all existing human-control and safety boundaries remain unchanged.
