# Explore: profile-aware-remote-eligibility

## Phase result

- **Status:** complete
- **Phase:** explore
- **Change:** `profile-aware-remote-eligibility`
- **Skill resolution:** `fallback-path` (`/home/jmse/.pi/agent/agents/sdd-explore.md` was explicitly supplied by the user; no project/user skill paths were injected)
- **Artifact store:** openspec
- **Tests:** not run; the configured full `make test` suite was intentionally not executed
- **Product code:** unchanged

## Current architecture

The product has two related but separate flows:

1. The operational pipeline collects and persists jobs, extracts structured facts, builds matching facts, applies hard blockers, scores, and exposes feedback.
2. The profile-relevant acquisition/evaluation flow performs profile-bound discovery, gated broad acquisition, immutable fact projection, relevance decisions, sampling, and materialization. It is intentionally fail-closed and keeps acquisition broad rather than filtering the parent pool by relevance.

The profile is persisted as `CandidateProfile` JSON and normalized/validated into frozen `CandidateProfileV1`. Profile identity is bound through canonical JSON SHA-256 and, in discovery/evaluation paths, through a selected-row binding containing profile id, row version, schema version, and canonical profile hash.

## Findings by requested area

### Profile location and remote constraints

- `src/role_radar/domain/profile.py` defines `CandidateProfileV1.regions` and `remote_only`, plus `ProfileHardConstraints.allowed_remote_policies`; remote preferences also exist as soft preferences.
- Profile normalization canonicalizes regions and remote policy aliases. Empty hard-constraint lists mean no hard restriction.
- Legacy profile adaptation in `src/role_radar/matching/profile_adapter.py` is deliberately conservative: a legacy remote preference does not enable `remote_only` and emits an ambiguity.
- `src/role_radar/db/models.py`, `src/role_radar/repositories/profiles.py`, and `src/role_radar/api/profiles.py` are the persistence/API seams; matching resolves an explicit profile id or requires exactly one active profile.
- Existing fixtures and tests commonly use `regions: ["spain"|"europe"]` and `remote_only: true`; the profile contract has no richer location model than canonical region strings plus remote policy vocabulary.

### Discovery and acquisition

- `src/role_radar/discovery/profile_terms.py` compiles only policy-mapped target roles/titles into bounded approved phrases, preserving profile binding and phrase provenance.
- `src/role_radar/discovery/planner_v2.py` turns those phrases into exactly four bounded, host-owned Greenhouse/Lever queries. The plan hash includes profile binding, policy, source registry, queries, and all limits.
- `src/role_radar/evaluation/profile_aware_discovery.py` only verifies/consumes an existing immutable discovery plan; it does not build queries or register product data.
- The normal continuous acquisition path (`src/role_radar/continuous_acquisition/acquisition.py`) runs source snapshots and collectors under request/deadline budgets, freshness policy, identity handling, and conservation counters. It does not consult a profile before collecting.
- The profile-relevant Gate C/D path (`gate_c_service.py`, `acquisition_runtime.py`) binds authorization, profile/policy/query-plan hashes, source plans, journaled transport, budgets, checkpoints, and sealed parent-pool artifacts. Gate D explicitly collects broad observations without relevance filtering, backfill, quota extra, or source replacement.
- Collectors preserve provider location values into `RawJob`/`ObservationEnvelope`: Greenhouse maps location objects to names, Lever uses primary/all locations, and Jobicy requires `jobGeo`. These are strings, not normalized profile-aware eligibility decisions.

### Extraction

- `src/role_radar/extraction/schemas.py` extracts `remote_policy` and `regions` as evidence-bearing fields, alongside employment, authorization, skills, and experience.
- `src/role_radar/extraction/validator.py` requires evidence for specified values and verifies evidence substrings against the job description; invalid/stale extractions are not used as authoritative facts.
- `src/role_radar/services/extraction_service.py` is a durable two-attempt provider/corrective workflow keyed by description hash, schema version, and prompt version.
- `src/role_radar/matching/facts.py` gives ATS source references precedence over valid current extraction values. Location-derived regions are only a fallback and exclude literal `remote`, `worldwide`, and `global` tokens. Conflicts become explicit ambiguities.

### Matching and eligibility

- `src/role_radar/matching/hard_filters.py` contains the current hard eligibility rules. Remote behavior is split across:
  - `allowed_remote_policies`: blocks a known remote/hybrid/onsite policy outside the allowlist.
  - `remote_only`: blocks hybrid and onsite, but does not block unknown remote policy.
  - `region_incompatible`: blocks when both sides have regions and there is no intersection, except unknown job regions and `worldwide` are allowed.
- `src/role_radar/matching/engine.py` always calculates explainable signals, while `eligible` is solely `not blockers`; model output cannot override blockers.
- `JobFacts` retains field-level provenance (`ats`, `extraction`, `unknown`) and matching results persist blockers, ambiguities, score, and an input/operation hash.
- Current score signals include `location_match`, but the hard-filter eligibility and scoring inputs are separate. Unknown facts generally remain eligible unless a specific blocker has enough evidence.

### Gates and feedback

- Gate B (`gate_b_preflight.py`) validates explicit profile/policy/packet identities, roots, seeds, windows, caps, cardinalities, and budgets without creating authority.
- Gate C authorizes a bound discovery plan and permits only verified official board configurations/evidence; Gate D acquires a broad sealed pool and proves reconciliation and no product mutation. Later Gate E/F flows project profile relevance, select/partition, approve, and materialize bounded payloads.
- `profile_relevance/facts.py` independently projects title/description matches and four constraint states: region, remote, employment, and authorization. Constraint evidence is policy-configured and can result in `match`, `conflict`, `indeterminate`, or `not_applicable`; all hashes bind profile, policy, acquisition, and input identities.
- `src/role_radar/services/feedback_service.py` currently collects discovery candidates and re-ranks them using approved literal phrases only. It exposes location on candidate input/rendering but does not apply profile region/remote eligibility or matching blockers.
- `src/role_radar/services/feedback_refinement.py` uses human apply/reject decisions to propose removal of low-precision coverage phrase groups. It does not update profile remote/location constraints and does not feed hard-filter outcomes into refinement.
- Feedback and blind-labeling gates preserve human decisions, notes, revision checks, and redaction/display boundaries; those consent and authorization boundaries must remain human-controlled.

## Existing test coverage

Relevant coverage exists in:

- `tests/unit/test_matching_core.py`: remote-only, allowed remote policies, unknown remote policy, region behavior, explainable blockers, profile canonicalization, and legacy adaptation.
- `tests/unit/test_extraction_validator.py`: evidence presence/substrings, duplicate extracted items, and validation errors.
- `tests/unit/test_profile_terms.py`: profile-bound term compilation, phrase limits, selected-row freezing, and profile binding drift rejection.
- `tests/unit/test_profile_relevance_materialization.py`, `tests/unit/test_profile_relevance_selection_partition.py`, and `tests/unit/test_profile_relevant_acquisition_architecture.py`: profile-relevance facts, gates, sampling, and artifact boundaries.
- `tests/integration/test_phase04_matching.py`: extraction/profile/job integration and persisted matching replay.
- `tests/integration/test_profile_relevant_acquisition_gate_d.py` and `tests/integration/test_profile_relevant_acquisition_gate_e_f_freeze.py`: broad acquisition, mixed-board parent pools, gate bindings, and freeze/materialization behavior.
- `tests/unit/test_feedback_surface.py` and `tests/integration/test_feedback_discovery_smoke.py`: discovery candidate ordering, phrase relevance bands, rendering, feedback decisions, and summaries.

No current test demonstrates a single end-to-end rule from a frozen profile's remote/location constraints through acquisition/discovery, extraction precedence, matching eligibility, and feedback presentation.

## Architectural seams and risks for proposal/design

1. **Eligibility timing is unresolved.** Gate D intentionally collects broadly, while ordinary collectors persist jobs before extraction/matching. The next phase must decide whether profile-aware remote eligibility is an acquisition admission rule, a post-extraction/matching rule, a feedback visibility rule, or separate rules for each stage.
2. **Evidence quality differs by stage.** ATS payloads may provide location/remote fields, extraction may provide evidence-backed values, and missing/ambiguous values currently fail open in operational matching but can become `indeterminate` in profile-relevance gates.
3. **Location semantics are underspecified.** Existing `regions` are canonical strings and location parsing is a simple fallback; there is no shared contract for remote scope, hybrid eligibility, timezone/geography, or multi-location postings.
4. **The two relevance systems are not unified.** Operational matching uses `JobFacts`/hard blockers; profile-relevant acquisition uses `AcquisitionObservation`/`ProjectedFacts`/constraint states. A proposal should avoid silently inventing a third eligibility model.
5. **Identity and gate bindings are pervasive.** Any profile-aware acquisition change must preserve profile hash/version bindings, plan/policy hashes, journal/budget reconciliation, immutable snapshots, and human authorization gates.
6. **Feedback currently refines discovery phrases, not eligibility constraints.** If feedback is intended to influence remote/location behavior, the proposal must define a human-approved, versioned policy path rather than automatic profile mutation.

## Likely smallest change surface to evaluate next

The smallest coherent design should first define one canonical remote/location eligibility vocabulary and its unknown/conflict behavior, then map it onto existing `JobFacts` hard filters and profile-relevance constraint states. Only after that should proposal/design decide whether discovery query terms, source configuration, Gate D broad acquisition, extraction fields, feedback bands, or persistence schemas actually need changes. Existing broad-acquisition and human-controlled gate boundaries should be preserved unless the next phase explicitly justifies a different scope.

## Next phase

**Proposal** — establish the problem statement, intended eligibility boundary, canonical rules, and explicit non-goals before specifying acceptance criteria or implementation tasks.
