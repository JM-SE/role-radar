# Profile-aware remote eligibility before feedback

## Intent

Make feedback profile-aware without narrowing acquisition: jobs are collected broadly, extracted, and then evaluated against the active candidate profile before they can appear in feedback. This removes avoidable review noise while preserving source coverage and the existing authorization, identity, and gate boundaries.

## Problem

Remote and location eligibility is not currently applied as a single post-extraction boundary before feedback. As a result, feedback can present jobs whose remote scope or region is incompatible with the profile, including jobs whose relevant facts are unknown. Applying source-side filtering would reduce coverage and conflict with the intentionally broad acquisition model, while applying an ad hoc feedback-only rule could diverge from the existing extraction and matching semantics.

The existing job corpus also needs to be brought under the same rule before new acquisition resumes; otherwise users would see inconsistent eligibility behavior between current and newly acquired jobs.

## Product outcome

After extraction, feedback contains only jobs with sufficient, compatible remote and region facts:

- A known remote policy is required; unknown remote scope is excluded.
- A known region is required unless the job is explicitly worldwide; unknown region is excluded.
- A job matches when its canonical region is one of the profile's exact regions, or when the job is explicitly worldwide.
- Jobs failing this eligibility decision remain outside feedback rather than being deleted or preventing broad acquisition.
- Current jobs are reprocessed under the rule before reacquisition resumes, so the feedback surface starts from one consistent policy.

## Scope

1. Define and apply one profile-aware eligibility decision after extraction and before feedback candidate selection.
2. Use the existing extraction evidence and canonical profile region values; preserve the established precedence and validation boundaries rather than creating a parallel location vocabulary.
3. Treat unknown remote policy and unknown region as ineligible for feedback.
4. Accept exact profile-region matches and explicit worldwide jobs. Do not broaden a profile region into an implicit geography.
5. Reprocess the existing job corpus before enabling the next acquisition cycle, using the same eligibility decision as newly processed jobs.
6. Ensure feedback ordering, rendering, and human feedback decisions operate only on eligible jobs.
7. Preserve broad acquisition and the existing gate, profile/version/hash, journal/budget, authorization, consent, and human-decision boundaries.
8. Add coverage for existing-job reprocessing, new-job processing, unknown facts, exact region matching, worldwide jobs, and preservation of acquisition/gate behavior.

## Affected areas

- Post-extraction job processing and matching eligibility.
- Feedback candidate selection and its associated summaries/rendering.
- Existing-job reprocessing/backfill orchestration before reacquisition.
- Unit and integration coverage spanning extraction facts, profile constraints, eligibility, and feedback.
- Any persisted eligibility or processing metadata required by the existing repository conventions; schema changes are not assumed until design confirms they are necessary.

## Non-goals

- Filtering collectors, source queries, Gate D parent pools, or other acquisition inputs by profile eligibility.
- Changing discovery phrase compilation, source registries, provider configurations, or broad-acquisition quotas.
- Deleting jobs or altering immutable acquisition observations because they are ineligible.
- Expanding region semantics to fuzzy geography, neighboring regions, timezone overlap, city/state parsing, or inferred remote scope.
- Treating missing or ambiguous facts as eligible through fail-open behavior.
- Automatically mutating profiles from feedback or changing feedback refinement into a remote/location policy editor.
- Changing authorization, consent, destructive-action, hash-binding, or human approval requirements.
- Replacing the existing matching or profile-relevance systems with a third eligibility architecture.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Unknown or stale extraction facts hide otherwise useful jobs. | Require evidence-backed facts, make exclusion explainable, and retain the underlying jobs for later reprocessing. |
| Region and remote semantics diverge between operational matching and feedback. | Reuse existing canonicalization, extraction precedence, and hard-filter boundaries; define the shared decision before implementation. |
| Reprocessing changes the visible feedback set unexpectedly. | Run it before reacquisition, produce counts/reasons for excluded jobs, and keep source/acquisition records unchanged. |
| A new eligibility step accidentally narrows acquisition or bypasses a gate. | Keep eligibility downstream of extraction and upstream of feedback only; preserve all existing gate, hash, journal, budget, and authorization checks. |
| Partial reprocessing leaves mixed policy versions. | Make reprocessing bounded and restartable, record the applicable profile/policy identity, and do not resume reacquisition until completion is confirmed. |

## Rollback

Disable the post-extraction feedback eligibility application and stop the reprocessing/reacquisition transition without deleting jobs or acquisition artifacts. Restore feedback to the prior candidate-selection behavior using the last known profile/policy binding. If eligibility state is persisted, retain it as historical metadata or invalidate it by its profile/policy hash rather than rewriting source facts. A rollback must not bypass existing authorization, consent, gate, or hash validation.

## Success criteria

- Broad acquisition continues to collect the same parent pool without profile-based source filtering.
- No job with unknown remote policy or unknown region appears in feedback.
- Jobs with an exact profile-region match appear; non-matching regions do not.
- Explicit worldwide jobs appear for profiles with any region set.
- Eligibility is evaluated only after extraction and before feedback presentation.
- Existing jobs are reprocessed under the new rule before new acquisition resumes, with restart/partial-run behavior observable and safe.
- Existing gate, authorization, consent, profile/version/hash, journal, budget, and immutable acquisition boundaries remain intact.
- Feedback decisions and refinement continue to require the existing human-controlled paths.
- Tests demonstrate the rules for both reprocessed current jobs and newly processed jobs, including unknown and worldwide cases.

## Proposal question round

The product scope is confirmed by the orchestrator, so no additional product decision is requested in this phase. The specification phase should confirm only implementation-level details: the exact persisted status/reason representation, the reprocessing checkpoint/resume mechanism, and how the active profile binding is selected when feedback is generated.
