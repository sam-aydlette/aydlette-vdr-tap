# Aydlette VDR Plugin Specification

**`aydlette_vdr` implements the method of "Vulnerability Evidence as a Product" (samaydlette.com/research/vulnerability-evidence.html) as a TAP plugin. For every open finding it decides internet reachability (IRV), likely exploitability (LEV) and impact (PAIN) from declarations that are reconciled with observations, runs the clock and the gates, and publishes every decision with its basis. Where an input is missing it takes the worst case, never a guess.**

## Plugin Identity

| Row | Value |
| --- | --- |
| Slug | `aydlette_vdr` |
| Display name | `Aydlette VDR` |
| Kind | Method plugin. It reads `compliance_core` findings and vulnerability records and `fedramp_20x_vdr`'s rule rows, and writes `fedramp_20x_vdr` evaluations of scheme `aydlette`. Platform adapters (for AWS, `aydlette_vdr_aws`) write its declarations and observations. |
| Repository | `aydlette-vdr-tap` (Apache-2.0 code, CC BY 4.0 docs) |

## Philosophy

FedRAMP's VDR rules turn on three answers per finding: is it reachable from the internet, is it likely to be exploited, and how bad would it be. A provider can give those answers from declarations, but declarations drift. This method makes each answer evidence: the owner declares exposure and classification, observers check the declarations, and reconciliation (Figure 6) decides which to believe. A missing declaration, a missing observation or a missing score never lowers a rating; it takes the worst case and shows up as work to do, in the gates, the decision queue and the coverage Search.

The method is the paper's; this plugin is one implementation of it. The pure core (`method/`) has no TAP or Django import, so the Appendix B conformance tests run on it directly and a provider can run it outside TAP.

**Provenance markers.**
- *Documented:* Appendix A (requirements) and Appendix B (conformance tests) of the paper, as published at samaydlette.com commit `43adaac` (2026-11-16). Requirement text below is quoted from it.
- *Observed:* the r20x TAP session running samaydlette.com's aws_core sweep (2026-11-18 and 2026-11-19).
- *Designed:* the plugin's own features (Searches, the fedramp_20x_vdr bridge, coverage).

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Evidence Not Assertion | Every IRV, LEV and PAIN value carries its basis, and a declaration counts only as far as the observations support it. |
| 2 | Worst Case When Missing | A missing input reads as the worst case and is published as a gap, a gate failure or a queue item. |
| 3 | Governed Choices | Every judgment the method leaves to the provider lives in a validated, versioned profile whose digest every output carries. |
| 4 | Same Grid | Results land on the grid beside other methods (`fedramp_20x_vdr` evaluations) so they can be compared. |
| 5 | Conformance Is Testable | Every Appendix B test is mapped to the test that proves it, or its status says why not. |

## Reading This Spec

Each requirement groups the paper's requirements for one part of the method. Its acceptance criteria are the paper's Appendix B tests (`T1` to `T74`) and, where no Appendix B test covers a requirement, a criterion named for that requirement. An acceptance criterion's status is `Implemented` only when a test cites it with `@pytest.mark.spec`. `In Development` means built but not yet tested, `Backlog` means not built, and `Proposed` means a human act or a live drill rather than a unit test. A requirement is `Implemented` only when all its criteria are.

## Requirements

| RID | Name | Status | Notes |
| --- | --- | :---: | --- |
| req-aydlette-vdr-rules | [Rules As Data](#rules-as-data) | In Development | Timeframes, the overdue limit and the impact scale come from fedramp_20x_vdr's seeded rows; every output records them. |
| req-aydlette-vdr-sources | [One Finding Stream](#one-finding-stream) | In Development | Every open compliance finding is evaluated, with or without a CVE; SDR entries and control-statement findings are not built. |
| req-aydlette-vdr-declarations | [Component Declarations](#component-declarations) | In Development | Exposure intent, data classification, Mission Critical and agency scope per component, with who decided; no defaults. |
| req-aydlette-vdr-reconcile | [Reconciliation](#reconciliation) | Implemented | Figure 6: declared intent and flows against what the observers saw; G4, G5 and G7; flows carry classification. |
| req-aydlette-vdr-irv | [Internet Reachability](#internet-reachability) | In Development | Figure 5: unresolved is IRV; narrowing and tested deflection lower it; nothing else does. |
| req-aydlette-vdr-lev | [Likely Exploitability](#likely-exploitability) | In Development | Figure 7 and the SSVC overlay, first match deciding; θ governed; overrides only by disposition. |
| req-aydlette-vdr-env | [The Environmental Vector](#the-environmental-vector) | Implemented | CVSS Environmental metrics set only where reconciliation backs them, before anything reads the vector. |
| req-aydlette-vdr-pain | [Impact (PAIN)](#impact-pain) | In Development | Three layers: inputs, a governed combining function, a governed mapping onto the rules' scale. |
| req-aydlette-vdr-clock | [The Clock](#the-clock) | In Development | Start from first evaluation, carried forward; a verified mitigation starts a new clock; the overdue limit never resets. |
| req-aydlette-vdr-dispositions | [Dispositions](#dispositions) | In Development | Decision records with deciders and review dates; false positives, mitigations, vendor dependency and VEX. |
| req-aydlette-vdr-gates | [Gates](#gates) | In Development | G1 to G5 and G7 per finding; G6 and the build side of G7 are the pipeline's; gate modes and team scoping are not built. |
| req-aydlette-vdr-governance | [Governed Profiles](#governed-profiles) | In Development | Governed values in a validated, versioned profile; a missing or invalid one fails; every output names its digest. |
| req-aydlette-vdr-publication | [Publication And The Queue](#publication-and-the-queue) | In Development | The decision queue and its rates are built; signing, schemas, tiers, run history and assessor input are the pipeline's. |
| req-aydlette-vdr-third-party | [Third-Party Resources](#third-party-resources) | Backlog | Not built: upstream findings, split responsibility and upstream-control lapses. |
| req-aydlette-vdr-searches | [Searches](#searches) | Implemented | Four module Searches (findings, summary, reconciliation, coverage), shipped as GRIFT nodes with their schemas. |
| req-aydlette-vdr-bridge | [fedramp_20x_vdr Evaluations](#fedramp20xvdr-evaluations) | Implemented | The vdr_evaluations collector writes IRV and LEV as scheme `aydlette`; only reconciled unreachability is backed. |
| req-aydlette-vdr-coverage | [Coverage](#coverage) | Implemented | `aydlette-coverage`: each prerequisite's share, the items missing it, and what the method does without it. |

### Rules As Data
----
RID: `req-aydlette-vdr-rules`

Status: `In Development`

The method never carries a FedRAMP number in code. Timeframes, the maximum overdue period and the PAIN levels are read from `fedramp_20x_vdr`'s seeded rule rows (`deadline_hours`, `acceptance_hours`, `LEVELS`), and every Search output carries a `rules` block naming the rows' source, count, read date and URLs.

#### From the paper

- **REQ-RUL-1**: Timeframes, the maximum overdue period, evaluation windows, cadence minimums, incident thresholds and the impact scale MUST be read from the machine-readable rules at a pinned version. They MUST NOT be copied into code or configuration by hand.
- **REQ-RUL-2**: Every output MUST record the rules version it used.

#### Implementation

`searches/pain.py` (`rules_block`, the `timeframe` closure in `evaluate_rows`); `method/profile.py` validates the scale mapping against the levels the rules publish.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-rules-1 | A new rules level fails until mapped | Implemented | T19: The pinned rules add a level to the impact scale; the profile is refused until its mapping covers it. | `test_t19_a_new_rules_level_fails_until_the_mapping_covers_it` |
| req-aydlette-vdr-rules-2 | Timeframes read from rule rows | Implemented | REQ-RUL-1: Every due date comes from `deadline_hours` and every accept-by from `acceptance_hours`; no timeframe constant exists in the plugin. | `test_due_dates_come_from_the_seeded_rule_rows` (grid) |
| req-aydlette-vdr-rules-3 | Outputs record the rules | In Development | REQ-RUL-2: Every Search output carries the `rules` block (source, row count, read date, URLs). | Built in `rules_block`; needs a grid test. |

### One Finding Stream
----
RID: `req-aydlette-vdr-sources`

Status: `In Development`

The plugin reads every open `compliance_core__compliance_finding`, whatever its source: scanner, DAST, configuration check or CVE. A finding with no vulnerability record is still evaluated. Findings about controls, indicators and processes, and the SDR entries that list them, are not built: they need an SDR model this plugin does not have.

#### From the paper

- **REQ-SRC-1**: Findings from every detection source, including scanners, penetration tests, disclosure reports, assessor findings, control and indicator status, and non-machine reviews, MUST enter one finding stream with the same fields. Each finding MUST keep its source’s detection time.
- **REQ-SRC-2**: A Rev5 control or Key Security Indicator recorded with a gap MUST have an open finding.
- **REQ-SRC-3**: A finding about a control, indicator or process MUST resolve to its SDR entry by identifier. Its reachability and impact MUST be evaluated at the most exposed and most sensitive component the control covers. A finding on a non-machine resource MUST be NIRV.
- **REQ-SRC-4**: Every finding MUST keep its clock in the vulnerability detail report. Each SDR entry MUST list the open findings against it by identifier.
- **REQ-SRC-5**: Each control statement MUST name the inventory components and settings it depends on. A change to any of them MUST open a finding against the statement.

#### Implementation

`searches/pain.py` (`evaluate_rows`); `method/evaluate.py` (`irv`: a non-machine finding is NIRV).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-sources-1 | A non-machine finding is NIRV | Implemented | T32: A finding on a process that touches no machine-based resource is NIRV. | `test_t32_non_machine_finding_is_nirv` |
| req-aydlette-vdr-sources-2 | Every finding enters one stream | Implemented | REQ-SRC-1: Every open compliance finding is evaluated, including findings with no vulnerability record, and keeps its source's detection time. | `test_a_finding_with_no_record_is_evaluated_in_the_same_stream` (grid) |
| req-aydlette-vdr-sources-3 | Penetration test findings | Backlog | T29: A penetration test report naming a URL on a public-edge component yields one finding per weakness, resolved to the component, detected on the report date. | Needs a penetration-test input; resolution is the shared-identifier rule. |
| req-aydlette-vdr-sources-4 | A control gap opens a finding | Backlog | T30: A Rev5 control's status changing to Partially Implemented opens a finding on its SDR entry, detected that day; the entry lists it. | Needs an SDR model (REQ-SRC-2, REQ-SRC-4). |
| req-aydlette-vdr-sources-5 | A changed control setting opens a finding | Backlog | T31: A setting named by a control statement changes; a finding opens against the statement until it is confirmed or rewritten. | REQ-SRC-5. |
| req-aydlette-vdr-sources-6 | SDR entries drop remediated findings | Backlog | T33: A remediated finding leaves its SDR entry's list and shows closed in the vulnerability detail report. | REQ-SRC-4. |

### Component Declarations
----
RID: `req-aydlette-vdr-declarations`

Status: `In Development`

A `aydlette_vdr__declaration` stamps a component's node with its exposure intent (public-edge, public-backed, internal), data classification (public, internal, PII, CUI), Mission Critical flag and agency scope, and names who classified the data and who judged criticality. There is no default: a missing intent or classification fails G5, a missing scope is multi-agency, and a missing decider is published as not recorded. Several declarations on one node merge to the most exposed and most sensitive. An adapter writes declarations; for AWS, aydlette-vdr-aws-tap reads them from tags, and its `Component` tag is the template identifier of REQ-IRV-7.

#### From the paper

- **REQ-IRV-1**: Every inventory component MUST declare exposure_intent as public-edge, public-backed or internal, with a one-sentence rationale. There is no default.
- **REQ-IRV-7**: A resource created from a template MUST carry the template’s identifier and MUST inherit its exposure intent, classification and flows. A resource with neither a template identifier nor an exact match MUST be unresolved.
- **REQ-IRV-13**: Every component MUST publish whether it is publicly exposed, derived from its exposure intent: yes for public-edge, no otherwise.
- **REQ-PAI-3**: Every component MUST declare its data classification (public, internal, or one or both of PII and CUI), MAY carry the Mission Critical flag, and SHOULD declare its agency scope. A missing data classification MUST fail G5. A missing scope MUST be treated as multi-agency. Each declaration MUST name who classified its data and who judged its criticality. A missing name MUST be published as not recorded.

#### Implementation

`models/declaration.py`; `method/evaluate.py` (`merge_declarations`, `declaration_gaps`, `needs`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-declarations-1 | No exposure intent fails G5 | Implemented | T6: A component with no exposure_intent fails G5. | `test_t6_no_exposure_intent_fails_g5` |
| req-aydlette-vdr-declarations-2 | No data classification fails G5 | Implemented | T43: A component with exposure intent but no data classification fails G5. | `test_t43_exposure_intent_without_data_class_fails_g5` |
| req-aydlette-vdr-declarations-3 | No agency scope is multi-agency | Implemented | T44: A component with no declared agency scope is treated as multi-agency. | `test_t44_no_agency_scope_is_multi_agency` |
| req-aydlette-vdr-declarations-4 | An unrecorded classifier is published | Implemented | T54: A component flagged CUI with no record of who classified it keeps the flag; who classified it is published as not recorded. | `test_t54_missing_classifier_is_published_as_not_recorded` |
| req-aydlette-vdr-declarations-5 | Public-backed is IRV and not publicly exposed | Implemented | T63: A component declared public-backed: its findings are IRV, and it is published as not publicly exposed. | `test_t63_public_backed_is_irv`, `test_t63_public_backed_is_not_publicly_exposed` |
| req-aydlette-vdr-declarations-6 | Merged declarations take the worst | Implemented | REQ-IRV-1: Several declarations on one component merge to the most exposed intent and the most sensitive classification. | `test_merge_takes_most_exposed_and_most_sensitive` |
| req-aydlette-vdr-declarations-7 | A templated resource inherits | Backlog | T37: An autoscaled instance carrying a template label resolves to the template's component and takes its exposure intent. | The AWS adapter's `Component` tag shares one declaration across resources (aws spec); the core has no template-label resolution of its own. |

### Reconciliation
----
RID: `req-aydlette-vdr-reconcile`

Status: `Implemented`

Reconciliation compares each declared component with the observations: whether an inside-out, outside-in or telemetry observer found a path from the internet, and which flows it saw. It is vendor-neutral: an observation is a node with an observer, a kind (`internet-path` or `flow`), a target, a result, a time and its evidence. Figure 6 assigns each component a cell. An observed path into an internal or public-backed component is undeclared exposure and fails G4; a public component with no path is over-declared and queued. Declared flows must state what they carry (REQ-PAI-5). A component without a fresh inside-out observation, or a public-edge component without a fresh outside-in one, fails G7. The observers' schedule (REQ-IRV-3) belongs to whoever runs the collectors; the method enforces it through freshness.

#### From the paper

- **REQ-IRV-2**: A component that receives and processes a declared flow from a public component MUST be public-backed. A conflicting internal declaration MUST fail gate G5.
- **REQ-IRV-3** (beyond CR26): Inside-out collection MUST run against live state with read-only credentials on every deploy, before publication, and on a governed schedule between deploys of at least once a day. Outside-in probing MUST run at least once a day and never less often than the rules require machine-based verification. Neither MAY weaken a resource.
- **REQ-IRV-4**: Reconciliation MUST apply Figure 6. Undeclared exposure MUST fail gate G4 and MUST NOT be closed by a disposition.
- **REQ-IRV-8**: Observed flows MUST be compared with declared flows. An undeclared flow from a public component into an internal component MUST be treated as undeclared exposure. Any other undeclared flow MUST be queued.
- **REQ-IRV-11**: Each outside-in result MUST record whether its probe was allowlisted. Results behind a shared edge MUST be attributed by hostname or server name.
- **REQ-PAI-5**: Every declared flow MUST state what it carries. A flow declared to carry a flag into a component without it MUST fail G5. A metadata-only flow MUST publish its reason. A flow from a sensitive component with undeclared contents, or seen only in telemetry, MUST be queued, and the receiving component MUST be classified as if it carried the source’s data flags until decided.

#### Implementation

`method/reconcile.py` (pure); `models/observation.py` (`Observation`, `DeclaredFlow`); `searches/pain.py` (`load_reconcile_inputs`, `reconcile_components`, the `aydlette-reconcile` Search).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-reconcile-1 | An observed path into internal fails G4 | Implemented | T1: A component declared internal with an observed path fails G4, and its findings are IRV. | `test_t1_declared_internal_with_observed_path_fails_g4_and_is_irv`, `test_t1_t27_internal_with_observed_path_is_undeclared_exposure` |
| req-aydlette-vdr-reconcile-2 | An outside-in probe into internal fails G4 | Implemented | T2: A component declared internal that an outside-in probe reaches fails G4. | `test_t2_outside_in_probe_reaching_an_internal_component_fails_g4` |
| req-aydlette-vdr-reconcile-3 | Public-edge with no path is over-declared | Implemented | T3: A public-edge component neither observer reaches is queued as over-declared; its findings stay IRV. | `test_t3_public_edge_with_no_path_is_over_declared_and_queued` |
| req-aydlette-vdr-reconcile-4 | Public-backed with a public flow is consistent | Implemented | T4: A public-backed component fed by a declared flow from a public component is IRV, and no gate fails. | `test_t4_public_backed_is_irv_and_no_gate_fails`, `test_t4_public_backed_with_declared_public_flow_is_consistent` |
| req-aydlette-vdr-reconcile-5 | A public flow into internal fails G5 | Implemented | T5: A component declared internal with a declared flow from a public component fails G5. | `test_t5_declared_public_flow_into_internal_fails_g5` |
| req-aydlette-vdr-reconcile-6 | A path found between deploys fails G4 | Implemented | T27: A path the next inside-out sweep finds into an internal component fails G4 and publishes the undeclared exposure. | The sweep's schedule is operational; this criterion is the reconciliation half. |
| req-aydlette-vdr-reconcile-7 | An undeclared public flow into internal fails G4 | Implemented | T39: Telemetry showing a public component sending data to an internal one, with no declared flow, is undeclared exposure: G4 fails. | `test_t39_observed_public_flow_into_internal_is_undeclared_exposure` |
| req-aydlette-vdr-reconcile-8 | Other undeclared flows are queued | Implemented | REQ-IRV-8: Any other observed flow that no declaration names is queued. | `test_other_undeclared_flow_is_queued` |
| req-aydlette-vdr-reconcile-9 | Allowlisted probes are marked | Implemented | T42: An outside-in result from an allowlisted address is marked allowlisted. | `test_t42_allowlisted_probe_is_recorded` |
| req-aydlette-vdr-reconcile-10 | A flow carrying PII into an unflagged component fails G5 | Implemented | T45: A flow declared to carry PII into a component not flagged PII fails G5. | `test_t45_flow_carrying_pii_into_unflagged_component_fails_g5` |
| req-aydlette-vdr-reconcile-11 | A metadata-only flow with a reason is accepted | Implemented | T46: A metadata-only flow from a PII component with a reason is accepted; a metadata-only flow without one fails G5. | `test_t46_metadata_only_flow_with_reason_is_accepted`, `test_metadata_only_flow_without_reason_fails_g5` |
| req-aydlette-vdr-reconcile-12 | An undeclared flow from PII is queued and inherits | Implemented | T47: Telemetry showing a PII component sending to an unflagged one, with no declared flow: queued, and the receiver is classified PII until decided. | `test_t47_telemetry_flow_from_pii_component_is_queued_and_inherits_pii` |
| req-aydlette-vdr-reconcile-13 | Stale or missing observations fail G7 | Implemented | REQ-IRV-3: A declared component with no inside-out observation inside the freshness window (at most a day), or a public-edge component with no outside-in one, fails G7. | `test_stale_or_missing_inside_out_observation_fails_g7`, `test_public_edge_needs_an_outside_in_observation` |
| req-aydlette-vdr-reconcile-14 | Public-backed with a direct path is undeclared exposure | Implemented | REQ-IRV-4: A public-backed component an observer reaches directly is undeclared exposure (a backed component has no direct path). | `test_public_backed_with_a_direct_path_is_undeclared_exposure` |
| req-aydlette-vdr-reconcile-15 | Public-backed with no public flow is over-declared | Implemented | REQ-IRV-4: A public-backed component with no path and no declared flow from a public component is over-declared. | `test_public_backed_without_a_public_flow_is_over_declared` |
| req-aydlette-vdr-reconcile-16 | A suggestion never replaces a declaration | Implemented | REQ-IRV-1: The intent the observations suggest is published beside the declaration and never used as one. | `test_suggested_intent_never_replaces_the_declaration`, `test_suggests_public_backed_for_a_component_fed_by_a_reachable_one` |

### Internet Reachability
----
RID: `req-aydlette-vdr-irv`

Status: `In Development`

A finding resolves to a component by the grid's own edges (`CARRIES_COMPLIANCE_FINDING`, else fedramp_20x_vdr's reach for package findings). An unresolved finding is IRV, takes the fail-safe classification and is queued. A finding on a public component is NIRV only with a narrowing record or a deflection verified by an outside-in triggering-payload test.

#### From the paper

- **REQ-IRV-5** (beyond CR26): A finding on a public component MAY be NIRV only with a recorded, vulnerability-specific deflection verified by an outside-in triggering-payload test, or with a narrowing record (REQ-IRV-9).
- **REQ-IRV-6** (beyond CR26): Findings MUST resolve to one component, or to an SDR entry, by exact match on a shared identifier. Unresolved findings MUST be IRV, rated with the fail-safe classification, and queued.
- **REQ-IRV-9**: A finding on a public component MAY be narrowed to NIRV by a disposition record whose evidence shows the trigger is off the payload path. The record MUST be published and MUST lapse when the artifact or the component’s flows change.
- **REQ-IRV-10**: A change of exposure intent toward more exposure MUST be evaluated as a potential significant change (SCN-CSO-EVA).
- **REQ-IRV-12**: The inside-out observer SHOULD re-evaluate on cloud change events, with the scheduled sweep as backstop.

#### Implementation

`method/evaluate.py` (`irv`); `searches/pain.py` (finding resolution).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-irv-1 | Unresolved is IRV, fail-safe and queued | Implemented | T7: A finding that matches no inventory identifier exactly is unresolved, IRV, at the fail-safe classification, and queued. | `test_t7_t38_unresolved_is_irv_fail_safe_and_queued` |
| req-aydlette-vdr-irv-2 | A short-lived resource with no match is unresolved | Implemented | T38: A resource with neither a template label nor an exact match is unresolved, IRV, fail-safe, queued. | `test_t7_t38_unresolved_is_irv_fail_safe_and_queued` |
| req-aydlette-vdr-irv-3 | Narrowing makes a public finding NIRV | Implemented | T40: A narrowing record makes a finding on a public component NIRV. | The other half of T40, a new build voiding the record, is the next row. |
| req-aydlette-vdr-irv-4 | A new build voids a narrowing | Backlog | T40: A new build of the artifact voids the narrowing record (REQ-IRV-9). | The disposition has no artifact identity to compare yet. |
| req-aydlette-vdr-irv-5 | Deflection counts only when tested | Implemented | REQ-IRV-5: A deflection lowers IRV only when an outside-in triggering-payload test verified it. | `test_deflection_counts_only_when_tested` |
| req-aydlette-vdr-irv-6 | More exposure is a significant change | Backlog | T41: A change moving a component from internal to public-edge records a significant-change evaluation (REQ-IRV-10). | Needs declaration history. |
| req-aydlette-vdr-irv-7 | Re-evaluate on change events | Backlog | REQ-IRV-12: The inside-out observer re-evaluates on cloud change events, with the sweep as backstop. | SHOULD. The adapters run on a schedule today. |

### Likely Exploitability
----
RID: `req-aydlette-vdr-lev`

Status: `In Development`

LEV is decided by Figure 7, each check independent and the first match deciding: fully mitigated, known exploited (KEV), exploitation observed, the FRD-LEV floor, a governed override, the prediction score against θ, and otherwise LEV (fail-safe). The SSVC overlay replaces the floor with its Automatable form and adds the proof-of-concept check; it is all or nothing. The inputs come from the vulnerability record (KEV, EPSS, SSVC from CISA Vulnrichment, as vuln_mosaic fills them) or from the plugin's `finding_facts`.

#### From the paper

- **REQ-LEV-1** (beyond CR26): LEV MUST be computed as in Figure 7, or as the SSVC overlay changes it, each check independent, first match deciding.
- **REQ-LEV-2**: θ is governed and MUST be published with its rationale. The exploit-prediction feed date and model version MUST be recorded per finding.
- **REQ-LEV-3**: The FRD-LEV floor check MUST NOT be overridden by an exploit-prediction score.
- **REQ-LEV-4** (beyond CR26): A provider MAY override an LEV result only through a disposition record that carries the justification, decided_by, decided_on and review_by. The record MAY cover one advisory across the components matched by a published selector, with exclusions by name. The override MUST be published with each finding it covers and MUST lapse at review_by.
- **REQ-LEV-5**: A provider that uses the SSVC overlay MUST record Exploitation, Automatable and Technical Impact on each finding as SSVC defines them, each with its source (a published record, the provider’s own analysis, or the person who reported the finding) and the time it was recorded. An unrecorded value MUST be published as not recorded.
- **REQ-LEV-6** (beyond CR26): Under the SSVC overlay, a finding with a public proof of concept that is automatable MUST be LEV, whether or not it is IRV.
- **REQ-LEV-7**: Under the SSVC overlay, the floor MUST read Automatable where it is recorded and the severity vector where it is not. Where neither exists, the finding MUST be treated as automatable (VER-EVA-AIA).
- **REQ-LEV-8**: A provider that uses the SSVC overlay MUST apply both of its changes to every finding and MUST name the overlay in each output’s methodology block.

#### Implementation

`method/evaluate.py` (`lev`, `automatable`); `method/profile.py` (θ, the overlay); `models/finding_facts.py`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-lev-1 | The floor beats a low prediction | Implemented | T8: An IRV finding exploitable over the network with no privileges and no user interaction is LEV even with a prediction below θ. | `test_t8_floor_beats_a_low_prediction` |
| req-aydlette-vdr-lev-2 | No score is LEV | Implemented | T9: A NIRV finding with no prediction score is LEV. | `test_t9_nirv_no_score_medium_severity_is_lev` |
| req-aydlette-vdr-lev-3 | A prediction below θ off the floor is NLEV | Implemented | REQ-LEV-1: A finding off the floor with a prediction below θ is NLEV. | `test_prediction_below_theta_off_the_floor_is_nlev` |
| req-aydlette-vdr-lev-4 | Unknown access on a reachable finding is LEV | Implemented | REQ-LEV-1: An IRV finding with unknown access is read as the worst case: LEV. | `test_unknown_access_on_a_reachable_finding_is_lev` |
| req-aydlette-vdr-lev-5 | An override lapses at review_by | Implemented | T28: A finding with no prediction score overridden to NLEV is LEV again once review_by passes. | `test_t28_override_lapses_at_review_by` |
| req-aydlette-vdr-lev-6 | An override never clears KEV or the floor | Implemented | REQ-LEV-3: A governed override cannot clear a known-exploited finding, observed exploitation or the FRD-LEV floor. | `test_override_never_clears_kev_or_the_floor` |
| req-aydlette-vdr-lev-7 | The prediction feed is recorded | Implemented | REQ-LEV-2: Each finding publishes its prediction feed date and model version, or not recorded. | `test_prediction_feed_is_recorded_or_not_recorded` |
| req-aydlette-vdr-lev-8 | One override across an advisory | Backlog | T49: One override naming an advisory and a package selector covers all twelve affected components, with its review date. | REQ-LEV-4 selectors are not modeled. |
| req-aydlette-vdr-lev-9 | A new component inherits the override | Backlog | T50: A component built later with the same package inherits the override unless excluded by name. |  |
| req-aydlette-vdr-lev-10 | Overlay: Automatable, reachable, no privileges is LEV | Implemented | T55: Under the SSVC overlay: IRV finding recorded Automatable, needing no privileges, with no proof of concept; prediction score below θ. Then: LEV. | `test_t55_overlay_automatable_irv_no_privileges_is_lev` |
| req-aydlette-vdr-lev-11 | Overlay: not Automatable is NLEV | Implemented | T56: Under the SSVC overlay: IRV finding recorded not Automatable, with its source, needing no privileges, with no proof of concept; prediction score below θ. Then: NLEV. | `test_t56_overlay_not_automatable_is_nlev` |
| req-aydlette-vdr-lev-12 | Overlay: a PoC on an Automatable flaw is LEV | Implemented | T57: Under the SSVC overlay: NIRV finding with a public proof of concept, recorded Automatable; prediction score below θ. Then: LEV. | `test_t57_overlay_poc_automatable_is_lev_even_nirv` |
| req-aydlette-vdr-lev-13 | Overlay: no recorded Exploitation skips the PoC check | Implemented | T58: Under the SSVC overlay: NIRV finding recorded Automatable, with no recorded Exploitation; prediction score below θ. Then: NLEV. The proof-of-concept check is skipped. | `test_t58_overlay_no_recorded_exploitation_skips_the_poc_check` |
| req-aydlette-vdr-lev-14 | Overlay: a pentest PoC needing a login is LEV | Implemented | T59: Under the SSVC overlay: penetration test finding that needs a login; the tester records a proof of concept and Automatable. Then: LEV. | `test_t59_overlay_pentest_finding_needing_a_login_with_a_poc_is_lev` |
| req-aydlette-vdr-lev-15 | Overlay: SSVC values published with source and time | Backlog | T60: Under the SSVC overlay: a finding’s Exploitation, Automatable and Technical Impact. Then: Each published with its source and time. An unrecorded value is published as not recorded. | `finding_facts` stores `ssvc_source` and `ssvc_recorded_at`, but no output publishes them yet (REQ-LEV-5). |
| req-aydlette-vdr-lev-16 | The overlay is named in each output | Implemented | REQ-LEV-8: Each output's profile block says whether the overlay is on. | `test_each_output_says_whether_the_overlay_is_on` (grid) |

### The Environmental Vector
----
RID: `req-aydlette-vdr-env`

Status: `Implemented`

The method reads one CVSS vector per finding: the newest CVSS version the enricher holds. Before reachability, LEV and impact read it, CVSS Environmental metrics are set where reconciliation backs them, and only there. Nobody chooses a number: the vector comes from the record, the security requirements (CR, IR, AR) are the needs map's, which the decision table already weighs, and each modified metric comes from evidence. No separate scoring function is applied.

- **Modified Attack Vector Adjacent** when the perimeter is backed: declared internal, Figure 6 consistent, a fresh observation found no path from the internet, and G4, G5 and G7 pass (the same evidence that backs `internet_reachable = false` in the bridge).
- **Modified Privileges Required Low** when authenticated ingress is backed: a fresh `unauth-ingress` observation found no ingress that takes unauthenticated requests, and none found one; Figure 6 is consistent; no undeclared flow was observed into the component; and G4, G5 and G7 pass. The observation speaks only to requests: an adapter answers only for components reached through requests it can see.

A modified metric only lowers a Base value of Network or None. Every other modified metric, User Interaction among them, stays X: no evidence the observers collect shows that a flaw fires only when a user acts. An unresolved finding takes none, and a finding on several components takes one only when all of them back it. The record's own Environmental metrics describe its publisher's environment and are never read. Each output publishes the Base vector, the environmental one, and each modified metric's basis.

What changes: the FRD-LEV floor and the SSVC overlay's Automatable read the environmental vector, so a backed Privileges Required lifts the floor and the prediction score decides, and a backed Adjacent attack vector is not automatable read from the vector. Reachability is still decided by Figure 5.

#### Implementation

`method/evaluate.py` (`environmental`); `method/reconcile.py` (`perimeter_backed`, `ingress_authenticated`, the `unauth-ingress` observation); `method/vector.py` (`with_environmental`). The AWS adapter's `unauth-ingress` rule is in aydlette-vdr-aws-tap.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-env-1 | Backed authenticated ingress lifts the floor | Implemented | A reachable finding exploitable over the network with no privileges and no user interaction, on a component whose authenticated ingress is backed, takes Modified Privileges Required Low; the floor no longer applies and a prediction below θ is NLEV. Without the backing, the floor decides. | `test_backed_authenticated_ingress_sets_mpr_low_and_lifts_the_floor` |
| req-aydlette-vdr-env-2 | A backed perimeter sets Modified Attack Vector Adjacent | Implemented | A Network vector on a component whose perimeter is backed takes Modified Attack Vector Adjacent; reachability is still Figure 5's; under the overlay the vector no longer reads as automatable. | `test_a_backed_perimeter_sets_mav_adjacent`, `test_mav_adjacent_makes_a_vector_read_flaw_not_automatable_under_the_overlay` |
| req-aydlette-vdr-env-3 | A modified metric only lowers | Implemented | Privileges Required Low or High, and an Attack Vector other than Network, are left as the record states them. | `test_a_modified_metric_only_lowers_a_network_or_none_base_value` |
| req-aydlette-vdr-env-4 | Only the method's own Environmental metrics are read | Implemented | With nothing backed the environmental vector is the Base vector. A record's own Environmental, Threat and Supplemental metrics are dropped and never read. | `test_nothing_backed_keeps_the_base_vector`, `test_the_records_own_environmental_metrics_are_never_read`, `test_the_environmental_vector_keeps_only_base_metrics_and_the_methods_own` |
| req-aydlette-vdr-env-5 | No backing, no modified metric | Implemented | An unresolved finding takes none; a finding on several components takes one only when all of them back it. | `test_an_unresolved_finding_takes_no_modified_metric`, `test_a_finding_on_several_components_needs_the_backing_on_all_of_them` |
| req-aydlette-vdr-env-6 | Every vector form takes the same metrics | Implemented | Scanner access with no vector, and a CVSS 4.0 vector, take the same modified metrics as a 3.x vector. | `test_scanner_access_takes_the_same_modified_metrics`, `test_a_cvss_4_vector_takes_the_same_modified_metrics` |
| req-aydlette-vdr-env-7 | What backs authenticated ingress | Implemented | Only a fresh answer that found no unauthenticated ingress, with none that found one, on a consistent component with no gate failing and no undeclared flow in. No answer backs nothing and fails nothing. | `test_ingress_is_authenticated_only_on_a_fresh_answer_with_no_unauthenticated_path`, `test_one_unauthenticated_answer_outweighs_another_that_found_none`, `test_ingress_backing_needs_a_consistent_component_with_no_gate_failing_or_undeclared_flow` |
| req-aydlette-vdr-env-8 | What backs the perimeter | Implemented | Only a consistent internal component that a fresh observation found no path to. | `test_the_perimeter_is_backed_only_for_a_consistent_internal_component_with_no_path` |

### Impact (PAIN)
----
RID: `req-aydlette-vdr-pain`

Status: `In Development`

The rating combines the vulnerability's technical impact, the properties its vector touches and the component's needs (from its classification), through a governed combining function (the decision tables; a profile that changes them publishes the deviation), onto the rules' scale. A fully mitigated finding is the scale's lowest level. The vocabulary, needs map and tables are global; a profile's deviations are published.

#### From the paper

- **REQ-PAI-1**: The impact rating MUST be computed in three layers: inputs from the vulnerability’s technical impact, the properties its severity vector says it touches, and the component’s classification; a governed combining function, by default the tables in Impact; and a governed mapping onto the scale from the rules. A fully mitigated finding MUST receive the scale’s lowest level.
- **REQ-PAI-2**: Every rating change MUST be appended with its time and reason.
- **REQ-PAI-4**: The classification vocabulary, the default map from classification to needs and the default impact tables MUST be global. A provider that deviates from any of them MUST publish the deviation.
- **REQ-PAI-6**: The fail-safe classification MUST be PII, CUI, Mission Critical and multi-agency.
- **REQ-PAI-7**: Technical impact MUST be read from the severity vector: total when confidentiality and integrity are both High, partial otherwise. Where there is no vector, the published fallback from the scanner’s severity MUST apply. Where neither exists, it MUST be total. Under the SSVC overlay, a published Technical Impact takes the vector’s place.

#### Implementation

`method/evaluate.py` (`technical_impact`, `needs`, `pain`); `method/profile.py` (`GLOBAL_DEFAULTS`, `deviations`, `digest`); `method/vector.py`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-pain-1 | Fully mitigated is the lowest level | Implemented | T15: A finding recorded not affected because a control protects it is fully mitigated at the scale's lowest level, never a false positive. | `test_t15_t23_fully_mitigated_is_n0_never_a_false_positive` |
| req-aydlette-vdr-pain-2 | Availability-only on CUI is the Medium need | Implemented | T48: An availability-only flaw on a CUI component that is not Mission Critical. Then: Weighed at the Medium availability need. | `test_t48_availability_only_on_cui_not_mission_critical_is_medium_need` |
| req-aydlette-vdr-pain-3 | Availability, partial, High need, multi-agency is N4 | Implemented | T61: Availability-only flaw with partial technical impact on a component with a High availability need, multi-agency. Then: N4. | `test_t61_availability_partial_high_need_multi_is_n4` |
| req-aydlette-vdr-pain-4 | C and I High is total | Implemented | T62: A vector marks confidentiality and integrity High; no SSVC overlay. Then: Technical impact total. | `test_t62_c_and_i_high_is_total` |
| req-aydlette-vdr-pain-5 | No vector and no severity is total | Implemented | REQ-PAI-7: With neither a vector nor a scanner severity, technical impact is total. | `test_no_vector_no_severity_is_total` |
| req-aydlette-vdr-pain-6 | The severity fallback keeps the fail-safe | Implemented | REQ-PAI-6: The scanner-severity fallback goes through the classification, and a fallback straight to the scale is refused. | `test_severity_fallback_goes_through_the_classification_so_the_fail_safe_holds`, `test_a_fallback_straight_to_the_scale_is_refused` |
| req-aydlette-vdr-pain-7 | Deviations are published | Implemented | REQ-PAI-4: The global defaults have no deviations; a profile's departures are listed by path. | `test_the_global_defaults_have_no_deviations` |
| req-aydlette-vdr-pain-8 | The worked scenario | Implemented | REQ-PAI-1: The paper's HTTP/2 flood scenario rates the docs site N1 and the filing API N4. | `test_scenario_http2_flood_docs_site_n1_filing_api_n4` |
| req-aydlette-vdr-pain-9 | Rating changes are appended | Backlog | REQ-PAI-2: Every rating change is appended with its time and reason. | The plugin computes ratings on read and keeps no history. |

### The Clock
----
RID: `req-aydlette-vdr-clock`

Status: `In Development`

The clock starts at the first evaluation (or detection, when evaluated in the same pass) and carries forward. A verified mitigation that changes the rating starts a new clock; any other change selects a new timeframe from the same start. The maximum overdue period counts from the first evaluation and never resets; past it, a finding is reported as accepted. A KEV due date caps the deadline.

#### From the paper

- **REQ-DLN-1**: The first detection and first evaluation times MUST carry forward across builds. A verified mitigation that changes the evaluation MUST start a new clock. Any other change in evaluation MUST select a new timeframe from the same start. No disposition pauses the clock.
- **REQ-DLN-2**: A finding likely to miss its deadline MUST be reported as likely overdue before the deadline.
- **REQ-DLN-3** (beyond CR26): The maximum overdue period MUST be counted from the first evaluation and MUST NOT reset.

#### Implementation

`method/evaluate.py` (the clock block in `evaluate`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-clock-1 | Past the overdue limit is accepted | Implemented | T14: A finding past the maximum overdue period, not fully mitigated or remediated, is reported as accepted. | `test_t14_past_max_overdue_is_reported_accepted` |
| req-aydlette-vdr-clock-2 | A verified mitigation starts a new clock | Implemented | T34: A verified mitigation that lowers a rating on day d counts the new timeframe from d; the first evaluation is unchanged. | `test_t34_verified_mitigation_starts_a_new_clock_first_evaluation_unchanged` |
| req-aydlette-vdr-clock-3 | Other changes keep the start | Implemented | T35: An evaluation that falls because the prediction score drops keeps the existing clock start. | `test_t35_evaluation_change_without_mitigation_keeps_the_clock_start` |
| req-aydlette-vdr-clock-4 | Successive mitigations cannot pass the limit | In Development | T36: Successive mitigations that move the deadline past the overdue limit from first evaluation are reported accepted when the limit ends. | Built (accept-by is fixed to first evaluation); needs a test. |
| req-aydlette-vdr-clock-5 | A KEV due date caps the deadline | Implemented | REQ-DLN-1:  | `test_kev_due_date_caps_the_deadline` |
| req-aydlette-vdr-clock-6 | Likely overdue is reported | In Development | REQ-DLN-2: A finding inside the governed margin before its deadline is reported likely overdue. | Built (`likely_overdue_margin_hours`); needs a test. |

### Dispositions
----
RID: `req-aydlette-vdr-dispositions`

Status: `In Development`

A disposition records what a person decided about a finding: false positive, full or partial mitigation, narrowing, deflection, LEV override, vendor dependency, risk acceptance or operational requirement. Each carries its reason, decider, decision date and review date, and is treated as absent once past review. A mitigation must name its control. A vendor-dependency disposition lapses when a fix is available, and an unknown fix state counts as available. A VEX-based false positive must cover the deployed version and a live statement.

#### From the paper

- **REQ-DSP-1**: Every disposition MUST carry the shared identifiers, the finding’s status, the reason, decided_by, decided_on and a governed review_by. Unrecorded fields MUST be published as not recorded.
- **REQ-DSP-2** (beyond CR26): A disposition past review_by MUST be treated as absent.
- **REQ-DSP-3**: The disposition encoding MUST keep the three distinctions in “What a disposition record must carry”.
- **REQ-DSP-4** (beyond CR26): A finding MAY be recorded as a false positive only if the reason it is not exploitable lives inside the scanned artifact and the flaw was never exploitable in the offering. Any other non-exploitable finding MUST be recorded as remediated or mitigated. A false positive MUST stay in the vulnerability detail report in a false-positive group with its reason.
- **REQ-DSP-5**: A false positive taken from a vendor’s VEX statement MUST name the statement, its source and the product version it covers, and that version MUST be the one deployed. A justification that depends on how the provider deploys or configures the product MUST be recorded as a mitigation. A changed or withdrawn statement MUST void the false positive in the next build.
- **REQ-MIT-1**: Every mitigation record MUST name its control by inventory identifier.
- **REQ-MIT-2** (beyond CR26): A change to a named control, or a failed outside-in re-test, MUST void the mitigations that depend on it in the same build. The finding MUST return to its prior evaluation and to the clock it had before the mitigation.
- **REQ-VD-1**: Scanner fix state and fixed versions MUST be retained on each finding.
- **REQ-VD-2** (beyond CR26): A vendor-dependency disposition MUST lapse on the first scan where a fix is available. An unknown fix state MUST count as available.

#### Implementation

`models/disposition.py`; `method/evaluate.py` (`disposition_state`, `KINDS`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-dispositions-1 | Vendor dependency lapses when fixable or unknown | Implemented | T12, T13: A vendor-dependency disposition lapses when the fix state becomes fixed or is unknown. | `test_t12_t13_vendor_dependency_lapses_when_fixable_or_unknown` |
| req-aydlette-vdr-dispositions-2 | Past review_by is absent and queued | Implemented | T16: Disposition with review_by in the past. Then: Treated as absent. Queued for review. | `test_t16_past_review_by_is_absent_and_queued` |
| req-aydlette-vdr-dispositions-3 | A runtime-flag mitigation is never a false positive | Implemented | T23: A feature disabled by a runtime flag is fully mitigated with the flag as its control, never a false positive. | `test_t15_t23_fully_mitigated_is_n0_never_a_false_positive` |
| req-aydlette-vdr-dispositions-4 | A mitigation needs a control | Implemented | REQ-MIT-1: A mitigation that names no control is not in force. | `test_mitigation_without_a_control_is_not_in_force` |
| req-aydlette-vdr-dispositions-5 | VEX needs the deployed version and a live statement | Implemented | T69, T70: A VEX false positive for another version, or from a withdrawn statement, is not in force. | `test_t69_t70_vex_false_positive_needs_the_deployed_version_and_a_live_statement` |
| req-aydlette-vdr-dispositions-6 | A build-stage-only package is a false positive | Proposed | T22: A vulnerable package present only in a build stage is recorded as a false positive. | A person records it; the method accepts the record. No check that the package is absent at runtime. |
| req-aydlette-vdr-dispositions-7 | A changed control voids its mitigations | Backlog | T24: A change to a control named by a mitigation voids it in the same build; the finding returns to its prior evaluation and clock. | REQ-MIT-2. Needs control change detection. |
| req-aydlette-vdr-dispositions-8 | A failed re-test voids its mitigations | Backlog | T25: An outside-in re-test showing the control no longer blocks the payload voids the mitigation. | REQ-MIT-2. |
| req-aydlette-vdr-dispositions-9 | A setting-dependent VEX is a mitigation | Proposed | T71: A VEX justification that depends on a provider-controlled setting is recorded as a mitigation naming that control. | A person records it; REQ-MIT-1 then holds. |
| req-aydlette-vdr-dispositions-10 | Fix state is retained | In Development | REQ-VD-1: Scanner fix state and fixed versions are kept on each finding. | `finding_facts.fix_state` holds the state; fixed versions are not modeled. |

### Gates
----
RID: `req-aydlette-vdr-gates`

Status: `In Development`

Every evaluated finding carries G1 (KEV past due), G2 (top-rated, reachable, likely exploitable, undecided), G3 (past its timeframe), G4 (undeclared exposure), G5 (missing or contradicting declarations) and G7 (missing or stale observations). The summary Search aggregates them. G6 (build integrity) and the build side of G7 (stale scanner databases) are the publication pipeline's, and every output lists them as not evaluated. Gate modes, team-scoped blocking and planted-condition drills are not built.

#### From the paper

- **REQ-GAT-1** (beyond CR26): Gates G1 to G7 MUST run on every build and every scheduled run. Each gate’s mode is governed and published. No mode MAY hide risk from the necessary parties: a detect-and-recover gate MUST publish the finding, the queue item and the recovery clock. G6 MUST be fail-closed, and a G6 failure MUST be published immediately as a status record of the failure.
- **REQ-GAT-2**: Every gate MUST have a test, and a known-bad input under version control that the gate must reject.
- **REQ-GAT-3**: A gate failure MUST block deploys and publication only for the team that owns the failing component. G6 failures, and G7 failures in shared parts of the platform, MUST block all teams.
- **REQ-GAT-4**: A change to a gate’s mode MUST be a decision record with decided_by, decided_on, the reason and review_by, and MUST be published.
- **REQ-GAT-5**: Every gate that reads live state MUST also be tested with a known-bad condition planted in a safe part of the live system. The condition MUST appear as a finding or a gate failure within one scheduled cycle, and its creation and cleanup MUST be logged changes.

#### Implementation

`method/evaluate.py` (the gates block); `searches/pain.py` (`aydlette_summary`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-gates-1 | KEV past due fails G1 even when protected | Implemented | T10: Known-exploited finding recorded as protected by a control, past its catalog due date. Then: G1 fails. | `test_t10_kev_past_catalog_due_date_fails_g1_even_when_protected`, `test_kev_past_its_due_date_fails_g1_on_the_grid` |
| req-aydlette-vdr-gates-2 | Top-rated reachable likely exploitable fails G2 | Implemented | REQ-GAT-1:  | `test_g2_top_rated_reachable_likely_exploitable_without_disposition` |
| req-aydlette-vdr-gates-3 | Past timeframe fails G3 | Implemented | T11: Finding past the timeframe the rules assign to its combination, no disposition. Then: G3 fails. | `test_t11_past_timeframe_without_disposition_fails_g3` |
| req-aydlette-vdr-gates-4 | Integrity failure blocks publication | Backlog | T17, T20: An output built from one inventory while another is published fails G6; nothing new is published and a status record names the failure. | G6 belongs to the publication pipeline, not this plugin. |
| req-aydlette-vdr-gates-5 | Detect-and-recover publishes the recovery | Backlog | T21: A gate in detect-and-recover mode lets the build proceed and publishes the finding, a queue item and its recovery clock. | Gate modes are not modeled (REQ-GAT-4). |
| req-aydlette-vdr-gates-6 | Gates block only the owning team | Backlog | T51: G4 fails for a component owned by team A. Then: Team A’s deploys are held. Team B deploys. | No team ownership is modeled (REQ-GAT-3). |
| req-aydlette-vdr-gates-7 | A stale vulnerability database fails G7 for all | Backlog | T52: The shared vulnerability database is stale. Then: G7 fails for every team. | The build side of G7 is the pipeline's. |
| req-aydlette-vdr-gates-8 | A mode change needs a decision record | Backlog | T53: A gate’s configured mode changes with no decision record. Then: The build fails. | REQ-GAT-4. |
| req-aydlette-vdr-gates-9 | A planted condition appears within one cycle | Proposed | T72: A security group opened by hand on a test component appears as a finding or a G4 failure within one scheduled cycle; the change and cleanup are logged. | A live drill (REQ-GAT-5), run with the assessor, not a unit test. |

### Governed Profiles
----
RID: `req-aydlette-vdr-governance`

Status: `In Development`

A profile (`aydlette_vdr__profile`) holds every governed choice: θ and its rationale, the combining function, the needs map, the tables, the severity fallback, the SSVC overlay and the freshness window. It is validated on every read; a missing or invalid profile fails the Search. Every output carries the profile's id, version, sha256 and deviations. Signed conformance results per profile version (REQ-GOV-2) are not built.

#### From the paper

- **REQ-GOV-1**: Governed values MUST live in a schema-validated, version-controlled file. The build MUST fail if it is missing or invalid. Every output MUST record its version.
- **REQ-GOV-2**: Every output MUST name the profile version it conforms to and carry the signed results of that version’s conformance tests.

#### Implementation

`method/profile.py` (`validate`, `digest`, `deviations`); `models/profile.py`; `grift/profiles.grift.json` (the `aydlette-starter` profile).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-governance-1 | A missing or invalid profile fails | Implemented | T18: Governed configuration missing or invalid. Then: The build fails. | `test_t18_missing_or_invalid_profile_fails` |
| req-aydlette-vdr-governance-2 | Half an overlay fails | Implemented | T68: A profile that enables the Automatable floor without the proof-of-concept check is refused. | `test_t68_half_an_overlay_fails_the_build` |
| req-aydlette-vdr-governance-3 | The profile digest is stable | Implemented | REQ-GOV-1: The same profile always yields the same digest, which every output records. | `test_profile_digest_is_stable` |
| req-aydlette-vdr-governance-4 | Signed conformance results | Backlog | T67: An output names its profile version and carries the signed results of that version's conformance tests; a consumer flags a failed test. | REQ-GOV-2. |

### Publication And The Queue
----
RID: `req-aydlette-vdr-publication`

Status: `In Development`

Every row carries its decision-queue items (kind, subject, opening time, why a person decides, options), and the summary Search publishes each kind's rate with its denominator and the count of findings the public tier withholds. Publishing itself (signing, FedRAMP report schemas, VEX, the two tiers, the run history and assessor input) happens in the publication pipeline, not in this plugin.

#### From the paper

- **REQ-QUE-1**: Decision-queue items MUST be published with kind, subject, opening time, why the decision belongs to a person, and options. An escalation rate for each kind of queue item MUST be published, with its denominator.
- **REQ-PUB-1**: Every output MUST be signed by an identity bound to the pipeline and verifiable without contacting the provider.
- **REQ-PUB-2**: A check outside the pipeline MUST fail when a published output is older than the governed freshness window, and MUST alert.
- **REQ-PUB-3**: Reports MUST follow FedRAMP’s report schemas. Dispositions MUST be published in a standard VEX format.
- **REQ-PUB-4**: Outputs MUST be published in two tiers. The full tier MUST go to all necessary parties through a FedRAMP-compatible trust center and MUST carry every finding and every report field. It MUST NOT carry exploitation detail beyond the report fields (CDS-CSO-RIS). The public tier MUST omit open findings that are both reachable and likely exploitable, including from its counts, until they are remediated, and MAY then add their full entries. A provider MAY publish the full tier openly where it determines that doing so will not likely lead to exploitation (VER-RPT-NID, VER-RPT-RPD).
- **REQ-PUB-5**: Every scheduled run MUST append a run record to the evidence history, whatever its outcome, with the run identifier, start and end times, job and rules versions, input counts and result. A scheduled slot with no run record MUST be published as a missed run. The evidence history MUST be append-only.
- **REQ-ASR-1**: Assessor findings and summaries MUST enter through an input port as records signed by the assessor. The provider MUST NOT change their intent, and every output that carries them MUST carry the assessor’s signature or a reference to it.

#### Implementation

`method/evaluate.py` and `method/reconcile.py` (queue items); `searches/pain.py` (`aydlette_summary`).

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-publication-1 | Queue items and rates are published | Implemented | REQ-QUE-1: Each queue item has kind, subject, opened_at, why and options; the summary publishes each kind's rate with its denominator. | Queue fields asserted in several tests; rates in `test_the_summary_counts_gates_the_queue_and_the_withheld_tier` (grid) |
| req-aydlette-vdr-publication-2 | The public tier withholds open IRV and LEV | In Development | T26: The summary counts open findings that are both IRV and LEV, which the public tier must neither list nor count. | The count is built (`public_tier_withheld`); the tiers themselves are the pipeline's. |
| req-aydlette-vdr-publication-3 | A missed run is published | Backlog | T73: A scheduled run does not start. Then: A missed run is published for its slot. The history does not show a clean day. | REQ-PUB-5: the pipeline's run history. |
| req-aydlette-vdr-publication-4 | Assessor text matches its signed record | Backlog | T74: The text of an assessor finding in an output differs from the assessor’s signed record. Then: The build fails. | REQ-ASR-1: the pipeline's assessor input port. |

### Third-Party Resources
----
RID: `req-aydlette-vdr-third-party`

Status: `Backlog`

Third-party information resources (MAS-CSO-TPR) as inventory components that name the upstream offering and the split of responsibility, with the upstream's findings linked into the provider's context. Nothing here is built.

#### From the paper

- **REQ-TPR-1**: Every third-party information resource documented under MAS-CSO-TPR MUST be an inventory component that names the upstream offering, the upstream component’s identifier, the provider’s exposure intent and classification for it, and the split between what the upstream runs and what the provider configures.
- **REQ-TPR-2** (beyond CR26): A finding the upstream reports on what it runs MUST appear as a linked finding that names the upstream finding, copies the facts about the vulnerability, evaluates reachability and impact in the provider’s context, and shows the upstream’s due date.
- **REQ-TPR-3**: A finding on what the provider configures MUST be the provider’s finding, on its clock, with the upstream’s remediation status as its fix state.
- **REQ-TPR-4**: A mitigation that names an upstream control MUST lapse when the upstream’s record for that control lapses or its re-test fails.
- **REQ-TPR-5**: Each third-party entry MUST state whether the provider has the upstream’s full tier. Where it does not, the gap MUST be published.

#### Implementation

None yet.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-third-party-1 | Upstream findings are linked | Backlog | T64: The upstream reports a finding on a component it runs. Then: Linked finding naming the upstream finding, with the facts about the vulnerability copied, reachability and impact from the provider’s declarations, and the upstream’s due date. |  |
| req-aydlette-vdr-third-party-2 | An upstream control lapse voids the mitigation | Backlog | T65: A provider mitigation names an upstream control; the upstream’s record for that control lapses. Then: Mitigation voided. Finding back at its prior evaluation on its pre-mitigation clock. |  |
| req-aydlette-vdr-third-party-3 | A missing upstream full tier is published | Backlog | T66: A third-party entry without access to the upstream’s full tier. Then: The entry says so, and the gap is published. |  |

### Searches
----
RID: `req-aydlette-vdr-searches`

Status: `Implemented`

`aydlette-pain`, `aydlette-summary`, `aydlette-reconcile` and `aydlette-coverage` are `module` Search runners, declared in the manifest and shipped as Search nodes whose input schemas match the runners'.

#### Implementation

`searches/pain.py`, `searches/coverage.py`, `searches/schema.py`, `grift/searches.grift.json`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-searches-1 | Every runner ships a node with its schema | Implemented |  | `test_every_runner_ships_a_search_node_with_its_schema` |
| req-aydlette-vdr-searches-2 | Runner keys are in the manifest | Implemented |  | `test_runner_keys_are_declared_in_the_manifest` |

### fedramp_20x_vdr Evaluations
----
RID: `req-aydlette-vdr-bridge`

Status: `Implemented`

The `vdr_evaluations` collector writes one `fedramp_20x_vdr__vdr_evaluation` of scheme `aydlette` per finding, so other methods on the grid can read this method's results. `pain` stays null (fedramp_20x_vdr v0 holds none); the rating and every basis are in `rationale`. Only `internet_reachable = false` is backed with evidence, and only when reconciliation supports it: declared internal, a consistent Figure 6 cell, a fresh observation with no path, and G4, G5 and G7 passing. LEV false and dispositions are recorded but never backed.

#### Implementation

`vdr_bridge.py` (pure); `collectors/vdr_evaluations/collector.py`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-bridge-1 | Reconciled internal backs unreachable | Implemented |  | `test_reconciled_internal_component_backs_unreachable_with_evidence` |
| req-aydlette-vdr-bridge-2 | Nothing is backed without clean reconciliation | Implemented |  | `test_nothing_is_backed_without_clean_reconciliation` |
| req-aydlette-vdr-bridge-3 | Dispositions and LEV are never backed | Implemented |  | `test_dispositions_and_lev_are_recorded_but_never_backed` |
| req-aydlette-vdr-bridge-4 | Several CVEs combine to the worst | Implemented |  | `test_several_cves_on_one_finding_combine_to_the_worst` |
| req-aydlette-vdr-bridge-5 | One evidence node per component | Implemented |  | `test_one_evidence_node_per_component` |

### Coverage
----
RID: `req-aydlette-vdr-coverage`

Status: `Implemented`

Without a prerequisite the method takes the worst case, fails a gate or queues a decision. Coverage lists, per prerequisite, what it applies to, how much has it, the items missing it and the consequence: declarations, observers, flows, finding factors decided on evidence, advisory feeds (CVSS, KEV, EPSS, SSVC) for CVE-like IDs, and vectors for checks. The inventory is every node an observer saw, a declaration names or an open finding is carried by, so the Search needs no platform knowledge.

#### Implementation

`method/coverage.py` (pure); `searches/coverage.py`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-coverage-1 | Untagged resources count against declared | Implemented |  | `test_untagged_resources_an_observer_saw_count_against_declared` |
| req-aydlette-vdr-coverage-2 | Missing declaration fields are listed | Implemented |  | `test_missing_declaration_fields_are_listed_by_component` |
| req-aydlette-vdr-coverage-3 | Observer gaps are split by observer | Implemented |  | `test_observer_gaps_split_inside_out_and_outside_in` |
| req-aydlette-vdr-coverage-4 | Public-backed needs a public flow | Implemented |  | `test_public_backed_needs_a_declared_flow_from_a_public_component` |
| req-aydlette-vdr-coverage-5 | Observed flows are checked | Implemented |  | `test_observed_flows_are_checked_against_declared_flows` |
| req-aydlette-vdr-coverage-6 | Fail-safe factors are counted | Implemented |  | `test_fail_safe_factors_are_counted_per_row` |
| req-aydlette-vdr-coverage-7 | Advisory feeds apply to advisories only | Implemented |  | `test_advisory_feeds_apply_only_to_advisories_and_checks_need_a_vector`, `test_advisory_ids` |
| req-aydlette-vdr-coverage-8 | No advisories is not applicable | Implemented |  | `test_no_advisories_is_not_applicable_rather_than_failing` |
| req-aydlette-vdr-coverage-9 | Gaps are listed worst first | Implemented |  | `test_summary_lists_gaps_worst_first` |

### The Method On A Grid
----
RID: `req-aydlette-vdr-grid`

Status: `Implemented`

Every path runs on a grid, not only on pure data, including the advisory path. The CVE grid fixture (`tests/cve_grid.py`) puts findings carrying CVE and GHSA records on a test grid, with declarations, observations, a declared flow and fedramp_20x_vdr's seeded rule rows. Its vulnerability nodes start bare and vuln_mosaic's own `enrich_grid` fills them through the grid, from real CVE List and GitHub advisory records and illustrative KEV and EPSS catalogs, running as the collector actor as vuln_mosaic's collector does. The fixture then runs all four Searches and the fedramp_20x_vdr bridge. vuln_mosaic is not a dependency of this plugin, so the tests skip in this plugin's own CI record and run in a session that composes both; a skip does not satisfy the method's definition of done.

#### Implementation

`tests/cve_grid.py`, `tests/test_grid_cve.py`; data in `tests/fixtures/cve_grid/`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-aydlette-vdr-grid-1 | Enrichment fills bare advisory records | Implemented | CVSS from the record's ADP or CNA container, KEV, EPSS and SSVC land on the bare vulnerability nodes; a fresh catalog's "not listed" is recorded; a GHSA gets no KEV answer. vuln_mosaic reports every node patched and none failed. | `test_enrichment_fills_the_bare_advisory_records` |
| req-aydlette-vdr-grid-2 | Each factor is decided by the feed that holds it | Implemented | KEV decides LEV first; EPSS is compared with θ; the record's vector is used and named. | `test_each_factor_is_decided_by_the_feed_that_holds_it` |
| req-aydlette-vdr-grid-3 | What no feed holds takes the worst case | Implemented | No EPSS score, no record and no carrier each take their fail-safe on the grid. | `test_what_no_feed_holds_takes_the_worst_case` |
| req-aydlette-vdr-grid-4 | The overlay reads Vulnrichment | Implemented | With the SSVC overlay on, technical impact comes from the record's SSVC; KEV still decides first. | `test_the_overlay_reads_vulnrichment_and_is_named` |
| req-aydlette-vdr-grid-5 | Reconciliation on the grid | Implemented | Declared components reconcile with their observations; an undeclared carrier is not a reconciled component. | `test_reconciliation_on_the_grid` |
| req-aydlette-vdr-grid-6 | Coverage counts what the feeds hold | Implemented | The advisory and check rows count the enriched records, and missing items are named. | `test_coverage_counts_what_the_feeds_hold` |
| req-aydlette-vdr-grid-7 | The bridge backs only reconciled unreachability | Implemented | The evaluations import into fedramp_20x_vdr; `backed_factors` reads internet_reachable = false only where reconciliation backs it, and never backs LEV. | `test_the_bridge_backs_only_reconciled_unreachability` |
| req-aydlette-vdr-grid-8 | With nothing backed the floor decides | Implemented | CVE-2019-9514 (HTTP/2 Reset Flood), enriched by vuln_mosaic onto a reachable component with no authenticated-ingress answer, or with one that found an unauthenticated route, is LEV by the FRD-LEV floor, and its environmental vector is the Base vector. | `test_with_nothing_backed_the_floor_decides_the_reset_flood`, `test_an_unauthenticated_route_backs_nothing` (grid) |
| req-aydlette-vdr-grid-9 | Authenticated ingress on the grid | Implemented | The same finding with an observation that every route requires authentication takes Modified Privileges Required Low, and its illustrative prediction below θ makes it NLEV; the reconciliation Search shows the backing. | `test_authenticated_ingress_lowers_privileges_and_the_prediction_decides` (grid) |

## Paper Coverage

Every requirement in Appendix A and every test in Appendix B, and where this spec holds it. Generated from the requirement tables above; the counts are the method's progress bar.

| Appendix B tests | Count |
| --- | ---: |
| Implemented | 46 |
| In Development | 2 |
| Proposed | 3 |
| Backlog | 23 |
| Total | 74 |

| Test | Acceptance criteria |
| --- | --- |
| T1 | req-aydlette-vdr-reconcile-1 (Implemented) |
| T2 | req-aydlette-vdr-reconcile-2 (Implemented) |
| T3 | req-aydlette-vdr-reconcile-3 (Implemented) |
| T4 | req-aydlette-vdr-reconcile-4 (Implemented) |
| T5 | req-aydlette-vdr-reconcile-5 (Implemented) |
| T6 | req-aydlette-vdr-declarations-1 (Implemented) |
| T7 | req-aydlette-vdr-irv-1 (Implemented) |
| T8 | req-aydlette-vdr-lev-1 (Implemented) |
| T9 | req-aydlette-vdr-lev-2 (Implemented) |
| T10 | req-aydlette-vdr-gates-1 (Implemented) |
| T11 | req-aydlette-vdr-gates-3 (Implemented) |
| T12 | req-aydlette-vdr-dispositions-1 (Implemented) |
| T13 | req-aydlette-vdr-dispositions-1 (Implemented) |
| T14 | req-aydlette-vdr-clock-1 (Implemented) |
| T15 | req-aydlette-vdr-pain-1 (Implemented) |
| T16 | req-aydlette-vdr-dispositions-2 (Implemented) |
| T17 | req-aydlette-vdr-gates-4 (Backlog) |
| T18 | req-aydlette-vdr-governance-1 (Implemented) |
| T19 | req-aydlette-vdr-rules-1 (Implemented) |
| T20 | req-aydlette-vdr-gates-4 (Backlog) |
| T21 | req-aydlette-vdr-gates-5 (Backlog) |
| T22 | req-aydlette-vdr-dispositions-6 (Proposed) |
| T23 | req-aydlette-vdr-dispositions-3 (Implemented) |
| T24 | req-aydlette-vdr-dispositions-7 (Backlog) |
| T25 | req-aydlette-vdr-dispositions-8 (Backlog) |
| T26 | req-aydlette-vdr-publication-2 (In Development) |
| T27 | req-aydlette-vdr-reconcile-6 (Implemented) |
| T28 | req-aydlette-vdr-lev-5 (Implemented) |
| T29 | req-aydlette-vdr-sources-3 (Backlog) |
| T30 | req-aydlette-vdr-sources-4 (Backlog) |
| T31 | req-aydlette-vdr-sources-5 (Backlog) |
| T32 | req-aydlette-vdr-sources-1 (Implemented) |
| T33 | req-aydlette-vdr-sources-6 (Backlog) |
| T34 | req-aydlette-vdr-clock-2 (Implemented) |
| T35 | req-aydlette-vdr-clock-3 (Implemented) |
| T36 | req-aydlette-vdr-clock-4 (In Development) |
| T37 | req-aydlette-vdr-declarations-7 (Backlog) |
| T38 | req-aydlette-vdr-irv-2 (Implemented) |
| T39 | req-aydlette-vdr-reconcile-7 (Implemented) |
| T40 | req-aydlette-vdr-irv-3 (Implemented); req-aydlette-vdr-irv-4 (Backlog) |
| T41 | req-aydlette-vdr-irv-6 (Backlog) |
| T42 | req-aydlette-vdr-reconcile-9 (Implemented) |
| T43 | req-aydlette-vdr-declarations-2 (Implemented) |
| T44 | req-aydlette-vdr-declarations-3 (Implemented) |
| T45 | req-aydlette-vdr-reconcile-10 (Implemented) |
| T46 | req-aydlette-vdr-reconcile-11 (Implemented) |
| T47 | req-aydlette-vdr-reconcile-12 (Implemented) |
| T48 | req-aydlette-vdr-pain-2 (Implemented) |
| T49 | req-aydlette-vdr-lev-8 (Backlog) |
| T50 | req-aydlette-vdr-lev-9 (Backlog) |
| T51 | req-aydlette-vdr-gates-6 (Backlog) |
| T52 | req-aydlette-vdr-gates-7 (Backlog) |
| T53 | req-aydlette-vdr-gates-8 (Backlog) |
| T54 | req-aydlette-vdr-declarations-4 (Implemented) |
| T55 | req-aydlette-vdr-lev-10 (Implemented) |
| T56 | req-aydlette-vdr-lev-11 (Implemented) |
| T57 | req-aydlette-vdr-lev-12 (Implemented) |
| T58 | req-aydlette-vdr-lev-13 (Implemented) |
| T59 | req-aydlette-vdr-lev-14 (Implemented) |
| T60 | req-aydlette-vdr-lev-15 (Backlog) |
| T61 | req-aydlette-vdr-pain-3 (Implemented) |
| T62 | req-aydlette-vdr-pain-4 (Implemented) |
| T63 | req-aydlette-vdr-declarations-5 (Implemented) |
| T64 | req-aydlette-vdr-third-party-1 (Backlog) |
| T65 | req-aydlette-vdr-third-party-2 (Backlog) |
| T66 | req-aydlette-vdr-third-party-3 (Backlog) |
| T67 | req-aydlette-vdr-governance-4 (Backlog) |
| T68 | req-aydlette-vdr-governance-2 (Implemented) |
| T69 | req-aydlette-vdr-dispositions-5 (Implemented) |
| T70 | req-aydlette-vdr-dispositions-5 (Implemented) |
| T71 | req-aydlette-vdr-dispositions-9 (Proposed) |
| T72 | req-aydlette-vdr-gates-9 (Proposed) |
| T73 | req-aydlette-vdr-publication-3 (Backlog) |
| T74 | req-aydlette-vdr-publication-4 (Backlog) |

| Requirement | RID |
| --- | --- |
| REQ-RUL-1 | req-aydlette-vdr-rules |
| REQ-RUL-2 | req-aydlette-vdr-rules |
| REQ-SRC-1 | req-aydlette-vdr-sources |
| REQ-SRC-2 | req-aydlette-vdr-sources |
| REQ-SRC-3 | req-aydlette-vdr-sources |
| REQ-SRC-4 | req-aydlette-vdr-sources |
| REQ-SRC-5 | req-aydlette-vdr-sources |
| REQ-IRV-1 | req-aydlette-vdr-declarations |
| REQ-IRV-2 | req-aydlette-vdr-reconcile |
| REQ-IRV-3 | req-aydlette-vdr-reconcile |
| REQ-IRV-4 | req-aydlette-vdr-reconcile |
| REQ-IRV-5 | req-aydlette-vdr-irv |
| REQ-IRV-6 | req-aydlette-vdr-irv |
| REQ-IRV-7 | req-aydlette-vdr-declarations |
| REQ-IRV-8 | req-aydlette-vdr-reconcile |
| REQ-IRV-9 | req-aydlette-vdr-irv |
| REQ-IRV-10 | req-aydlette-vdr-irv |
| REQ-IRV-11 | req-aydlette-vdr-reconcile |
| REQ-IRV-12 | req-aydlette-vdr-irv |
| REQ-IRV-13 | req-aydlette-vdr-declarations |
| REQ-LEV-1 | req-aydlette-vdr-lev |
| REQ-LEV-2 | req-aydlette-vdr-lev |
| REQ-LEV-3 | req-aydlette-vdr-lev |
| REQ-LEV-4 | req-aydlette-vdr-lev |
| REQ-LEV-5 | req-aydlette-vdr-lev |
| REQ-LEV-6 | req-aydlette-vdr-lev |
| REQ-LEV-7 | req-aydlette-vdr-lev |
| REQ-LEV-8 | req-aydlette-vdr-lev |
| REQ-PAI-1 | req-aydlette-vdr-pain |
| REQ-PAI-2 | req-aydlette-vdr-pain |
| REQ-PAI-3 | req-aydlette-vdr-declarations |
| REQ-PAI-4 | req-aydlette-vdr-pain |
| REQ-PAI-5 | req-aydlette-vdr-reconcile |
| REQ-PAI-6 | req-aydlette-vdr-pain |
| REQ-PAI-7 | req-aydlette-vdr-pain |
| REQ-TPR-1 | req-aydlette-vdr-third-party |
| REQ-TPR-2 | req-aydlette-vdr-third-party |
| REQ-TPR-3 | req-aydlette-vdr-third-party |
| REQ-TPR-4 | req-aydlette-vdr-third-party |
| REQ-TPR-5 | req-aydlette-vdr-third-party |
| REQ-DLN-1 | req-aydlette-vdr-clock |
| REQ-DLN-2 | req-aydlette-vdr-clock |
| REQ-DLN-3 | req-aydlette-vdr-clock |
| REQ-DSP-1 | req-aydlette-vdr-dispositions |
| REQ-DSP-2 | req-aydlette-vdr-dispositions |
| REQ-DSP-3 | req-aydlette-vdr-dispositions |
| REQ-DSP-4 | req-aydlette-vdr-dispositions |
| REQ-DSP-5 | req-aydlette-vdr-dispositions |
| REQ-MIT-1 | req-aydlette-vdr-dispositions |
| REQ-MIT-2 | req-aydlette-vdr-dispositions |
| REQ-VD-1 | req-aydlette-vdr-dispositions |
| REQ-VD-2 | req-aydlette-vdr-dispositions |
| REQ-GAT-1 | req-aydlette-vdr-gates |
| REQ-GAT-2 | req-aydlette-vdr-gates |
| REQ-GAT-3 | req-aydlette-vdr-gates |
| REQ-GAT-4 | req-aydlette-vdr-gates |
| REQ-GAT-5 | req-aydlette-vdr-gates |
| REQ-GOV-1 | req-aydlette-vdr-governance |
| REQ-GOV-2 | req-aydlette-vdr-governance |
| REQ-PUB-1 | req-aydlette-vdr-publication |
| REQ-PUB-2 | req-aydlette-vdr-publication |
| REQ-PUB-3 | req-aydlette-vdr-publication |
| REQ-PUB-4 | req-aydlette-vdr-publication |
| REQ-PUB-5 | req-aydlette-vdr-publication |
| REQ-ASR-1 | req-aydlette-vdr-publication |
| REQ-QUE-1 | req-aydlette-vdr-publication |

## Future

- Publish the SSVC source and time per finding (T60), the smallest open gap in the overlay.
- Disposition selectors (T49, T50), artifact identity for narrowing (T40), and control change detection (T24, T25).
- Gate modes and team ownership (T21, T51, T53), once a provider needs them.
