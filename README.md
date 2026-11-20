# aydlette-vdr-tap

A TAP plugin that implements the method in
[Vulnerability Evidence as a Product](https://samaydlette.com/research/vulnerability-evidence.html) (Sam Aydlette,
2026-10-23) for FedRAMP VDR: each open finding's reachability (IRV), likely exploitability (LEV), Potential Agency Impact
N-rating (PAIN), clock and gates. Every decision comes with the basis a reader can check by hand.

A provider brings its facts as nodes on the grid. The method reads them, applies the provider's governed
profile and writes nothing back.

| Node | What it says | Points at |
|---|---|---|
| `aydlette_vdr__declaration` | Exposure intent (public-edge, public-backed, internal) with a rationale; data class (public, internal, PII, CUI); Mission Critical; agency scope; who classified the data | any node: the component (`DECLARES_COMPONENT`, a wildcard edge) |
| `aydlette_vdr__observation` | One observer's latest answer for a component: is there a path from the internet (`internet-path`), or a flow from another component (`flow`); inside-out, outside-in or telemetry; when; on what evidence | the component (`OBSERVES_COMPONENT`) and, for a flow, its sender (`OBSERVES_SENDER`); both wildcards |
| `aydlette_vdr__declared_flow` | A flow the owner declared and the data flags it carries, or why it is metadata only (REQ-PAI-5) | its two components (`FLOW_SOURCE`, `FLOW_TARGET`) |
| `aydlette_vdr__finding_facts` | Scanner severity and access data, SSVC values and their source, fix state, deployed version, first evaluation | one finding (`DESCRIBES_FINDING`) |
| `aydlette_vdr__disposition` | False positive, fully or partially mitigated (names a control), narrowing, deflection (tested), LEV override, vendor dependency, risk accepted, operational requirement; decided_by, decided_on, review_by | the findings it covers (`DISPOSES_FINDING`) |
| `aydlette_vdr__check_vector` | A governed CVSS vector for a configuration check with none, decided by a named person and reviewed by a date | the check's vulnerability record, by `vuln_id` |
| `aydlette_vdr__profile` | The governed choices: θ and its rationale, the combining function, the needs map, the tables, the severity fallback, the SSVC overlay | — |

Findings, vulnerability records (CVSS, KEV, EPSS, SSVC) and `CARRIES_COMPLIANCE_FINDING` come from `compliance_core`.
Timeframes and the maximum overdue period come from `fedramp_20x_vdr`'s seeded rule rows, never from this code
(REQ-RUL-1).

The core never asks how an observation was made. An adapter turns a platform's facts into these nodes; for AWS that is
[aydlette-vdr-aws-tap](../aydlette-vdr-aws-tap), which reads aws_core's nodes.

## Reconciliation (Figure 6)

Before any finding is evaluated, each declared component's intent is reconciled with fresh observations
(`method/reconcile.py`):

| Declared | Path observed | No path observed |
|---|---|---|
| internal | undeclared exposure: G4, findings IRV, no disposition closes it | consistent |
| public-edge | consistent | over-declared: queued, findings stay IRV |
| public-backed | undeclared exposure: a backed component has no direct path (G4) | consistent if a declared flow from a public component feeds it; otherwise over-declared |

Flows: an undeclared observed flow from a public component into an internal one is undeclared exposure (REQ-IRV-8);
other undeclared flows are queued, and the receiver inherits the sender's data flags until someone decides (T47). A
declared flow that carries a flag the receiver lacks, or states neither its contents nor a metadata reason, fails G5.
Observers must have looked within `observer_freshness_hours` (at most 24): inside-out for every component, outside-in
too for public-edge ones, or G7 fails.

## Searches

* `aydlette-pain` (`fedramp_class` is required; `profile_id` defaults to `aydlette-starter`): one row per open finding,
  including configuration and DAST findings, which need no CVE. Each row gives the component and how the finding was
  resolved to it, IRV, LEV and PAIN with their bases, the three values behind the rating (need met, technical impact,
  scope), the dispositions and whether each is in force, the clock (start, due, accept-by, state), gates G1 to G5 and G7,
  decision
  queue items, and the prediction feed.
* `aydlette-reconcile`: one row per declared component: declared intent, what the observers saw, the Figure 6 cell, G4,
  G5, G7, queue items, whether it is publicly exposed, and the intent the observations alone suggest (never used as a
  declaration).
* `aydlette-summary`: the same evaluation, aggregated: counts by rating, column, group and state, the gates, the decision
  queue with its rates (REQ-QUE-1), and the number of findings the public tier withholds (REQ-PUB-4).
* `aydlette-coverage`: whether the environment gives the method what it needs. Without a prerequisite the method takes
  the worst case, fails a gate or queues a decision. Its answer is still correct, but pessimistic. One row per
  prerequisite gives what it applies to, how much has it, the items missing it, and what the method does without it:
  * **declarations:** declared; intent, data, agency scope; who classified the data and who judged Mission Critical;
    no contradictions.
  * **observers:** fresh inside-out and outside-in observations; no undeclared exposure.
  * **flows:** public-backed components fed by a declared flow; observed flows that are declared; flows that state what
    they carry.
  * **findings:** resolved to a component, and IRV, LEV, impact and needs decided on evidence rather than a fail-safe.
  * **advisories:** for CVE, GHSA and other advisory IDs, the CVSS vector, KEV status, EPSS and SSVC. These are the
    fields vuln_mosaic fills from NVD, KEV, EPSS and CISA Vulnrichment.
  * **checks:** for Checkov, ZAP and other check IDs, a CVSS vector, from the record or a governed check vector.

  The inventory is every node an observer looked at, a declaration names, or an open finding is carried by. The adapter
  decides what is in scope by what it observes, so the Search needs no platform knowledge (`method/coverage.py`).

Every output carries the profile's id, version, sha256 and deviations from the global defaults (REQ-GOV-1, REQ-PAI-4),
along with where the timeframes came from (REQ-RUL-2).

## fedramp_20x_vdr evaluations

One collector, `aydlette_vdr:vdr_evaluations`, puts this method on the same grid as VDR-max and other methods. Run it
after the observers. It writes one `fedramp_20x_vdr__vdr_evaluation` per open finding with scheme `aydlette`:

* `internet_reachable` and `likely_exploitable` are this method's IRV and LEV. Several CVEs on one finding combine to the
  worst.
* `pain` stays null, because fedramp_20x_vdr v0 refuses a value. The rating and the bases of all three are in
  `rationale`.
* `evaluator` names the governed profile and its digest. The profile is `aydlette-starter` unless
  `AYDLETTE_VDR_PROFILE` names another.

Other methods read a factor as the worst case unless evidence backs it. This collector backs only one thing:
`internet_reachable = false`, with basis `protected_at_perimeter`, when the component is declared internal, Figure 6
finds it consistent, a fresh observation found no path, and G4, G5 and G7 pass. The evidence node
(`compliance_evidence`, source `aydlette_vdr`, key `reconcile:<component>`) lists the observations. LEV false,
narrowing and deflection are recorded but not backed: none of them is one of the nine CycloneDX justifications.
stackarmor_vdr reads these evaluations with `evaluation_scheme: aydlette`.

## stackArmor's worked examples

`combining = "cvss_environmental"` runs stackArmor's rating as a published deviation. `tests/test_stackarmor_examples.py`
encodes the memo's weights and boundaries as a profile, with `isc_cap` set to the memo's D_H and the U boundaries
divided by D_H. All five worked examples give the memo's N-levels. Exact boundaries can be written as decimal
strings: example 5 sits exactly on U = 0.28.

The two methods still differ in two places, and the tests show both:

* An unresolved finding here takes the fail-safe classification (HHH needs, multi-agency). stackArmor rates it at the
  container's or archetype's profile.
* With the SSVC overlay on, a CISA Technical Impact of total that the vector does not show scores every affected
  property High. stackArmor reads only the vector. C:H/I:L/A:L at HHH, single agency, is N3 there and N4 here.

Examples 4 and 5 use requirement vectors (MMH, LMM) that the default needs map cannot produce. On a grid they need a
profile whose needs map does.

## Profiles

One profile is seeded. Copy it under your own `profile_id` and govern it.

* `aydlette-starter`: the method's global defaults (the decision-table combining function, the needs map, the effect and
  scale tables, the severity fallback to technical impact, no SSVC overlay). It sets θ = 0.10 only so that it runs. The
  method gives θ no default (REQ-LEV-2), and the rationale says so.

A profile is refused (the Search fails) when θ or its rationale is missing, when it enables half of the SSVC overlay
(T68), or when its scale mapping does not cover every level the rules publish (T19).

## Layout

* `tap_plugin/aydlette_vdr/method/`: the method, pure Python with no TAP or Django import. A provider can run it outside
  TAP.
* `tests/test_conformance.py`: the Appendix B conformance tests the method decides on its own (T1, T4, T6 to T16, T18,
  T19, T23, T28, T32, T34, T35, T38, T40, T43, T44, T48, T54 to T58, T61 to T63, T68 to T70, and the paper's HTTP/2
  scenario). Run them with
  `uv run --no-project --python 3.14 --with pytest python -m pytest tap_plugin/aydlette_vdr/tests/test_conformance.py`.
* `models/`, `edges/`, `grift/`, `searches/`: the TAP layer.

## Not in v0.1

* Observers themselves: the core reads observations; adapters make them (aydlette-vdr-aws-tap has inside-out and outside-in).
* G6, the build side of G7 (stale scanner databases, missing feeds), signing, two-tier publication, run records, and the decision queue as a published product. These belong to
  the pipeline.
* Template inheritance (REQ-IRV-7) beyond what an adapter groups, third-party linked findings (REQ-TPR) and rating
  history (REQ-PAI-2).
* Panels.

## Specification and contributing

[`specs/spec-aydlette-vdr-v0.md`](specs/spec-aydlette-vdr-v0.md) maps every requirement to the code and the test that proves it, including each of the paper's Appendix B conformance tests. Its Paper Coverage table shows how many are implemented. [`CONTRIBUTING.md`](CONTRIBUTING.md) defines when a change, a release and the method are done.

## How this was made

Code and tests written with Claude Code (Claude Opus 5.5); method, design decisions and review by Sam Aydlette.

## License

Code: [Apache-2.0](LICENSE). Documentation, including the method's tables restated here:
[CC BY 4.0](LICENSES/CC-BY-4.0.txt). Use it freely, with attribution to Sam Aydlette,
[Vulnerability Evidence as a Product](https://samaydlette.com/research/vulnerability-evidence.html). See [NOTICE](NOTICE).
