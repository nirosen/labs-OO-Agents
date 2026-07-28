<div align="center">

<br />

<picture>
  <source
    media="(prefers-color-scheme: dark)"
    srcset="assets/nvidia-labs-object-oriented-agents-dark.svg"
  >
  <source
    media="(prefers-color-scheme: light)"
    srcset="assets/nvidia-labs-object-oriented-agents-light.svg"
  >
  <img
    alt="NVIDIA-labs Object Oriented Agents"
    src="assets/nvidia-labs-object-oriented-agents-light.svg"
    width="820"
  >
</picture>

<p align="center"><b>A Pythonic way to build AI agents.</b></p>

[![NVIDIA](https://img.shields.io/badge/NVIDIA-76B900?logo=nvidia&logoColor=white)](https://www.nvidia.com/)
[![Paper](https://img.shields.io/badge/paper-arXiv-b31b1b?logo=arxiv&logoColor=white)](https://arxiv.org/abs/2607.20709)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**[Quick Start](#quick-start)** &nbsp;·&nbsp; **[Examples](examples/README.md)** &nbsp;·&nbsp; **[Paper](https://arxiv.org/abs/2607.20709)**

<br />

</div>


NVIDIA-labs OO Agents (NOOA) is a model-agnostic Python framework designed to support reliable AI agent development. Many agent frameworks represent prompts, tools, callbacks, and workflows as separate abstractions. NOOA offers an alternative object-oriented interface that brings these concepts together in a Python class. NOOA lets developers express an agent’s state, capabilities, prompts, and typed interfaces through a single Python class:

```python
from nooa import Agent

# The agent is a Python object.
class SupportAgent(Agent):
    """You are a support agent."""

    # State lives on the object. Fields are typed.
    order_db: OrderDB

    # Ordinary method. Just Python.
    def is_refund_eligible(self, order: Order) -> bool:
        return order.delivered and order.days_since_delivery <= 30

    # Agentic method: the runtime hands this to an LLM.
    async def triage(self, message: str, order: Order) -> Ticket:
        """Create a typed support ticket."""
        ...
```

**What's happening here:**

- **Agents are Python objects.** Fields are state, methods are capabilities, docstrings are prompts, type annotations are contracts.
- **`...` bodies are LLM-driven.** A method with `...` becomes an agentic loop; a real body stays deterministic Python. 
- **Code as action.** The model acts by writing Python in a Jupyter-style REPL with access to `self`, imports, and helpers — Python methods and type annotations supply the callable interfaces, reducing the need to write separate tool-schema definitions.
- **Pythonic and agent-ready.** Typed I/O with auto-retry, live-object arguments passed by reference, and model-callable context and event APIs — designed around agent-oriented Python workflows.

This design supports familiar Python testing, tracing, refactoring, and version-control workflows — **just like the rest of your software**. Read the paper for the design principles and evaluation results: [NVIDIA OO Agents: Native Python Object-Oriented Agents](https://arxiv.org/abs/2607.20709).

## Security Review Follow-On: Receipt Source Alignment

> Branch: `codex/security-receipt-source-alignment`

This slice adds one opt-in public helper for a narrow receipt-coherence question: whether every supplied `SecurityReceipt.source` value exactly matches one caller-selected `expected_source`. The identity-approval detector path now runs that helper after receipt-ID uniqueness and before receipt scope or profile policy. The new `mislabel_receipt_source` authority fault rewrites one transported row source while keeping the bundle count coherent, so the refusal isolates source-label drift from transport completeness and run-scope diagnostics.

```mermaid
flowchart LR
    B["complete ReceiptBundle rows"] --> I["validate_receipt_id_uniqueness()"]
    I --> A["validate_receipt_source_alignment()"]
    A -- "exact source match" --> S["validate_receipt_scope()"]
    S --> P["profile scorer"]
    A -. "receipt_source_mismatch" .-> X["scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `ReceiptSourceAlignmentValidation`, `ReceiptSourceAlignmentSignal`, `ReceiptSourceAlignmentError`, canonical `RECEIPT_SOURCE_ALIGNMENT_SIGNALS`, `validate_receipt_source_alignment()`, `require_valid_receipt_source_alignment()`, `receipt_source_alignment_signals()`, example-local `receipt_source_alignment_gated_scorer()`, and `mislabel_receipt_source` authority fault |
| Security claim | Applications can opt into a fail-closed exact string check for one supplied receipt iterable, and the example detector refuses a visibly mislabeled receipt row after receipt-ID uniqueness and before receipt scope or profile policy runs. |
| Non-claim | A clean result means only that every supplied receipt carried a `source` exactly equal to one caller-supplied `expected_source`. Both the row `source` values and the expected value are producer-controlled, so agreement between them is coherence, not provenance: a fully consistent bundle can still be fabricated. It does not authenticate receipts, sources, or the expected value; prove that the receipts originated from the named source; establish alignment across bundles, runs, or sources; dereference or correlate source labels against any external system; prove receipt coverage or that omitted receipts do not exist; or make the same-user authority subprocess a trust boundary. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v14` |
| Review files | `src/nooa/security/receipts.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/approval_authority.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_receipts.py`, `tests/security/test_approval_authority.py`, `tests/security/test_detector_harness.py`, `tests/security/test_surface_guide.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipts.py tests/security/test_approval_authority.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/receipts.py examples/security_hardening/approval_authority.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Receipt ID Uniqueness Validation

> Branch: `codex/security-receipt-id-uniqueness`

This slice adds one opt-in public helper for an intrinsic property of supplied receipt rows: whether one materialized iterable reuses a `receipt_id`. The identity-approval detector path now runs that helper after receipt-bundle completeness passes and before receipt scope or profile policy runs. The new `duplicate_receipt_id` authority fault writes two copies with one repeated ID while keeping the bundle count coherent, so the refusal proves the uniqueness gate is independent of transport completeness and run-scope diagnostics.

```mermaid
flowchart LR
    B["complete ReceiptBundle rows"] --> I["validate_receipt_id_uniqueness()"]
    I -- "distinct receipt_id values" --> S["validate_receipt_scope()"]
    S --> P["profile scorer"]
    I -. "duplicate_receipt_id" .-> X["scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `ReceiptIdUniquenessValidation`, `ReceiptIdUniquenessSignal`, `ReceiptIdUniquenessError`, canonical `RECEIPT_ID_UNIQUENESS_SIGNALS`, `validate_receipt_id_uniqueness()`, `require_valid_receipt_id_uniqueness()`, `receipt_id_uniqueness_signals()`, example-local `receipt_id_uniqueness_gated_scorer()`, and `duplicate_receipt_id` authority fault |
| Security claim | Applications can opt into a fail-closed check that one supplied receipt iterable does not reuse a `receipt_id`, and the example detector refuses a duplicate-ID receipt bundle before receipt scope or profile policy runs. |
| Non-claim | A clean uniqueness result means only that no two supplied receipts in one materialized iterable shared a `receipt_id`. It does not authenticate receipts, sources, or identifiers; prove that distinct identifiers denote distinct receipts, or that a duplicate identifier denotes a dishonest collector rather than a construction bug; establish uniqueness across bundles, runs, or sources; dereference or correlate identifiers against any external system; prove receipt coverage or that omitted receipts do not exist; or make the same-user authority subprocess a trust boundary. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v13` |
| Review files | `src/nooa/security/receipts.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/approval_authority.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_receipts.py`, `tests/security/test_approval_authority.py`, `tests/security/test_detector_harness.py`, `tests/security/test_surface_guide.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipts.py tests/security/test_approval_authority.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/receipts.py examples/security_hardening/approval_authority.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Finding Required Evidence Ref

> Branch: `codex/security-finding-required-evidence-ref`

This slice adds one opt-in public helper for a narrow finding-consumer question: whether every supplied `SecurityFinding` row contains one caller-selected exact `required_evidence_ref`. The example supervisor uses that helper after finding scope, report coherence, and ID uniqueness have passed, with its independently selected `input_id` as the required ref. The same slice also closes the earlier metadata gap by refusing a detector report whose echoed `detector_input_id` does not match that supervisor-selected value before finding admission begins.

```mermaid
flowchart LR
    S["supervisor-selected input_id"] --> R["detector report input ID gate"]
    R --> V["validate_finding_required_evidence_ref()"]
    F["admitted FindingBundle rows"] --> V
    V -- "required ref present" --> A["DetectedScenario.findings"]
    V -. "missing_required_evidence_ref" .-> X["scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `FindingRequiredEvidenceRefValidation`, `FindingRequiredEvidenceRefSignal`, `FindingRequiredEvidenceRefError`, canonical `FINDING_REQUIRED_EVIDENCE_REF_SIGNALS`, `validate_finding_required_evidence_ref()`, `require_valid_finding_required_evidence_ref()`, `finding_required_evidence_ref_signals()`, supervisor report `detector_input_id` admission, example-local `drop_required_evidence_ref`, and a final required-ref finding-admission stage |
| Security claim | Applications can opt into an exact presence check for one caller-selected finding evidence ref, and the example supervisor refuses both visible detector-report input-ID drift and admitted finding rows that omit its selected `input_id` after existing scope, coherence, and uniqueness gates pass. |
| Non-claim | Presence is not provenance. This does not authenticate findings, reports, scorers, evidence IDs, or the required ref; prove that the cited ref resolves to anything real or supports a finding; require any other evidence; prove detector coverage; or stop a detector that simply echoes the supervisor-supplied `input_id`. Refusal text includes raw identifiers that a deployment may need to redact. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v12` |
| Review files | `src/nooa/security/findings.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_findings.py`, `tests/security/test_detector_harness.py`, `tests/security/test_surface_guide.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_findings.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/findings.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Finding Evidence-Ref Membership

> Branch: `codex/security-finding-evidence-ref-membership`

This slice adds one opt-in public helper for a narrow scorer-conformance question: whether each supplied `SecurityFinding.evidence_refs` value appears in one caller-supplied `allowed_evidence_ids` iterable. The example harness wraps each profile scorer inside the detector process, builds that allowed set from the current `DetectorInput.input_id`, effect IDs, and receipt IDs, and refuses scorer output that invents a reference before it emits the finding bundle.

```mermaid
flowchart LR
    D["DetectorInput IDs"] --> V["validate_finding_evidence_ref_membership()"]
    F["scorer SecurityFinding rows"] --> V
    V -- "all refs in supplied set" --> B["FindingBundle"]
    V -. "unknown_evidence_ref" .-> X["detector-side refusal"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `FindingEvidenceRefValidation`, `FindingEvidenceRefSignal`, `FindingEvidenceRefError`, canonical `FINDING_EVIDENCE_REF_SIGNALS`, `validate_finding_evidence_ref_membership()`, `require_valid_finding_evidence_ref_membership()`, `finding_evidence_ref_signals()`, and example-local `evidence_ref_membership_gated_scorer()` |
| Security claim | Applications can opt into an exact membership check that supplied finding references stay within one caller-supplied ID set, and the example detector refuses a scorer that cites an ID outside the current `DetectorInput` before bundle emission. |
| Non-claim | This does not authenticate findings, scorers, evidence IDs, or the allowed set; dereference evidence; prove that present references support a finding; require any evidence ref to exist; prove detector coverage; enforce a supervisor-selected required ref; normalize case, whitespace, or Unicode; or survive a hostile detector process that bypasses the wrapper. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v11` |
| Review files | `src/nooa/security/findings.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_findings.py`, `tests/security/test_detector_harness.py`, `tests/security/test_surface_guide.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_findings.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/findings.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Finding Admission Diagnostics

> Branch: `codex/security-finding-admission-diagnostics`

This slice adds no public `nooa.security` API. It gives the example-local `DetectorReport` one supervisor-owned `finding_admission_refusal` field so current finding-admission failures can be distinguished without parsing human-readable refusal text. Report admission clears any child-supplied value first; only the supervisor's count, scope, refused-report-row, and ID-uniqueness gates set the field.

```mermaid
flowchart LR
    B["complete FindingBundle"] --> C["count gate"]
    C --> S["scope gate"]
    S --> R["report coherence gate"]
    R --> U["ID uniqueness gate"]
    C -. "count_mismatch" .-> F["DetectorReport.finding_admission_refusal"]
    S -. "scope_drift" .-> F
    R -. "refused_report_rows" .-> F
    U -. "duplicate_finding_id" .-> F
```

| Review item | Detail |
| --- | --- |
| Adds | Example-local `FindingAdmissionRefusal`, `DetectorReport.finding_admission_refusal`, supervisor-side clearing of child-supplied values, and structured refusal-stage coverage for the existing finding count, scope, refused-report-row, and ID-uniqueness gates |
| Security claim | Consumers of this example report can identify which current supervisor finding-admission stage refused rows without parsing the free-form `refusal_reason` string. |
| Non-claim | The field is not a public NOOA schema, detector verdict, trust boundary, or evidence-reference validator. It does not authenticate reports, findings, producers, identifiers, or refusal text; add a new finding gate; prove detector coverage; or make a same-user child process trustworthy. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v10` |
| Review files | `examples/security_hardening/detector_harness.py`, `tests/security/test_detector_harness.py`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_detector_harness.py`; `pytest tests/security`; `ruff check examples/security_hardening tests/security`; `pyright examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Finding ID Uniqueness Validation

> Branch: `codex/security-finding-id-uniqueness`

This slice adds one opt-in public helper for an intrinsic property of supplied finding rows: whether one materialized iterable reuses a `finding_id`. The example supervisor now runs that gate after it has admitted a complete, count-coherent, scope-clean, report-coherent finding bundle and before it exposes rows on `DetectedScenario.findings`. Existing scope and report-coherence refusals retain precedence; ID uniqueness runs only after those checks pass. The new `duplicate_finding_id` fault keeps `declared_finding_count` coherent at `2`, so the refusal proves the uniqueness gate is independent of bundle completeness, count, and run-scope diagnostics.

```mermaid
flowchart LR
    B["admitted FindingBundle rows"] --> S["validate_finding_scope()"]
    S -- "scope clean" --> I["validate_finding_id_uniqueness()"]
    I -- "distinct finding_id values" --> A["DetectedScenario.findings"]
    I -. "duplicate_finding_id" .-> X["scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `FindingIdUniquenessValidation`, `FindingIdUniquenessSignal`, `FindingIdUniquenessError`, canonical `FINDING_ID_UNIQUENESS_SIGNALS`, `validate_finding_id_uniqueness()`, `require_valid_finding_id_uniqueness()`, `finding_id_uniqueness_signals()`, example-local `duplicate_finding_id` fault, and supervisor-side refusal after existing bundle, scope, and report-coherence gates |
| Security claim | Applications can opt into a fail-closed check that one supplied finding iterable does not reuse a `finding_id`, and the example supervisor refuses a duplicate-ID bundle before downstream scenario consumers accept rows. |
| Non-claim | A clean uniqueness result means only that no two admitted rows in one `FindingBundle` shared a `finding_id`. It does not authenticate rows, producers, or identifiers; prove that distinct identifiers denote distinct findings, or that a duplicate identifier denotes a dishonest producer rather than a scorer bug; establish uniqueness across bundles, runs, or producers; dereference or correlate identifiers against any external system; prove detector coverage or that omitted findings do not exist; or make the same-user detector subprocess a trust boundary. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v9` |
| Review files | `src/nooa/security/findings.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_findings.py`, `tests/security/test_detector_harness.py`, `tests/security/test_surface_guide.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_findings.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/findings.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Receipt Bundle Version Contract

> Branch: `codex/security-receipt-bundle-version-contract`

This slice changes no receipt-bundle parsing behavior. It publishes the version-token rule that `read_receipt_bundle()` already uses to distinguish a malformed `schema_version` from a well-formed future bundle version, then pins that rule in the checked receipt-bundle conformance fixture. Third-party readers no longer need to reverse-engineer a private regex to reproduce the same malformed-vs-unsupported split.

```mermaid
flowchart LR
    V["receipt bundle<br/>schema_version"] --> P["RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN<br/>full token match"]
    P -- "current v1 token" --> R["v1 parser path"]
    P -- "future matching token" --> U["UnsupportedReceiptBundleVersionError"]
    P -. "non-matching token" .-> M["invalid receipt bundle document"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN` and `RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE`; conformance-fixture header assertions for both |
| Security claim | Independent receipt-bundle readers can reproduce NOOA's current version-token classification rule without guessing at private implementation detail. |
| Non-claim | Publishing the pattern does not authenticate bundle bytes, promise support for every matching future token, make unsupported versions safe to parse, or change any receipt-bundle runtime behavior. |
| Base slice | `codex/security-receipt-bundle-conformance-vectors` |
| Review files | `src/nooa/security/receipts.py`, `src/nooa/security/__init__.py`, `tests/security/fixtures/receipt_bundle_conformance_v1.json`, `tests/security/test_receipt_bundle_conformance.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipt_bundle_conformance.py tests/security/test_surface_guide.py`; `pytest tests/security`; `git diff --quiet 5b1a0e9 -- ':(glob)examples/**/*.py'`; `pytest`; `ruff check src/nooa/security tests/security` |

## Security Review Follow-On: Finding Bundle Conformance Vectors

> Branch: `codex/security-finding-bundle-conformance-vectors`

This slice adds no `src/nooa` runtime behavior. It adds checked LF-terminated reference vectors for the public finding-bundle transport introduced in the previous slice. The vectors pin representative `write_finding_bundle()` bytes, then exercise `read_finding_bundle()` across clean, internally spaced, truncated, over-bound, invalid UTF-8, malformed, and version-classified documents so reviewers can catch drift in the new wire contract without mistaking conformance for detector trust.

```mermaid
flowchart LR
    F["finding bundle fixture"] --> W["write_finding_bundle()<br/>exact bytes"]
    F --> R["read_finding_bundle()<br/>selected outcomes"]
    W --> B["LF JSON<br/>key order + UTF-8"]
    R --> S["bundle / signals / errors"]
```

| Review item | Detail |
| --- | --- |
| Adds | `tests/security/fixtures/finding_bundle_conformance_v1.json`, exact-byte writer checks, selected reader-outcome checks, a surface-guide reference, and README guidance |
| Security claim | Reviewers can now detect accidental drift in the current `FindingBundle` writer bytes and selected reader classifications, including visible truncation, bounded admission, strict JSON portability, and the published malformed-vs-unsupported version split. |
| Non-claim | The vectors do not authenticate findings or producers, prove detector coverage, cover every malformed document, make a clean bundle trustworthy, or require independent writers to copy NOOA's exact JSON formatting when they already satisfy the accepted reader contract. |
| Base slice | `codex/security-finding-bundle-handoff` |
| Review files | `tests/security/fixtures/finding_bundle_conformance_v1.json`, `tests/security/test_finding_bundle_conformance.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `README.md` |
| Validation | `pytest tests/security/test_finding_bundle_conformance.py`; `pytest tests/security`; `git diff --quiet b72680e -- src/nooa ':(glob)examples/**/*.py'`; `ruff check tests/security`; `pytest` |

## Security Review Follow-On: Finding Bundle Handoff

> Branch: `codex/security-finding-bundle-handoff`

This slice moves detector findings out of the example-local `DetectorReport` JSON and onto a public `FindingBundle` transport. The detector still emits one stdout report, but that report now carries only `declared_finding_count`; the actual `SecurityFinding` rows are written as one bounded LF-terminated bundle through a dedicated inherited descriptor backed by a supervisor-owned temporary file. The supervisor admits both channels, requires a complete bundle, cross-checks the declared count, validates finding run scope against its selected `run_id`, and only then exposes admitted rows on `DetectedScenario.findings`. When a parsed detector output is refused, the report keeps its detector-declared count as diagnostic metadata while the scenario exposes no admitted rows.

```mermaid
flowchart LR
    S["supervisor-selected run_id"] --> R["report admission<br/>+ report run_id"]
    D["detector subprocess"] --> O["DetectorReport stdout<br/>declared_finding_count"]
    D --> W["write_finding_bundle()<br/>LF-terminated JSON"]
    O --> R
    W --> T["supervisor-owned<br/>temporary file"]
    T --> B["read_finding_bundle()<br/>max_finding_bundle_bytes"]
    R --> C["count + coherence gates"]
    B --> C
    C --> V["validate_finding_scope()"]
    V -- "accepted" --> A["DetectedScenario.findings"]
    B -. "invalid / over-bound / truncated" .-> X["scored=False"]
    C -. "count mismatch / refused report rows" .-> X
    V -. "missing / stale run_id" .-> X
```

| Review item | Detail |
| --- | --- |
| Adds | Public `FindingBundle`, `FindingBundleReadResult`, `FindingBundleIncompleteError`, `FindingBundleInputTooLargeError`, `UnsupportedFindingBundleVersionError`, canonical `FINDING_BUNDLE_COMPLETENESS_SIGNALS`, public finding-bundle version pattern constants, bounded `read_finding_bundle()` / `write_finding_bundle()`, `require_complete_finding_bundle()`, example-local report/schema V4 handoff, `truncate_finding_document` / `drop_finding_count_mismatch`, and `max_finding_bundle_bytes` |
| Security claim | The example supervisor can distinguish one complete LF-terminated finding document from visible truncation, reject count drift between report metadata and finding rows, and refuse off-scope rows before downstream scenario consumers accept them. |
| Non-claim | A clean `FindingBundle` is not a verdict, severity model, enforcement action, detector-coverage proof, finding-id uniqueness guarantee, or evidence-reference validator. An empty clean bundle is not evidence that nothing was found. The bundle-level `producer` assertion does not constrain row-level `SecurityFinding.producer`, and the same-user temporary-file channel is not an authentication, sandboxing, or privilege boundary. |
| Base slice | `codex/security-supervisor-output-admission` |
| Review files | `src/nooa/security/findings.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_findings.py`, `tests/security/test_detector_harness.py`, `tests/security/test_data_export_example.py`, `tests/security/test_joint_readme.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_findings.py tests/security/test_detector_harness.py tests/security/test_data_export_example.py tests/security/test_surface_guide.py tests/security/test_joint_readme.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/findings.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Supervisor Output Admission

> Branch: `codex/security-supervisor-output-admission`

This slice adds no `nooa.security` runtime API. It completes the example supervisor's subprocess-output admission boundary around the existing detector harness: victim summaries, authority summaries, and detector reports now each pass through a bounded parse-admission step after `communicate()` returns. A malformed or over-bound detector report becomes `scored=False`; malformed or over-bound victim/authority summaries become a typed example-local `SupervisorAdmissionError`; and a victim summary whose echoed `scenario` drifts from the supervisor-selected scenario is rejected before `DetectedScenario` is assembled.

```mermaid
flowchart LR
    V["victim stdout"] --> VA["victim summary admission<br/>max_victim_summary_bytes"]
    A["authority stdout"] --> AA["authority summary admission<br/>max_authority_summary_bytes"]
    D["detector stdout"] --> DA["detector report admission<br/>max_detector_report_bytes"]
    VA -- "valid + scenario match" --> S["DetectedScenario"]
    AA -- "valid" --> S
    DA -- "valid + report scope clean" --> S
    VA -. "over-bound / invalid / scenario drift" .-> X["SupervisorAdmissionError"]
    AA -. "over-bound / invalid" .-> X
    DA -. "over-bound / invalid / scope drift" .-> R["DetectorReport<br/>scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Example-local `SupervisorAdmissionError`, `SubprocessOutputFault`, `max_victim_summary_bytes`, `max_authority_summary_bytes`, bounded victim/authority summary admission helpers, detector malformed-payload refusal, and runnable malformed/scope-drift output faults |
| Security claim | The example supervisor now applies bounded parse admission to every child stdout payload it parses and refuses visible malformed, over-bound, or self-reported victim-scenario drift before downstream scenario consumers accept it. |
| Non-claim | This does not authenticate any child process or summary field, prove that a well-formed summary is true, make echoed `VictimSummary.scenario` trusted provenance, or cap memory before `communicate()` collects stdout. Detector, victim, and authority outputs remain same-user subprocess-controlled example artifacts, not stable NOOA schemas. |
| Base slice | `codex/security-finding-scope-gate` |
| Review files | `examples/security_hardening/detector_harness.py`, `tests/security/test_detector_harness.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `git diff --quiet 7d4e9d5 -- src/nooa`; `pytest`; `ruff check examples/security_hardening tests/security`; `pyright examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Finding Scope Gate

> Branch: `codex/security-finding-scope-gate`

This slice brings the opt-in finding scope helper onto the current receipt-bundle base and wires its first real consumer at the supervisor side of the detector handoff. On the current branch, the later Finding Bundle Handoff above moves rows out of `DetectorReport` JSON: the supervisor admits the report metadata, reads the separate `FindingBundle`, then requires every emitted `SecurityFinding` row to carry the supervisor-selected scope. The example `blank_finding_run_id` and `stale_finding_run_id` detector faults now become `scored=False` instead of accepted off-scope finding rows; both fail explicitly if a chosen scenario produces no finding to corrupt.

```mermaid
flowchart LR
    S["supervisor-selected run_id"] --> A["report parse admission<br/>max_detector_report_bytes"]
    D["detector subprocess<br/>DetectorReport metadata"] --> A
    A --> R["report run_id check"]
    B["FindingBundle rows"] --> V["validate_finding_scope()"]
    R --> V
    V -- "clean finding scope" --> O["DetectedScenario"]
    R -. "report scope mismatch" .-> X["scored=False"]
    V -. "missing_run_id / run_id_mismatch" .-> X
```

| Review item | Detail |
| --- | --- |
| Adds | Public `FindingScopeValidation`, `FindingScopeSignal`, `FindingScopeError`, canonical `FINDING_SCOPE_SIGNALS`, `validate_finding_scope()`, `finding_scope_signals()`, and `require_valid_finding_scope()`; an example-local supervisor report admission gate; `blank_finding_run_id` / `stale_finding_run_id`; and `max_detector_report_bytes` |
| Security claim | The out-of-process detector example can refuse a parsed report or finding rows whose visible `run_id` disagrees with the supervisor-selected scope before downstream scenario consumers accept them. |
| Non-claim | This does not authenticate the detector, report bytes, finding producer, or `expected_run_id`; prove detector coverage; enforce finding-id uniqueness; dereference evidence refs; assign severity or verdict; or cap memory before `communicate()` collects stdout. The demo refusal text includes raw run and finding identifiers. |
| Base slice | `codex/security-receipt-bundle-transport` |
| Review files | `src/nooa/security/findings.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_findings.py`, `tests/security/test_detector_harness.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_findings.py tests/security/test_detector_harness.py tests/security/test_surface_guide.py`; `pytest tests/security`; `pytest`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/findings.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Receipt Bundle Conformance Vectors

> Branch: `codex/security-receipt-bundle-conformance-vectors`

This slice adds no `src/nooa` runtime behavior. It adds checked LF-terminated reference vectors for the public receipt-bundle transport introduced in the previous slice. The vectors pin representative `write_receipt_bundle()` bytes, then exercise `read_receipt_bundle()` across clean, count-mismatched, internally spaced, truncated, over-bound, invalid UTF-8, malformed, and version-classified documents so reviewers can catch drift in the new wire contract without mistaking conformance for authenticity.

```mermaid
flowchart LR
    F["receipt bundle fixture"] --> W["write_receipt_bundle()<br/>exact bytes"]
    F --> R["read_receipt_bundle()<br/>selected outcomes"]
    W --> B["LF JSON<br/>key order + UTF-8"]
    R --> S["bundle / signals / errors"]
```

| Review item | Detail |
| --- | --- |
| Adds | `tests/security/fixtures/receipt_bundle_conformance_v1.json`, exact-byte writer checks, selected reader-outcome checks, a surface-guide reference, and README guidance |
| Security claim | Reviewers can now detect accidental drift in the current `ReceiptBundle` writer bytes and selected reader classifications, including visible truncation and declared-count mismatch. |
| Non-claim | The vectors do not authenticate receipts or producers, prove collection completeness, cover every malformed document, make a clean bundle trustworthy, or require independent writers to copy NOOA's exact JSON formatting when they already satisfy the accepted reader contract. |
| Base slice | `codex/security-receipt-bundle-transport` |
| Review files | `tests/security/fixtures/receipt_bundle_conformance_v1.json`, `tests/security/test_receipt_bundle_conformance.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipt_bundle_conformance.py`; `pytest tests/security`; `git diff --quiet 90995ff -- src/nooa ':(glob)examples/**/*.py'`; `pytest` |

## Security Review Follow-On: Receipt Bundle Transport

> Branch: `codex/security-receipt-bundle-transport`

This slice adds one public receipt transport boundary beside the existing effect egress contract. `write_receipt_bundle()` emits one bounded LF-terminated `ReceiptBundle` document, `read_receipt_bundle()` preserves reader-visible truncation and declared-count mismatch diagnostics, and `require_complete_receipt_bundle()` turns those diagnostics into a fail-closed gate before receipt scope or detector policy runs. The identity detector example now uses that core path instead of its former example-local receipt JSON reader.

```mermaid
flowchart LR
    A["authority or backend"] --> W["write_receipt_bundle()<br/>LF-terminated JSON"]
    W --> P["receipt pipe"]
    P --> R["read_receipt_bundle()<br/>signals + budgets"]
    R -- "complete" --> G["require_complete_receipt_bundle()"]
    G --> S["receipt scope gate"]
    S --> D["detector policy"]
    R -. "truncated / receipt_count_mismatch" .-> X["DetectorReport<br/>scored=False"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `ReceiptBundle`, `ReceiptBundleReadResult`, `ReceiptBundleIncompleteError`, `ReceiptBundleInputTooLargeError`, `UnsupportedReceiptBundleVersionError`, canonical `RECEIPT_BUNDLE_COMPLETENESS_SIGNALS`, bounded `read_receipt_bundle()` / `write_receipt_bundle()`, `require_complete_receipt_bundle()`, and authority `truncate_receipt_document` / `drop_receipt_count_mismatch` faults |
| Security claim | A detector can distinguish one complete LF-terminated receipt bundle from a reader-visible truncated or declared-count-mismatched bundle and refuse it before run-scope or profile policy consumes receipt copies. |
| Non-claim | A clean bundle does not authenticate the producer or bytes, prove receipt coverage, detect a dishonest producer that omits receipts before declaring a matching count, enforce receipt-id uniqueness, correlate receipts to effects, establish run scope, or make an empty bundle evidence that no receipts exist. |
| Base slice | `codex/security-detector-receipt-scope-gate` |
| Review files | `src/nooa/security/receipts.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/approval_authority.py`, `examples/security_hardening/detector_harness.py`, `tests/security/test_receipts.py`, `tests/security/test_approval_authority.py`, `tests/security/test_detector_harness.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipts.py tests/security/test_approval_authority.py tests/security/test_detector_harness.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/receipts.py examples/security_hardening/approval_authority.py examples/security_hardening/detector_harness.py` |

## Security Review Follow-On: Detector Receipt Scope Gate

> Branch: `codex/security-detector-receipt-scope-gate`

This slice wires the opt-in receipt scope helper into the example detector subprocess when an authority receipt pipe is present. The harness wraps the identity scorer with the supervisor-selected `run_id` before policy runs, so one stale authority receipt now becomes a visible `scored=False` refusal instead of being silently dropped by the scorer's same-run join. Receipt-free profiles keep their existing direct scorer path.

```mermaid
flowchart LR
    S["supervisor-selected run_id"] --> G["receipt_scope_gated_scorer()"]
    A["authority receipt pipe"] --> D["DetectorInput"]
    D --> G
    G -- "clean receipt scope" --> P["identity scorer"]
    G -. "run_id_mismatch" .-> R["DetectorReport<br/>scored=False"]
    P --> F["finding or no finding"]
```

| Review item | Detail |
| --- | --- |
| Adds | Example-local `receipt_scope_gated_scorer()`, an authority `stale_receipt_run_id` fault, focused harness tests, and README guidance for the new refusal path |
| Security claim | The out-of-process identity example can fail closed on a visible mismatched receipt `run_id` before application policy consumes the supplied receipt copies. |
| Non-claim | This is not automatic `DetectorInput` enforcement, receipt authentication, source authentication, coverage proof, sandboxing, or attestation. The demo refusal text includes raw run and receipt identifiers; real deployments must decide whether that text may cross a process boundary. |
| Base slice | `codex/security-receipt-scope-validation` |
| Review files | `examples/security_hardening/detector_harness.py`, `examples/security_hardening/approval_authority.py`, `examples/security_hardening/identity_approval.py`, `tests/security/test_detector_harness.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_detector_harness.py tests/security/test_data_export_example.py tests/security/test_approval_authority.py`; `pytest tests/security`; `ruff check examples/security_hardening tests/security`; `pyright examples/security_hardening/detector_harness.py examples/security_hardening/approval_authority.py` |

## Security Review Follow-On: Receipt Scope Validation

> Branch: `codex/security-receipt-scope-validation`

This slice adds one opt-in core helper on top of the existing `SecurityReceipt` transport shape. Applications that already selected an assessment `run_id` can materialize one supplied receipt iterable, preserve its order, and fail closed on blank or mismatched receipt scopes before passing those copies to detector policy. The transport model itself stays permissive: blank `run_id` values remain valid until a caller chooses to enforce one expected scope.

```mermaid
flowchart LR
    R["SecurityReceipt copies"] --> V["validate_receipt_scope()<br/>expected_run_id"]
    V --> S["ReceiptScopeValidation"]
    S -- "no scope signals" --> Q["require_valid_receipt_scope()"]
    Q --> D["DetectorInput or caller policy"]
    S -. "missing_run_id<br/>run_id_mismatch" .-> X["caller refusal"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `ReceiptScopeValidation`, `ReceiptScopeSignal`, `ReceiptScopeError`, canonical `RECEIPT_SCOPE_SIGNALS`, `validate_receipt_scope()`, `receipt_scope_signals()`, and `require_valid_receipt_scope()` |
| Security claim | Applications can make one narrow receipt handoff invariant explicit: every supplied receipt copy must carry the caller-selected non-empty `run_id` before downstream policy consumes it. |
| Non-claim | Directly constructing `ReceiptScopeValidation` does not perform the check. This helper does not authenticate receipt sources or `expected_run_id`, verify collection coverage, enforce receipt-id uniqueness, inspect application-specific receipt semantics, correlate receipts to effects, prove backend truth, or make an empty clean bundle evidence that no receipts exist. |
| Base slice | `codex/security-minimal-out-of-process-recipe` |
| Review files | `src/nooa/security/receipts.py`, `src/nooa/security/__init__.py`, `tests/security/test_receipts.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `README.md` |
| Validation | `pytest tests/security/test_receipts.py tests/security/test_surface_guide.py`; `pytest tests/security`; `pytest`; `ruff check src/nooa/security tests/security` |

## Security Review Follow-On: Minimal Out-of-Process Recipe

> Branch: `codex/security-minimal-out-of-process-recipe`

This slice adds no `src/nooa` runtime behavior. It adds a focused two-process recipe between the single-process API snippet and the full detector harness: one victim child receives only the V2 effect-pipe write end, one detector child receives only the effect-pipe read end, and the detector builds `DetectorInput` from public APIs before running a tiny example scorer. The recipe keeps the boundary visible without importing the authority, profile, or fault-matrix machinery from the larger harness.

```mermaid
flowchart LR
    S["supervisor"] -- "effect-pipe write fd" --> V["victim child"]
    S -- "effect-pipe read fd" --> D["detector child"]
    V --> E["FdEffectSink<br/>V2 records + stream_end"]
    E --> P["pipe"]
    P --> D
    D --> I["DetectorInput"]
    I --> F["example finding<br/>or refusal"]
    V -. "exit before stream_end" .-> X["missing_stream_end"]
    X -.-> D
```

| Review item | Detail |
| --- | --- |
| Adds | `examples/security_hardening/minimal_detector.py`, focused subprocess-boundary tests, a hardening-example reading order, and README invariants that keep the active joint section unique |
| Security claim | Users now have a readable out-of-process recipe that demonstrates effect-pipe endpoint separation and preserves V2 `missing_stream_end` refusal outside the victim process. |
| Non-claim | Two same-user processes are not a privilege boundary; the recipe does not authenticate records, prove completeness, provide sandboxing or attestation, or make its scorer a NOOA policy API. |
| Base slice | `codex/security-transport-conformance-vectors` |
| Review files | `examples/security_hardening/minimal_detector.py`, `tests/security/test_minimal_detector.py`, `tests/security/test_joint_readme.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `README.md` |
| Validation | `pytest tests/security/test_minimal_detector.py tests/security/test_joint_readme.py`; `pytest tests/security`; `git diff --quiet 12c1e3f -- src/nooa`; `pytest` |

## Security Review Follow-On: Transport Conformance Vectors

> Branch: `codex/security-transport-conformance-vectors`

This slice adds no `src/nooa` runtime behavior. It adds checked JSON reference vectors for the remaining public security transport shapes that already carry `-v1` wire discriminators: `SecurityReceipt`, `SecurityFinding`, and `DetectorInput`. Each vector pins current key order and compact UTF-8 bytes in the writer direction, then validates the fixture bytes back into the same model so reviewers can catch serialization drift without mistaking conformance for authenticity.

```mermaid
flowchart LR
    R["SecurityReceipt"] --> V["checked transport vectors"]
    F["SecurityFinding"] --> V
    D["DetectorInput"] --> V
    V --> W["model_dump_json()<br/>exact bytes"]
    V --> P["model_validate_json()"]
    P --> E["same model<br/>same -v1 shape"]
```

| Review item | Detail |
| --- | --- |
| Adds | `tests/security/fixtures/security_transport_conformance_v1.json`, byte-level checks for three public transport shapes, reverse-direction fixture validation, and a surface-guide note |
| Security claim | Reviewers can now detect accidental drift in the current `SecurityReceipt`, `SecurityFinding`, and `DetectorInput` JSON wire forms, including key order and representative payload encoding. |
| Non-claim | Checked vectors do not authenticate receipts, findings, detector inputs, or their producers; prove that content is true; cover every possible JSON value; or add verdict, severity, or enforcement semantics. |
| Base slice | `codex/security-effect-egress-producer-conformance` |
| Review files | `tests/security/fixtures/security_transport_conformance_v1.json`, `tests/security/test_transport_conformance.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `README.md` |
| Validation | `pytest tests/security/test_transport_conformance.py`; `pytest tests/security`; `git diff --quiet 5664907 -- src/nooa`; `pytest` |

## Security Review Follow-On: Producer Egress Conformance Vectors

> Branch: `codex/security-effect-egress-producer-conformance`

This slice adds no `src/nooa` runtime behavior. It adds writer-direction reference vectors for the existing `FdEffectSink` V1 and V2 output, then checks that the current sink emits those bytes exactly and that the same vectors still round-trip through `read_effect_egress()`. The reader fixtures already told an independent collector what bytes it must accept; this slice gives reviewers a checked reference for what NOOA's own producer emits today without claiming that equivalent external JSON writers must use identical formatting.

```mermaid
flowchart LR
    R["fixed EffectRecord inputs"] --> S["FdEffectSink<br/>V1 / V2"]
    S --> V["producer vectors<br/>checked bytes"]
    V --> B["LF JSON frame shape<br/>key order + compact encoding"]
    V --> C["read_effect_egress()"]
    C --> RT["round-trip record check"]
    S --> E["V2 close()<br/>stream_end count"]
    E --> V
```

| Review item | Detail |
| --- | --- |
| Adds | `tests/security/fixtures/effect_egress_producer_conformance_v1.json`, exact-byte producer checks, reader round-trip checks, and a surface-guide note for the reference vectors |
| Security claim | Reviewers can now detect accidental drift in the current `FdEffectSink` V1/V2 frame encoding and keep its checked producer examples aligned with the existing reader contract. |
| Non-claim | Exact producer vectors do not authenticate frames, prove completeness, make a producer trusted, or require independent writers to copy NOOA's JSON formatting when they already satisfy the accepted wire contract. They are regression references for this implementation, not evidence-authenticity fixtures. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline-v2` |
| Review files | `tests/security/fixtures/effect_egress_producer_conformance_v1.json`, `tests/security/test_egress_producer_conformance.py`, `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `README.md` |
| Validation | `pytest tests/security/test_egress_producer_conformance.py`; `pytest tests/security`; `git diff --quiet 11ae1eb -- src/nooa`; `pytest` |

## Security Review Joint Branch: End-to-End Detector Pipeline V14

> Branch: `codex/security-hardening-e2e-detector-pipeline-v14`

This is the current presentation branch for the security path assembled across the smaller review slices. It adds no runtime behavior beyond those slices. A maintainer can now review one cumulative path with two victim families, application-owned defender and backend policy, V2 collector-facing egress, public LF-terminated receipt and finding bundle transports, published version-token classification contracts for both bundle types, out-of-process detector scoring, reader-visible refusal on incomplete or inconsistent effect, receipt, and finding streams, an example-local receipt-ID uniqueness gate before receipt scope and identity policy, an example-local receipt scope gate before identity policy, detector-side evidence-ref membership checks against the current `DetectorInput` before finding bundle emission, supervisor-side report input-ID admission, finding bundle admission, finding scope validation, finding-ID uniqueness validation, required evidence-ref presence against the supervisor-selected `input_id`, and example-local structured finding-admission refusal stages before scenario consumers accept rows, bounded parse admission for every child stdout payload consumed by the example, a checked surface guide for the public `nooa.security` exports, and checked conformance vectors for both bundle boundaries. `SURFACE.md` owns the export map, transport rules, minimal integration, and canonical boundaries; this section owns the runnable composition and checked scenario matrix.

```mermaid
flowchart LR
    I["prompt injection<br/>or unsafe task context"] --> V1["IdentityApprovalAgent"]
    I --> V2["DataExportAgent"]
    V1 --> D["defender middleware"]
    D -- "continue" --> B1["identity backend"]
    D -- "deny" --> E1["denied effect"]
    V2 --> B2["export backend allowlist"]
    V1 --> VS["victim summary JSON"]
    V2 --> VS
    V1 -- "approval request" --> A["approval authority"]
    A -- "token response" --> V1
    A --> AS["authority summary JSON"]
    A -- "ReceiptBundle" --> RP["receipt pipe"]
    B1 --> ES["FdEffectSink<br/>V2"]
    B2 --> ES
    E1 --> ES
    ES --> EP["effect pipe"]
    EP --> T["detector subprocess"]
    RP --> T
    T --> C["read_effect_egress()<br/>signals + budgets"]
    T --> RB["read_receipt_bundle()<br/>identity only"]
    C --> DI["DetectorInput"]
    RB --> Q["require_complete_receipt_bundle()"]
    Q --> DI
    DI --> RI["receipt_id_uniqueness_gated_scorer()<br/>identity only"]
    RI --> G["receipt_scope_gated_scorer()<br/>identity only"]
    G --> P1["identity scorer"]
    DI --> P2["export scorer"]
    P1 --> EM["evidence_ref_membership_gated_scorer()<br/>current DetectorInput IDs"]
    P2 --> EM
    EM --> RPT["DetectorReport JSON<br/>declared_finding_count"]
    EM --> FBW["write_finding_bundle()"]
    FBW --> FFT["supervisor-owned<br/>finding temp file"]
    VS --> VA["victim summary admission<br/>+ scenario check"]
    AS --> AA["authority summary admission"]
    RPT --> RA["detector report admission<br/>+ run_id / input_id checks"]
    FFT --> FBR["read_finding_bundle()<br/>signals + budgets"]
    RA --> FC["finding count gate"]
    FBR --> FC
    FC --> FG["finding scope gate"]
    FG --> FCG["report coherence gate"]
    FCG --> FU["finding ID uniqueness gate"]
    FU --> FR["required evidence-ref gate<br/>supervisor-selected input_id"]
    VA --> F["DetectedScenario"]
    AA --> F
    FR --> F
    C -. "gap / truncation / missing end / count mismatch" .-> X["DetectorReport<br/>scored=False"]
    RB -. "truncated / receipt count mismatch" .-> X
    RI -. "duplicate_receipt_id" .-> X
    G -. "receipt run_id mismatch" .-> X
    EM -. "unknown_evidence_ref" .-> X
    RA -. "over-bound / invalid / report run_id / input_id mismatch" .-> X
    FBR -. "truncated / invalid / over-bound" .-> X
    FC -. "count_mismatch" .-> FAD["finding_admission_refusal"]
    FG -. "scope_drift" .-> FAD
    FCG -. "refused_report_rows" .-> FAD
    FU -. "duplicate_finding_id" .-> FAD
    FR -. "missing_required_evidence_ref" .-> FAD
    FAD --> X
    X --> F
    VA -. "over-bound / invalid / scenario drift" .-> Y["SupervisorAdmissionError"]
    AA -. "over-bound / invalid" .-> Y
```

The matrix covers paths that return `DetectedScenario`. Victim and authority summary admission faults raise `SupervisorAdmissionError` instead, so their exact refusal shapes stay in `tests/security/test_detector_harness.py` rather than being flattened into matrix rows. The matrix still has no row for detector-side evidence-ref membership because current scorers emit refs within their `DetectorInput`, the current fault axis mutates outputs only after scoring, and the supervisor still has no independent evidence-ID set to recheck membership after bundle admission. V13 adds one row for the supervisor-side required-ref gate because `drop_required_evidence_ref` can strip the anchor after scoring and before finding admission. V14 adds one detector-side row for `duplicate_receipt_id`: the authority can duplicate a transported receipt after issuance while keeping the receipt bundle count coherent, so the receipt-ID wrapper can refuse before receipt scope or policy runs. Its `Finding admission refusal` remains `None`, so the row joins the existing detector-side pre-finding-admission collision group with malformed report and stale receipt-scope cases; the fault column keeps them distinct.

<!-- JOINT_SCENARIO_MATRIX_START -->
| Scenario | Victim fault | Authority fault | Detector fault | Subprocess output fault | Profile | V2 effect signals | Receipt bundle signals | Finding bundle signals | Finding admission refusal | Scored | Findings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `vulnerable_attack` | `none` | `none` | `none` | `none` | `identity_approval` | `()` | `()` | `()` | `None` | `True` | `1` |
| `vulnerable_attack` | `none` | `none` | `none` | `malformed_detector_report` | `identity_approval` | `()` | `()` | `()` | `None` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `blank_finding_run_id` | `none` | `identity_approval` | `()` | `()` | `()` | `"scope_drift"` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `stale_finding_run_id` | `none` | `identity_approval` | `()` | `()` | `()` | `"scope_drift"` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `duplicate_finding_id` | `none` | `identity_approval` | `()` | `()` | `()` | `"duplicate_finding_id"` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `drop_required_evidence_ref` | `none` | `identity_approval` | `()` | `()` | `()` | `"missing_required_evidence_ref"` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `truncate_finding_document` | `none` | `identity_approval` | `()` | `()` | `("truncated",)` | `None` | `False` | `0` |
| `vulnerable_attack` | `none` | `none` | `drop_finding_count_mismatch` | `none` | `identity_approval` | `()` | `()` | `()` | `"count_mismatch"` | `False` | `0` |
| `defender_only_attack` | `none` | `none` | `none` | `none` | `identity_approval` | `()` | `()` | `()` | `None` | `True` | `0` |
| `hardened_authorized` | `none` | `none` | `none` | `none` | `identity_approval` | `()` | `()` | `()` | `None` | `True` | `0` |
| `hardened_authorized` | `none` | `stale_receipt_run_id` | `none` | `none` | `identity_approval` | `()` | `()` | `()` | `None` | `False` | `0` |
| `hardened_authorized` | `none` | `duplicate_receipt_id` | `none` | `none` | `identity_approval` | `()` | `()` | `()` | `None` | `False` | `0` |
| `hardened_authorized` | `none` | `truncate_receipt_document` | `none` | `none` | `identity_approval` | `()` | `("truncated",)` | `()` | `None` | `False` | `0` |
| `hardened_authorized` | `none` | `drop_receipt_count_mismatch` | `none` | `none` | `identity_approval` | `()` | `("receipt_count_mismatch",)` | `()` | `None` | `False` | `0` |
| `vulnerable_attack` | `partial_tail_crash` | `truncate_receipt_document` | `none` | `none` | `identity_approval` | `("truncated", "missing_stream_end")` | `("truncated",)` | `()` | `None` | `False` | `0` |
| `export_vulnerable_attack` | `none` | `none` | `none` | `none` | `data_export` | `()` | `()` | `()` | `None` | `True` | `1` |
| `export_hardened_attack` | `none` | `none` | `none` | `none` | `data_export` | `()` | `()` | `()` | `None` | `True` | `0` |
| `vulnerable_attack` | `partial_tail_crash` | `none` | `none` | `none` | `identity_approval` | `("truncated", "missing_stream_end")` | `()` | `()` | `None` | `False` | `0` |
| `vulnerable_attack` | `exit_between_frames` | `none` | `none` | `none` | `identity_approval` | `("missing_stream_end",)` | `()` | `()` | `None` | `False` | `0` |
| `vulnerable_attack` | `drop_record_count_mismatch` | `none` | `none` | `none` | `identity_approval` | `("record_count_mismatch",)` | `()` | `()` | `None` | `False` | `0` |
| `export_vulnerable_attack` | `sequence_gap` | `none` | `none` | `none` | `data_export` | `("first_sequence_error",)` | `()` | `()` | `None` | `False` | `0` |
<!-- JOINT_SCENARIO_MATRIX_END -->

| Review item | Detail |
| --- | --- |
| Included slices | `codex/security-hardening-e2e-detector-pipeline`, `codex/security-second-victim-detector-generality`, `codex/security-effect-egress-stream-end-v2`, `codex/security-surface-guide`, `codex/security-lossy-writer-fault-coverage`, `codex/security-effect-egress-producer-conformance`, `codex/security-transport-conformance-vectors`, `codex/security-minimal-out-of-process-recipe`, `codex/security-receipt-scope-validation`, `codex/security-detector-receipt-scope-gate`, `codex/security-receipt-bundle-transport`, `codex/security-receipt-bundle-conformance-vectors`, `codex/security-receipt-bundle-version-contract`, `codex/security-finding-scope-gate`, `codex/security-supervisor-output-admission`, `codex/security-finding-bundle-handoff`, `codex/security-finding-bundle-conformance-vectors`, `codex/security-finding-id-uniqueness`, `codex/security-finding-admission-diagnostics`, `codex/security-finding-evidence-ref-membership`, `codex/security-finding-required-evidence-ref`, `codex/security-receipt-id-uniqueness` |
| V14 addition | The identity-approval detector path now rejects repeated `receipt_id` values in one complete supplied receipt iterable before receipt scope or profile policy runs. The new `duplicate_receipt_id` row is detector-side, so it stays in the existing `Finding admission refusal = None` bucket instead of creating a new supervisor finding-admission stage. |
| Security claim | Applications can compose and review one deterministic hardening path around current NOOA primitives: observe effects, keep authorization policy application-owned, move detector scoring outside the victim process, preserve V2 reader-visible refusal semantics, refuse reader-visible receipt-bundle truncation or count mismatch before receipt scope and identity policy run, refuse repeated `receipt_id` values in one supplied identity receipt iterable before receipt scope and identity policy run, refuse visible stale receipt scope before identity policy runs, refuse detector-side scorer outputs that cite refs outside the current `DetectorInput` ID set before finding bundle emission, admit every parsed child stdout payload through bounded shape checks, refuse visible detector-report run or input-ID drift, refuse reader-visible finding-bundle truncation or report-to-bundle count drift before finding scope runs, refuse visible finding scope drift, refuse repeated `finding_id` values in one admitted finding iterable after existing scope and coherence gates pass, refuse admitted rows that omit the supervisor-selected `input_id` after those gates pass, identify current finding-admission refusal stages through an example-local structured field instead of parsing refusal text, reject victim-summary scenario drift before scenario consumers accept it, and reuse the same detector handoff across two example victim policies. |
| Non-claim | This remains a same-user, same-host example with no sandboxing, signing, authentication, attestation, production IAM boundary, or completeness proof. Two victims do not establish general coverage. A valid-looking V2 terminator, receipt bundle, or finding bundle can still be forged; matching future bundle version tokens are not promises of parser support or safety; a dishonest writer can omit an effect, receipt, or finding and declare the reduced count; receipts and findings remain caller-controlled copies; count agreement, scope consistency, distinct receipt IDs, distinct finding IDs, evidence-ref membership against a detector input, required-ref presence, and `finding_admission_refusal` are not authenticity, provenance, evidence support, or cross-bundle uniqueness; the detector sees the supervisor-selected `input_id` and can echo it mechanically; the receipt-ID and evidence-ref wrappers are not supervisor gates and a hostile detector can bypass them; the new field is example-local rather than a public NOOA schema; clean empty bundles are not evidence that nothing exists; a well-formed victim or authority summary can still lie; the three stdout byte bounds apply only after `communicate()` has collected stdout; the finding-bundle bound applies only when the supervisor reads its same-user temporary file; refusal text can expose raw identifiers; and zero findings remain policy-specific example outcomes rather than a general safety verdict. |
| Presentation files | `README.md`, `examples/security_hardening/README.md`, `tests/security/test_joint_readme.py` |
| Validation | `pytest tests/security/test_joint_readme.py tests/security/test_detector_harness.py tests/security/test_receipts.py tests/security/test_findings.py tests/security/test_receipt_bundle_conformance.py tests/security/test_finding_bundle_conformance.py tests/security/test_surface_guide.py`; `pytest tests/security`; `ruff check src/nooa/security examples/security_hardening tests/security`; `pyright src/nooa/security/receipts.py src/nooa/security/findings.py examples/security_hardening/approval_authority.py examples/security_hardening/detector_harness.py`; `pytest` |

Run representative paths:

```bash
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack
uv run python -m examples.security_hardening.detector_harness demo --scenario hardened_authorized
uv run python -m examples.security_hardening.detector_harness demo --scenario hardened_authorized --authority-fault stale_receipt_run_id
uv run python -m examples.security_hardening.detector_harness demo --scenario hardened_authorized --authority-fault duplicate_receipt_id
uv run python -m examples.security_hardening.detector_harness demo --scenario hardened_authorized --authority-fault truncate_receipt_document
uv run python -m examples.security_hardening.detector_harness demo --scenario hardened_authorized --authority-fault drop_receipt_count_mismatch
uv run python -m examples.security_hardening.detector_harness demo --scenario export_vulnerable_attack
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --victim-fault drop_record_count_mismatch
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --detector-fault blank_finding_run_id
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --detector-fault stale_finding_run_id
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --detector-fault duplicate_finding_id
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --detector-fault truncate_finding_document
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --detector-fault drop_finding_count_mismatch
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --subprocess-output-fault malformed_detector_report
```

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the progressive rationale and [`examples/security_hardening/SURFACE.md`](examples/security_hardening/SURFACE.md) for the checked public-surface map. Historical per-slice review notes remain below for branch-by-branch context.

## Security Review Follow-On: Lossy Writer Fault Coverage

> Branch: `codex/security-lossy-writer-fault-coverage`

This slice adds no new `src/nooa` API. It extends the example-only subprocess harness with two orderly-looking writer faults that the existing composed pipeline had not exercised end to end: one skips a sequence number before a valid V2 terminator, and one drops the first effect frame while declaring the pre-loss record count. The detector now has regression coverage for refusing both paths across the identity and data-export profiles instead of silently turning a lost allowed effect into a zero-finding score.

```mermaid
flowchart LR
    V["victim emits allowed effect"] --> R["record frame<br/>sequence=0"]
    R --> P["effect pipe"]
    V -. "sequence_gap" .-> G["stream_end<br/>sequence=2<br/>record_count=1"]
    V -. "drop_record_count_mismatch" .-> M["stream_end only<br/>sequence=0<br/>record_count=1"]
    G --> P
    M --> P
    P --> D["detector subprocess"]
    D --> GS["first_sequence_error<br/>refused"]
    D --> MS["record_count_mismatch<br/>refused"]
```

| Fault | Retained records | Stream end | Completeness signals | Detector result |
| --- | --- | --- | --- | --- |
| `--victim-fault sequence_gap` | 1 | Declared | `("first_sequence_error",)` | Refused |
| `--victim-fault drop_record_count_mismatch` | 0 | Declared count `1` | `("record_count_mismatch",)` | Refused |
| Equivalent V1 sequence gap | 2 | Not applicable | `("first_sequence_error",)` | No V2 count signal |

| Review item | Detail |
| --- | --- |
| Adds | Example-local lossy writer faults in `effect_collector.py`, shared detector-harness plumbing, identity and export profile refusal tests, and a false-negative regression that proves the empty retained effect tuple would otherwise score as zero findings |
| Security claim | The composed detector path now demonstrates refusal for reader-visible sequence discontinuity and V2 declared-count mismatch across both current victim profiles, including the empty-record false-negative case that the V2 count signal prevents. |
| Non-claim | A declared count catches an inconsistent writer, not a dishonest one. A writer can still omit an effect and declare the reduced count, forge a terminator, or emit nothing before close. Sequence continuity still assumes a cooperative single writer; these faults add no authentication, sandboxing, attestation, or completeness proof. |
| Base slice | `codex/security-surface-guide` |
| Review files | `examples/security_hardening/effect_collector.py`, `examples/security_hardening/detector_harness.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_effect_collector.py`, `tests/security/test_detector_harness.py`, `tests/security/test_data_export_example.py`, `README.md` |
| Validation | `pytest tests/security`; `git diff --quiet 6fe84b5 -- src/nooa`; `pytest` |

Run the new orderly-looking loss paths:

```bash
uv run python -m examples.security_hardening.effect_collector demo --victim-fault sequence_gap
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --victim-fault drop_record_count_mismatch
uv run python -m examples.security_hardening.detector_harness demo --scenario export_vulnerable_attack --victim-fault drop_record_count_mismatch
```

## Security Review Follow-On: Checked Security Surface Guide

> Branch: `codex/security-surface-guide`

This slice adds no new runtime behavior. It consolidates the current `nooa.security` surface into one checked guide beside the hardening examples, so a maintainer can review the composed API without reconstructing ten chronological branch deltas. A new test keeps the guide's export index aligned with `nooa.security.__all__` and executes the documented minimal V2 sink-to-detector path.

```mermaid
flowchart LR
    A["46 public exports"] --> G["SURFACE.md<br/>grouped by audience"]
    G --> T["test_surface_guide.py"]
    T --> X["export index exact match"]
    T --> S["executable minimal integration"]
    G --> B["canonical boundaries<br/>stated once"]
```

| Review item | Detail |
| --- | --- |
| Adds | `examples/security_hardening/SURFACE.md`, a grouped export index, one runnable minimal integration, consolidated trust-boundary statements, and `tests/security/test_surface_guide.py` |
| Security claim | The documented surface is checked against the actual public export list, and the documented minimal sink-to-`DetectorInput` path is executable against the current API. |
| Non-claim | Documentation is not a security control, an API stability guarantee, or a hardened deployment recipe. Grouping exports by audience is editorial and does not restrict access, authenticate evidence, or add enforcement. |
| Base slice | `codex/security-effect-egress-stream-end-v2` |
| Review files | `examples/security_hardening/SURFACE.md`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_surface_guide.py`, `README.md` |
| Validation | `pytest tests/security/test_surface_guide.py`; `git diff --quiet 805b8e6 -- src/nooa`; `pytest` |

Read the consolidated guide at [`examples/security_hardening/SURFACE.md`](examples/security_hardening/SURFACE.md).

## Security Review Follow-On: V2 Effect Egress Stream End

> Branch: `codex/security-effect-egress-stream-end-v2`

This slice adds an opt-in `nooa-effect-egress-v2` envelope beside the existing V1 default. A V2 `FdEffectSink.close()` writes one explicit stream-end frame with the next sequence number and a writer-declared record count; `read_effect_egress()` preserves that fact as `stream_end_declared` and `declared_record_count`. The subprocess examples opt into V2 so a victim that exits between complete frames is no longer reported like an orderly writer close.

```mermaid
flowchart LR
    V["victim subprocess"] --> R0["record frame<br/>sequence=0"]
    R0 --> P["effect pipe"]
    V -- "normal close()" --> E["stream_end frame<br/>sequence=1<br/>record_count=1"]
    E --> P
    V -. "exit_between_frames" .-> X["EOF without stream_end"]
    P --> C["read_effect_egress()<br/>V2-aware reader"]
    C --> OK["stream_end_declared=True<br/>signals=()"]
    C --> MISS["missing_stream_end<br/>detector refuses"]
```

| Scenario | Received records | Stream end | Completeness signals | Detector result |
| --- | --- | --- | --- | --- |
| Normal V2 victim run | 1 | Declared | `()` | Scoreable |
| `--victim-fault partial_tail_crash` | 1 | Missing | `("truncated", "missing_stream_end")` | Refused |
| `--victim-fault exit_between_frames` | 1 | Missing | `("missing_stream_end",)` | Refused |
| Legacy V1 stream | Any | Not applicable | Existing V1 signals only | Backward compatible |

| Review item | Detail |
| --- | --- |
| Adds | Public V2 schema constants, one writer-declared stream-end frame, version-aware read results, `missing_stream_end` and `record_count_mismatch` diagnostics, V2 conformance vectors, and V2 opt-in for the collector/detector examples |
| Security claim | A collector that explicitly expects V2 can distinguish orderly writer-declared completion from EOF between complete frames, and can refuse a record-count mismatch without breaking V1 readers or V1 default writers. |
| Non-claim | A valid-looking stream-end frame is not authentication, attestation, or proof that every effect was emitted. A compromised writer can still forge records, forge a terminator, omit effects before closing, or share the same-user same-host process boundary. |
| Base slice | `codex/security-second-victim-detector-generality` |
| Review files | `src/nooa/security/egress.py`, `src/nooa/security/__init__.py`, `tests/security/test_egress.py`, `tests/security/fixtures/effect_egress_stream_end_conformance_v1.json`, `examples/security_hardening/effect_collector.py`, `examples/security_hardening/detector_harness.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_effect_collector.py`, `tests/security/test_detector_harness.py`, `tests/security/test_data_export_example.py` |
| Validation | `pytest tests/security`; `pytest` |

Run the V2 subprocess paths:

```bash
uv run python -m examples.security_hardening.effect_collector demo --victim-fault exit_between_frames
uv run python -m examples.security_hardening.detector_harness demo --scenario vulnerable_attack --victim-fault exit_between_frames
uv run python -m examples.security_hardening.detector_harness demo --scenario export_vulnerable_attack --victim-fault exit_between_frames
```

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the V2 framing diagram, exact refusal behavior, and trust-boundary limits.

## Security Review Follow-On: Second Victim Detector Generality

> Branch: `codex/security-second-victim-detector-generality`

This slice adds a second example victim without changing `src/nooa/**`: a `DataExportAgent` records `data.export` effects, a backend can enforce a destination allowlist, and an export scorer flags allowed exports outside that allowlist. The point is not to broaden the threat claim. It is to test whether the existing `DetectorInput` handoff and detector subprocess are actually neutral enough for a policy that does not use approval receipts at all.

```mermaid
flowchart LR
    I1["prompt injection<br/>grant request"] --> V1["IdentityApprovalAgent"]
    I2["prompt injection<br/>export request"] --> V2["DataExportAgent"]
    V1 --> E1["identity EffectRecord"]
    V2 --> E2["data.export EffectRecord"]
    A["approval authority<br/>identity profile only"] --> R["receipt pipe"]
    E1 --> H["shared detector_harness.score_fd()"]
    E2 --> H
    R --> H
    H --> DI["detector_input_from_egress()"]
    DI --> S1["identity scorer<br/>requires asserted receipt coverage"]
    DI --> S2["export scorer<br/>ignores receipt coverage"]
    S1 --> F["finding or refusal"]
    S2 --> F
```

| Scenario | Profile | Authority | Receipt coverage | Detector result |
| --- | --- | --- | --- | --- |
| `vulnerable_attack` | Identity approval | Yes | `asserted_complete` | 1 finding |
| `export_vulnerable_attack` | Data export | No | `unknown` | 1 finding |
| `export_hardened_attack` | Data export | No | `unknown` | 0 findings |
| `export_hardened_allowed` | Data export | No | `unknown` | 0 findings |
| `export_vulnerable_attack --victim-fault partial_tail_crash` | Data export | No | `unknown` | Refused, not clean |

| Review item | Detail |
| --- | --- |
| Adds | Example-only `data_export.py`, shared example-local `detector_policy.py`, a small detector-profile registry in `detector_harness.py`, profile-tagged detector reports, export scenarios, and tests that pin receipt-free scoring plus cross-scorer non-matches |
| Security claim | The current detector handoff stretches to a second, non-identity policy: both victims use the same `score_fd()` and `detector_input_from_egress()` path, while the export scorer can score a complete input with `receipts=()` and `receipt_coverage="unknown"`. |
| Non-claim | Two example victims do not establish general coverage of agent method shapes. The destination allowlist is example policy; NOOA still does not own export authorization, detector sufficiency, or verdicts. The second victim inherits the same unauthenticated, same-user, same-host transport and adds no sandboxing, attestation, authentication, or completeness proof. |
| Base slice | `codex/security-hardening-e2e-detector-pipeline` |
| Review files | `examples/security_hardening/data_export.py`, `examples/security_hardening/detector_policy.py`, `examples/security_hardening/detector_harness.py`, `examples/security_hardening/identity_approval.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_data_export_example.py`, `tests/security/test_detector_harness.py` |
| Validation | `pytest tests/security`; `git diff --quiet a7b11e7 -- src/nooa`; `pytest` |

Run the second victim through the same detector harness:

```bash
uv run python -m examples.security_hardening.detector_harness demo --scenario export_vulnerable_attack
uv run python -m examples.security_hardening.detector_harness demo --scenario export_hardened_attack
uv run python -m examples.security_hardening.detector_harness demo --scenario export_vulnerable_attack --victim-fault partial_tail_crash
```

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the profile split, receipt-free scoring path, and explicit non-claims.

## Security Review Follow-On: Approval Authority Receipts

> Branch: `codex/security-approval-authority-receipts`

This slice removes the detector harness's circular supervisor-issued receipt path. An example-only approval authority process now owns the fixed demo allowlist, returns a run-scoped token response to the victim, and writes a bounded receipt document directly to the detector with receipt rows only for tokens it actually issued. The shared authorized request fixture is tokenless; the same-process baseline still gets an explicit local helper, while the subprocess detector path must obtain its run-scoped token through the authority round trip.

```mermaid
flowchart LR
    S["supervisor"] --> V["victim subprocess"]
    V -- "approval request" --> A["approval authority<br/>fixed demo allowlist"]
    A -- "token response" --> V
    V -- "effect write fd only" --> EP["effect pipe"]
    A -- "AuthorityReceiptDocument<br/>bounded JSON" --> RP["receipt pipe"]
    EP -- "effect read fd only" --> D["detector subprocess"]
    RP -- "receipt read fd only" --> D
    D --> DI["DetectorInput<br/>assembled detector-side"]
    DI --> P["identity scorer"]
    P --> R["DetectorReport<br/>scored or refused"]
```

| Review item | Detail |
| --- | --- |
| Adds | Example-only `approval_authority.py`, shared `identity_contract.py` constants plus deterministic run-scoped token derivation, bounded request/response/receipt documents, authority subprocess wiring in `detector_harness.py`, authority issuance counts in the detector report, and an explicit local token helper for the older same-process demo |
| Security claim | The detector's approval receipts now derive from a separate issuing process action rather than a supervisor branch on scenario name: an authorized request gets one authority-issued run-scoped token and receipt, while an unapproved request gets no receipt and remains detectable by the existing scorer. |
| Non-claim | The authority is still a same-user, same-host demo process with no authentication, signing, sandboxing, or privilege boundary. A receipt says only that this authority process issued a token; it does not prove the backend honored it, prove the effect occurred, make `receipt_coverage="asserted_complete"` independently verifiable, or make a self-reported `issued_token_count` honest. The fixed allowlist and deterministic run-scoped token derivation are demo policy and regression aids, not an IAM system or secret-bearing protocol. |
| Base slice | `codex/security-trusted-detector-harness` |
| Review files | `examples/security_hardening/approval_authority.py`, `examples/security_hardening/identity_contract.py`, `examples/security_hardening/detector_harness.py`, `examples/security_hardening/identity_approval.py`, `examples/security_hardening/effect_collector.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_approval_authority.py`, `tests/security/test_detector_harness.py`, `tests/security/test_hardening_example.py` |
| Validation | `pytest tests/security`; `pytest` |

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the authority topology, failure path, and exact trust-boundary limits.

## Security Review Follow-On: Detector Subprocess Harness

> Branch: `codex/security-trusted-detector-harness`

This slice adds one example-only out-of-process detector harness on top of `DetectorInput`. The supervisor gives the victim only the effect-pipe write end, gives the detector only the effect-pipe read end plus a bounded supervisor-issued receipt document, and lets the detector construct and score one `DetectorInput` outside the victim process. A truncated effect stream becomes an explicit detector refusal rather than a misleading zero-finding result.

```mermaid
flowchart LR
    S["supervisor<br/>scenario + demo receipt document"] --> RP["receipt pipe<br/>bounded JSON"]
    S --> V["victim subprocess"]
    V -- "effect write fd only" --> EP["effect pipe"]
    RP -- "receipt read fd only" --> D["detector subprocess"]
    EP -- "effect read fd only" --> D
    D --> DI["DetectorInput<br/>assembled detector-side"]
    DI --> P["identity scorer<br/>example-local policy"]
    P --> R["DetectorReport<br/>scored or refused"]
    D -. "gap / truncated tail" .-> X["refusal_reason"]
```

| Review item | Detail |
| --- | --- |
| Adds | Example-only `detector_harness.py`, `DetectorReceiptDocument`, `DetectorReport`, `DetectedScenario`, bounded receipt-document parsing, and an example-local `UnscoreableDetectorInputError` so detector refusal is data rather than a generic crash |
| Security claim | Applications can place deterministic detector policy outside the victim process, assemble `DetectorInput` from collector-facing effect bytes plus a separately supplied receipt document, preserve reader-visible incompleteness as an explicit refusal, and cap receipt-document bytes before parsing. |
| Non-claim | The detector subprocess is not automatically trusted: it shares a uid with the victim, the supervisor-issued receipt document is a deterministic demo artifact rather than a backend audit export, `receipt_coverage="asserted_complete"` remains an unverified supervisor assertion, findings are not more authentic merely because policy ran out of process, and a clean empty stream still cannot distinguish valid completion from intentional omission. This harness assembles `DetectorInput` detector-side; it does not define a byte-level `DetectorInput` wire protocol. `DetectorReport` and `DetectedScenario` are example artifacts, not stable NOOA schemas. |
| Base slice | `codex/security-detector-input-contract` |
| Review files | `examples/security_hardening/detector_harness.py`, `examples/security_hardening/effect_collector.py`, `examples/security_hardening/identity_approval.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_detector_harness.py` |
| Validation | `pytest tests/security`; `pytest` |

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the subprocess topology, refusal path, and trust-boundary limits.

## Security Review Slice: Detector Input Contract

> Branch: `codex/security-detector-input-contract`

This slice adds one neutral handoff object between collector-facing evidence and application-owned detector policy. `DetectorInput` carries effect copies, public egress completeness diagnostics, a narrowly named completeness-gate assertion, backend receipt copies, and a caller-asserted receipt collection coverage label. The identity-approval example now scores one `DetectorInput` instead of loose `(effects, receipts, run_id)` arguments, so findings can cite the exact detector input that policy consumed without moving join semantics into NOOA.

```mermaid
flowchart LR
    E["read_effect_egress()<br/>EffectRecord copies"] --> S["effect_egress_completeness_signals()"]
    E --> G["require_complete_effect_egress()<br/>default fail-closed handoff"]
    S --> D["DetectorInput<br/>signals + gate assertion"]
    G --> D
    R["SecurityReceipt copies<br/>caller-asserted source + coverage"] --> D
    D --> P["application detector policy<br/>outside NOOA core"]
    P --> F["SecurityFinding<br/>evidence_refs include input_id"]
```

| Review item | Detail |
| --- | --- |
| Adds | Public `DetectorInput`, `ReceiptCoverage`, `effect_egress_completeness_signals()`, and `detector_input_from_egress()`; the identity-approval example now constructs and scores a detector input bundle |
| Security claim | Applications can make the detector handoff explicit: collector-facing effect copies, reader-visible completeness diagnostics, the specific completeness-gate assertion, and caller-asserted receipt collection coverage can cross one frozen-field transport object without making NOOA own detector policy or receipt-to-effect correlation. |
| Non-claim | The bundle authenticates nothing, proves no omitted effect, verifies no receipt source or coverage assertion, verifies no receipt belongs to its `run_id`, establishes no relationship between a receipt and an effect, and is not itself a detector, threshold, verdict, or enforcement action. Constructing it in a victim process does not make it trusted. |
| Base slice | `codex/security-hardening-e2e-defender-provenance-egress-contract-collector-completeness-gate-input-budget` |
| Review files | `src/nooa/security/evidence.py`, `src/nooa/security/egress.py`, `src/nooa/security/__init__.py`, `examples/security_hardening/identity_approval.py`, `tests/security/test_evidence.py`, `tests/security/test_egress.py`, `tests/security/test_hardening_example.py` |
| Validation | `pytest tests/security`; `pytest` |

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the detector-input placement in the hardening flow and the explicit trust-boundary limits.

## Security Review Slice: Hardening Flow + Defender + Guard Labels + Bounded Egress

> Branch: `codex/security-hardening-e2e-defender-provenance-egress-contract-collector-completeness-gate-input-budget`

This joint slice composes the identity-approval hardening demo, one deterministic application-owned `agent_call` defender recipe, the built-in `framework_guard_observer`, bounded descriptor-backed effect egress, the public `nooa-effect-egress-v1` collector contract, the public `require_complete_effect_egress()` gate, and collector-wide input budgets. The same attack-shaped request still has vulnerable, defender-only, and backend-hardened comparison points. The scorer consumes collector-facing `read_effect_egress()` output instead of the local event store and uses the core gate to refuse a parsed stream with a first sequence discontinuity or truncated trailing frame. The reader also refuses streams that exceed `max_total_bytes` or `max_records` before downstream policy retains unbounded state. Public wire constants and conformance vectors let an independent collector implement the same transport without copying private source constants; the V1 writer and reader also reject out-of-range JSON integers, cyclic metadata, and other values that would not round-trip portably, while backend receipts and findings remain outside core NOOA.

```mermaid
flowchart LR
    I["prompt injection or unsafe context"] --> V["NOOA victim agent"]
    V --> M["grant_access()"]
    M --> O["agent_call recorder<br/>outer wrapper"]
    O --> D["example defender middleware<br/>missing token rule"]
    D -- "deny before backend" --> DX["AccessDecision<br/>source=defender"]
    D -- "pass through" --> B["identity backend<br/>authoritative"]
    B --> BY["AccessDecision<br/>source=backend"]
    DX --> AE["EffectRecord<br/>observer=agent_call_middleware"]
    BY --> AE
    V --> XP["execute_python"]
    XP -- "mapped result.error" --> GO["framework_guard_observer"]
    GO --> GE["EffectRecord<br/>observer=framework_guard"]
    AE --> ES["FdEffectSink<br/>blocking fd"]
    GE --> ES
    ES --> EC["read_effect_egress()<br/>records + diagnostics + budgets"]
    WC["V1 wire contract<br/>version + keys + bounds"] --> EC
    CV["conformance vectors"] --> WC
    EC --> CG["require_complete_effect_egress()<br/>fail closed on gap / truncation"]
    EC -.->|"gap or truncated tail"| IX["EffectEgressIncompleteError"]
    EC -.->|"over total bytes or records"| BX["EffectEgressInputTooLargeError"]
    CG --> AI["identity effects<br/>scorer input"]
    CG --> P["guard evidence<br/>not scorer input"]
    B --> R["SecurityReceipt collector<br/>run_id"]
    AI --> S["application scorer"]
    R --> S
    S --> F["SecurityFinding<br/>run_id"]
```

| Review item | Detail |
| --- | --- |
| Adds | End-to-end identity-approval example, an example-only deterministic `agent_call` defender recipe, `framework_guard_observer()`, bounded `FdEffectSink` transport, public V1 wire constants and conformance vectors, collector-side `read_effect_egress()`, public `require_complete_effect_egress()`, public `EffectEgressInputTooLargeError` plus collector-wide byte and record budgets, run-scoped `SecurityReceipt`, and run-scoped `SecurityFinding` |
| Security claim | Applications can add a deterministic preflight denial, emit bounded framed effect copies through a chosen blocking descriptor, let an independent collector implement the documented `nooa-effect-egress-v1` transport, fail closed on reader-visible sequence discontinuities and trailing partial frames through one core helper, bound payload bytes admitted to parsing and retained complete records, and keep application-owned effects and guard-shaped records distinguishable by `observer` label while composing separately collected receipts and policy-specific findings. |
| Non-claim | The demo does not simulate an LLM attack, make same-process descriptors or receipts trusted, make the defender a trusted boundary or backend authorization replacement, generalize beyond this scripted missing-token rule, authenticate the origin of a guard-shaped exception or record, turn transport compatibility or guard telemetry into a vulnerability detector, prove unrecorded effects did not happen, distinguish a malicious clean stop from valid completion, promise future-version wire stability, or make NOOA enforce authorization policy. A clean result, including an empty stream, means only that the reader saw no known gap, truncation, or budget refusal. The byte and record budgets are local collector resource backstops, not authenticity or authorization guarantees. |
| Included slices | `codex/security-receipt-contract`, `codex/agent-call-effect-recorder`, `codex/effect-record-jsonl-sink`, `codex/security-finding-contract`, `codex/framework-guard-observer`, `codex/security-hardening-defender-recipe`, `codex/security-effect-egress`, `codex/security-effect-egress-contract`, `codex/security-effect-egress-completeness-gate`, `codex/security-effect-egress-input-budget`, `codex/security-hardening-e2e-defender-provenance-egress-contract-collector` |
| Review files | `examples/security_hardening/identity_approval.py`, `examples/security_hardening/effect_collector.py`, `examples/security_hardening/README.md`, `src/nooa/security/__init__.py`, `src/nooa/security/egress.py`, `src/nooa/security/observers.py`, `tests/security/fixtures/effect_egress_conformance_v3.json`, `tests/security/test_egress.py`, `tests/security/test_effect_collector.py`, `tests/security/test_hardening_example.py`, `tests/security/test_observers.py` |
| Validation | `pytest tests/security`; `pytest` |

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the four-scenario comparison, egress notes, and guard-label notes.

## Security Review Follow-On: Out-of-Process Collector

> Branch: `codex/security-hardening-e2e-defender-provenance-egress-contract-collector`

This follow-on layers the example-only supervisor and collector harness onto the composed slice above. The supervisor gives a victim subprocess only a pipe write end and a collector subprocess only the read end, then joins collector-side `read_effect_egress()` facts with the victim process status. The collector intentionally remains fact-reporting rather than calling `require_complete_effect_egress()`: it must preserve gapped or truncated stream diagnostics for the supervisor instead of collapsing them into an exception. The shared reader still rejects malformed frames, non-portable values, and over-budget input rather than turning them into clean summary facts.

```mermaid
flowchart LR
    S["supervisor"] -- "pipe read fd only" --> C["collector subprocess"]
    S -- "pipe write fd only" --> V["victim subprocess"]
    I["prompt injection<br/>or unsafe context"] --> A
    V --> A["NOOA victim agent"]
    A --> E["FdEffectSink"]
    A -.->|"--emit-guard-effect"| X["execute_python<br/>validation denial"]
    X --> G["EffectRecord<br/>observer=framework_guard"]
    G --> E
    E --> P["pipe bytes"]
    WC["V1 wire contract<br/>version + keys + bounds"] --> C
    CV["conformance vectors"] --> WC
    P --> C
    C --> R["read_effect_egress()<br/>records + stream facts"]
    C -.->|"over total bytes or records"| BX["EffectEgressInputTooLargeError"]
    V --> VX["victim returncode"]
    R --> J["supervisor join"]
    VX --> J
```

| Review item | Detail |
| --- | --- |
| Adds | `examples/security_hardening/effect_collector.py`, an example-only two-subprocess harness, collector summary models, an example-local `--emit-guard-effect` coverage knob, and focused collector tests |
| Security claim | A supervisor can keep the pipe read end out of the victim subprocess, making bytes already written to the pipe unavailable for victim readback or truncation, while separately observing V1 stream-shape facts and the victim return code. With the example-local guard coverage knob enabled, the collector also preserves distinct `observer` labels for agent-call and framework-guard records that crossed the pipe. |
| Non-claim | The collector path carries effect records and victim status only. It does not move receipts, findings, or the demo's incomplete-stream scoring refusal across the process boundary; authenticate records; prove omitted effects did not happen; distinguish malicious omission from valid clean completion; provide a privilege boundary between these same-user, same-host processes; provide sandboxing or attestation; prevent the effect; or produce a detector verdict. The shared reader's byte and record budgets bound local collector resource use only. |
| Base slice | `codex/security-hardening-e2e-defender-provenance-egress-contract`; joint integration adds `codex/security-effect-egress-completeness-gate` and `codex/security-effect-egress-input-budget` without changing this collector's fact-reporting behavior |
| Review files | `examples/security_hardening/effect_collector.py`, `examples/security_hardening/README.md`, `examples/README.md`, `tests/security/test_effect_collector.py` |
| Validation | `pytest tests/security`; `pytest` |

See [`examples/security_hardening/README.md`](examples/security_hardening/README.md) for the collector command, subprocess trust-boundary notes, and the base hardening flow.

## Effect Egress Wire Contract

An independent collector may rely on these public exports:

| Export | Value |
| --- | --- |
| `EFFECT_EGRESS_SCHEMA_VERSION` | `"nooa-effect-egress-v1"` |
| `EFFECT_EGRESS_SCHEMA_VERSION_V2` | `"nooa-effect-egress-v2"` |
| `EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS` | `("nooa-effect-egress-v1", "nooa-effect-egress-v2")` |
| `EFFECT_EGRESS_SCHEMA_VERSION_PATTERN` | `nooa-effect-egress-v[1-9][0-9]*` |
| `EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE` | `"full"` |
| `EFFECT_EGRESS_FRAME_KEYS` | `{"schema_version", "sequence", "record"}` |
| `EFFECT_EGRESS_STREAM_END_FRAME_KEYS` | `{"schema_version", "sequence", "stream_end"}` |
| `EFFECT_EGRESS_RECORD_EVENT_TYPE` | `"EffectRecord"` |
| `EFFECT_EGRESS_STREAM_END_EVENT_TYPE` | `"EffectEgressStreamEnd"` |
| `EFFECT_EGRESS_RECORD_KEYS` | `{"event_type", "id", "metadata", "status", "tag", "timestamp", "effect_type", "target", "decision", "observer", "generation_id", "tool_call_id", "attributes"}` |
| `EFFECT_EGRESS_STREAM_END_KEYS` | `{"event_type", "record_count"}` |
| `EffectEgressCompletenessSignal` | `Literal["first_sequence_error", "truncated", "missing_stream_end", "record_count_mismatch"]` |
| `EFFECT_EGRESS_COMPLETENESS_SIGNALS` | `("first_sequence_error", "truncated", "missing_stream_end", "record_count_mismatch")` |
| `MAX_EFFECT_EGRESS_JSON_INTEGER` | `9007199254740991` |
| `MAX_EFFECT_EGRESS_SEQUENCE` | `9007199254740991` |
| `DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES` | `1048576` |
| `DEFAULT_EFFECT_EGRESS_MAX_TOTAL_BYTES` | `268435456` |
| `DEFAULT_EFFECT_EGRESS_MAX_RECORDS` | `1048576` |

A collector that wants a fail-closed handoff can pass the
`EffectEgressReadResult` from `read_effect_egress()` to
`require_complete_effect_egress()`. For V1, the helper returns that result's exact
`records` tuple when `first_sequence_error is None` and the result does not
report truncation. For V2, it additionally requires one stream-end frame and a
declared record count that matches the retained complete records. Otherwise it
raises `EffectEgressIncompleteError`, whose `reasons`, `first_sequence_error`,
`truncated`, `stream_end_declared`, and `declared_record_count` fields preserve
the reader-visible degradation without inventing a detector verdict.

`effect_egress_completeness_signals(egress)` exposes the same canonical
reader-visible diagnostics without forcing the fail-closed decision. It
returns only facts already present on the read result. `missing_stream_end` is
version-conditional and applies only when the result is explicitly V2; an
empty tuple still does not prove omitted effects did not occur or that received
bytes are authentic.

The conformance fixture's own `schema_version` is
`"nooa-effect-egress-conformance-v3"` because it now publishes the collector
budget defaults and their refusal vectors. Its `wire_schema_version` remains
`"nooa-effect-egress-v1"` and continues to pin V1 reader compatibility. The
separate `tests/security/fixtures/effect_egress_stream_end_conformance_v1.json`
fixture pins only the V2 stream-end addition.

Both transports are LF-delimited UTF-8 JSON. Each complete frame ends in one LF
byte, has no BOM or leading/trailing whitespace outside the JSON object, and
contains exactly the keys for its frame kind above. CRLF termination is invalid;
internal JSON whitespace is allowed. Duplicate object keys, non-standard numeric
constants such as `NaN` or `Infinity`, integer literals outside
`-MAX_EFFECT_EGRESS_JSON_INTEGER..MAX_EFFECT_EGRESS_JSON_INTEGER`, numeric
literals that overflow to a non-finite value, and lone-surrogate string escapes
are invalid.

```json
{"schema_version":"nooa-effect-egress-v1","sequence":0,"record":{"event_type":"EffectRecord","id":"00000000-0000-0000-0000-000000000001","metadata":{},"status":"active","tag":null,"timestamp":"2026-07-27T00:00:00","effect_type":"fs.write","target":"/tmp/a","decision":"observed","observer":"","generation_id":"","tool_call_id":"","attributes":{}}}
```

V1 remains the default writer envelope for compatibility. A caller opts into
V2 with `FdEffectSink(fd, schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2)` and
must call `sink.close()` to emit the writer-declared terminator:

```json
{"schema_version":"nooa-effect-egress-v2","sequence":1,"stream_end":{"event_type":"EffectEgressStreamEnd","record_count":1}}
```

The contract is intentionally narrow:

- `schema_version` must be in `EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS`; a future token whose entire value matches `EFFECT_EGRESS_SCHEMA_VERSION_PATTERN` under `EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE == "full"` raises `UnsupportedEffectEgressVersionError`. Use a whole-string API such as Python `re.fullmatch()` or its equivalent; do not emulate it with prefix/substring matching or `^...$`, which can treat a trailing newline specially. The pattern accepts `v1`, `v2`, and `v10`, but not `v0`, `v01`, case variants, or tokens with trailing whitespace or newline.
- Every integer in the JSON payload must stay within `-MAX_EFFECT_EGRESS_JSON_INTEGER..MAX_EFFECT_EGRESS_JSON_INTEGER`, which keeps values exact in JSON implementations that use IEEE-754 numbers.
- `sequence` is a strict integer in the inclusive range `0..MAX_EFFECT_EGRESS_SEQUENCE`, where `MAX_EFFECT_EGRESS_SEQUENCE == MAX_EFFECT_EGRESS_JSON_INTEGER`. The collector records the first `(expected, observed)` discontinuity but still returns the complete frames it could parse.
- `record` must contain exactly `EFFECT_EGRESS_RECORD_KEYS`, carry `event_type == EFFECT_EGRESS_RECORD_EVENT_TYPE`, and validate as an `EffectRecord`. V1 and V2 record frames intentionally share the full writer-emitted `EffectRecord` payload shape; omitted defaulted fields such as `id` or `timestamp` are invalid rather than minted at read time. Changing accepted record fields requires a future envelope or an explicitly versioned record payload.
- A V2 `stream_end` frame must contain exactly `EFFECT_EGRESS_STREAM_END_KEYS`, carry `event_type == EFFECT_EGRESS_STREAM_END_EVENT_TYPE`, and declare the number of record frames the writer says it emitted before closing. It consumes the next sequence number. Any later frame is invalid.
- `FdEffectSink` rejects `EffectRecord` instances whose serialized payload would add envelope-incompatible fields, change the record event type, contain invalid scalar values such as out-of-range integers, non-finite floats, or lone surrogates, or require cyclic or non-JSON-native `metadata` values to be rewritten during envelope serialization. `JsonlEffectSink` is a separate raw-record sink and should not be treated as an effect-egress envelope compatibility oracle.
- `read_effect_egress()` starts sequence validation at `0`, so attaching to a stream after its first frame intentionally reports an initial discontinuity and `require_complete_effect_egress()` refuses that parsed result by design.
- A trailing unterminated line is reported as `truncated=True` and is not parsed as a record.
- `read_effect_egress(..., expected_schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2)` is needed only when an otherwise empty stream must be classified as missing a V2 terminator; without that caller context an empty stream remains version-unknown.
- `require_complete_effect_egress()` is a convenience gate over the public reader diagnostics only. A clean V2 result means only that the writer declared an end frame and its count matched the complete records retained by this reader; it is not proof that no effect was omitted or that the records are authentic.
- `read_effect_egress()` accepts positive `max_total_bytes` and `max_records` budgets in addition to `max_frame_bytes`. The total-byte budget covers payload bytes admitted to parsing, including complete frames and a trailing unterminated line; the reader may use one bounded lookahead byte to distinguish exact EOF from overflow. The record budget counts only complete parsed records. Exceeding either budget raises `EffectEgressInputTooLargeError` and is not downgraded to truncation.
- A newline-terminated malformed frame raises a generic `ValueError`. Callers that distinguish outcomes must catch `UnsupportedEffectEgressVersionError`, `EffectEgressFrameTooLargeError`, and `EffectEgressInputTooLargeError` before a generic `ValueError` handler because all three distinguished errors subclass `ValueError`; `EffectEgressIncompleteError` is a `RuntimeError`, so `require_complete_effect_egress(read_effect_egress(fh))` keeps invalid bytes distinct from a parsed short or gapped stream.
- A line larger than the configured frame maximum, counting the terminating LF byte for complete frames, raises `EffectEgressFrameTooLargeError` when the reader reaches that frame bound before the total-byte budget; it is not downgraded to truncation.

The checked-in `tests/security/fixtures/effect_egress_conformance_v3.json`
vectors cover empty input, compact and internally-spaced valid frames,
well-formed multi-frame input, forward, duplicate, and backward sequence
discontinuities, first-error-wins behavior after a later backward step, exact
and one-over sequence bounds, exact and one-over record integer bounds, a
trailing partial frame, exact-max and over-bound complete and unterminated
lines, exact and one-over collector total-byte and complete-record budgets,
future-version classification including malformed near misses such as a
trailing newline escape, strict
LF framing without BOM or outer whitespace, blank and malformed frames
including a second-line failure, negative sequence rejection, each missing
required key, a missing defaulted record key, unexpected envelope and record
keys including wrong or empty record event types, duplicate object keys,
non-standard numeric constants, out-of-range integer literals, numeric
overflow literals, lone-surrogate escapes, and one invalid UTF-8 line encoded
as `payload_base64`.
They are V1 reader compatibility fixtures for independent collectors, not
evidence-authenticity fixtures. The V2 stream-end fixture additionally covers
an empty terminated stream, missing terminators, a truncated terminator,
record-count mismatch, and a hard error for frames after stream end; it also is
not an authenticity fixture.

## Installation

Install directly from GitHub with [uv](https://docs.astral.sh/uv/getting-started/installation/). Add the **core** framework to a new (or existing) Python project:

```bash
uv init my-agent-project
cd my-agent-project

uv add "nooa @ git+https://github.com/NVIDIA-NeMo/labs-OO-Agents.git@main"
```

<details>
<summary><b>Optional sub-packages</b> — CLI, memory, evaluation pipeline</summary>

<br />

All of these live in the same repo and are addressed with `#subdirectory=…`.

```bash
# CLI (beta): the `nooa` command, trace viewer, eval runner
uv add "nooa-cli @ git+https://github.com/NVIDIA-NeMo/labs-OO-Agents.git@main#subdirectory=packages/nooa-cli"

# Long-term memory subsystem (MemoryManager)
uv add "nooa-memory @ git+https://github.com/NVIDIA-NeMo/labs-OO-Agents.git@main#subdirectory=packages/nooa-memory"

# Evaluation pipeline for agent testing
uv add "eval_pipeline @ git+https://github.com/NVIDIA-NeMo/labs-OO-Agents.git@main#subdirectory=util/eval_pipeline"
```

</details>

## Quick Start

## WARNING
This is a research tool that can be configured to execute LLM-generated code. LLM-generated code may take dangerous or unwanted actions, incuding sending private data to uncontrolled locations, deleting files, or modifying its environments.  Ensure you run NOOA agents in a sandboxed environment isolated from your primary filesystem, such as [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell).

> **Research software**  NOOA is research software, not production. We welcome contributions and fixes, but expect rough edges. 


### Choose a model

Choose from supported hosted or local [LiteLLM-supported](https://docs.litellm.ai/) model:

```python
from nooa.unifiedllm.registry import get_llm_client

llm = get_llm_client("claude-haiku-4-5")                                            # Anthropic (after `export ANTHROPIC_API_KEY=...`)
llm = get_llm_client("gpt-5-mini")                                                  # OpenAI    (after `export OPENAI_API_KEY=...`)
llm = get_llm_client("ollama_chat/qwen3:1.7b", api_base="http://localhost:11434")   # Ollama    (no key)
llm = get_llm_client("hosted_vllm/Qwen/Qwen3-1.7B", api_base="http://localhost:8000/v1")  # vLLM (no key)
```

### Your first agent

***Agents are Python objects***. Methods with `...` bodies are **generation methods** — implemented at runtime by an LLM-driven strategy. The signature defines the contract; the docstring is the prompt.

```python
import asyncio

from nooa import Agent


class FeedbackAgent(Agent, llm=llm):
    """You are an agent specializing in analyzing customer feedback."""

    async def analyze_feedback(self, text: str) -> str:
        """Analyze customer feedback for sentiment and key topics in one sentence."""
        ...


async def main():
    agent = FeedbackAgent()
    result = await agent.analyze_feedback("Great product, but shipping was slow")
    print(result)


asyncio.run(main())
```

Run the same code from your own project with `python`. You can run the checked-in example:

```bash
uv run python examples/quickstart/01_first_generation_method.py
```

Rename `analyze_feedback` to `analyze_feedback_briefly` and the output changes — your method name, parameters, and docstring *are* the prompt.

Ready for more? See [**examples/**](examples/README.md) for the full progressive tutorial — structured output, tools, strategies, tracing, context blocks, MCP, and more.

### See what your agent is doing

Every LLM call, code execution, and method invocation is traced by default — orchestrators, generation methods, and helpers, with parent-child spans preserved. If you installed the CLI and viewer dependencies, start the trace viewer and open the run in your browser:

```bash
uv run nooa start-dev        # trace viewer on http://localhost:5001
```

If the viewer isn't running, tracing is silently disabled — no configuration needed either way.

## Learn more

- **[examples/README.md](examples/README.md)** — the full progressive tutorial: structured output, tools via `self`, strategies, progressive disclosure with `doc()`, tracing, dynamic prompts, context blocks, summarization, skills, MCP, sandbox, and more.
- **[Paper](https://arxiv.org/abs/2607.20709)** — design principles, harness details, capability tests, and SWE-bench Verified / Terminal-Bench 2.0 results.
- **[AGENTS.md](AGENTS.md)** — conventions used inside this repo (helpful when reading the source).

## Contributing

For a local editable install, clone the repo and sync the development environment with `uv`:

```bash
git clone https://github.com/NVIDIA-NeMo/labs-OO-Agents.git
cd labs-OO-Agents
uv sync --group dev
```

This installs the core framework, workspace packages, development tools, the `nooa` CLI, and the trace viewer runtime in the repo's `.venv`. Run CLI commands through `uv`:

```bash
uv run nooa --help
uv run nooa start-dev       # trace viewer on http://localhost:5001
```

Enable pre-commit hooks and run the test/lint suite:

```bash
uv run pre-commit install
uv run pytest                # run tests
uv run ruff check            # lint
uv run pyright               # type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

## Citation

If you use NVIDIA-labs OO Agents in your research, please cite:

```bibtex
@techreport{nvidia_oo_agents_2026,
  title  = {NVIDIA-labs OO Agents: Native Python Object-Oriented Agents},
  author = {Furgale, Paul and Klingler, Severin and Nolan, James and Staats, Matt and
            Di Lorenzo, Gaia and Martinez Abad, Elisa and Schueler, Christian and
            Dinu, Razvan and Devoto, Alessio and Berard, Pascal and Kaplun, Gal and Sarafian, Elad and
            Roveri, Riccardo and Derczynski, Leon and Silveira Cabral, Ricardo},
  year   = {2026},
}
```

## License

Apache 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
