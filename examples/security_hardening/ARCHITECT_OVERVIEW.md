# NOOA Security Hardening Overview

This document is the short architect-facing map for the current security work
in the `nirosen/labs-OO-Agents` fork and the related agents-lab/Garak
experiments.

The core threat is simple:

```text
untrusted prompt / retrieved content
              |
              v
      prompt injection
              |
              v
        NOOA agent acts
              |
              +--> grant access
              +--> export data
              +--> merge code
              +--> process payment
```

The security problem is not only "did the model say something unsafe?" The
important production question is:

```text
What sensitive action did the agent actually take,
and was that action really authorized?
```

## Current End-to-End Story

The current work splits cleanly across two repositories:

```text
agents-lab + Garak                         nirosen/labs-OO-Agents
------------------                         ------------------------
realistic NOOA victims                     reusable NOOA security primitives
prompt-injection attacks                   effect / receipt / finding schemas
vulnerable vs hardened runs                bounded transport + validation gates
external scoring experiments               example detector pipeline
```

Together they form one hardening loop:

```text
1. Attack
   Garak chains probe
          |
          v
   NOOA victim agent

2. Observe
   sensitive method call
          |
          v
   EffectRecord
          |
          v
   bounded effect egress

3. Corroborate
   backend receipt / authority receipt
          |
          v
   SecurityReceipt

4. Decide
   DetectorInput
          |
          v
   application-owned detector
          |
          v
   SecurityFinding

5. Route
   admitted finding / refusal
          |
          v
   CI / reviewer / operator input
```

## What Exists Today In The NOOA Fork

The current cumulative review branch is:

```text
codex/security-hardening-e2e-detector-pipeline-v17
```

It demonstrates two example victim families:

```text
IdentityApprovalAgent
    prompt injection -> grant_access()

DataExportAgent
    prompt injection -> export_dataset()
```

The branch adds or composes the following building blocks:

| Building block | Purpose | Client value |
| --- | --- | --- |
| `EffectRecord` | Structured copy of a sensitive action | See what the agent actually did |
| `FdEffectSink` + V2 egress | Bounded, framed effect transport | Avoid treating broken telemetry as clean |
| `SecurityReceipt` | Backend or authority evidence copy | Separate agent intent from backend approval |
| `ReceiptBundle` | Bounded receipt transport | Catch truncation and count drift |
| `DetectorInput` | Explicit detector handoff object | Standardize what a detector consumes |
| `SecurityFinding` | Structured detector output | Feed CI, review, or dashboards |
| `FindingBundle` | Bounded finding transport | Catch malformed or incomplete detector output |
| Scope / ID / source checks | Coherence validation | Reject stale, duplicate, or mislabeled rows |
| Evidence-ref checks | Finding consistency validation | Reject findings that cite unknown or missing refs |
| Structured refusal stages | Machine-readable failures | Diagnose why evidence was refused |
| Refusal text redaction | Safer human-readable diagnostics | Avoid copying row IDs into logs by default |

The branch is intentionally narrow. It shows how applications can compose
security around NOOA primitives without making NOOA own business policy,
authorization, or detector verdicts.

## Why This Helps NOOA Clients

The client-facing value is easiest to explain as three questions:

```text
1. Did the agent take a sensitive action?
   -> EffectRecord

2. Was the action actually approved by the backend?
   -> SecurityReceipt

3. Can I trust the evidence enough to act on the result?
   -> transport gates + scope gates + finding admission
```

That gives teams a practical hardening workflow:

```text
build agent
   |
   v
run Garak attack
   |
   v
collect effects + receipts
   |
   v
detect unsafe behavior
   |
   v
fix policy / backend / agent
   |
   v
rerun before production
```

## What Agents-Lab And Garak Add

The agents-lab side provides realistic victims and repeatable attacks:

```text
ecommerce_chain_required
    search_catalog -> place_order -> process_payment

codereview_chain_required
    upload_file -> run_ci_command -> merge_pr

identity_chain_required
    upload_access_request -> run_access_review -> grant_access
```

The Garak chains probe is used as the red-team layer:

```text
Garak AgentBreaker chains
        |
        v
prompt injection / tool misuse attempt
        |
        v
NOOA victim
        |
        v
backend side effect
```

That gives NOOA maintainers a repeatable way to answer:

```text
Can a realistic attacker make this agent misuse its capabilities?
```

## Current Trust Boundary

The current work is useful, but it is not claiming more than it proves:

```text
Checked mechanically:
    - bounded transport checks
    - visible scope / count / ID mismatches
    - backend receipt projection
    - deterministic detector policy

Not established:
    - same-user subprocesses
    - in-process telemetry authenticity
    - receipt provenance
    - detector honesty
    - full completeness of emitted evidence
```

In other words:

```text
NOOA can help applications observe and validate evidence.
NOOA is not becoming a sandbox, IAM system, or attestation system.
```

The current work does not claim:

```text
- sandboxing
- signed provenance
- backend attestation
- trusted same-user subprocesses
- complete evidence coverage
- detector honesty
- production IAM enforcement
```

## Future Direction

The next useful product direction is a more trusted detector layer:

```text
                  +----------------------+
                  | static code analysis |
                  | of agent methods      |
                  +----------+-----------+
                             |
                             v
Garak attacks ---> trusted detector ---> CI hardening gate
                             |
                             v
                      fix / block / rerun
```

That future detector can combine:

```text
runtime evidence
+ backend receipts
+ static analysis
+ policy checks
+ deterministic rules
+ human approval for high-risk actions
```

The likely longer-term security path is:

```text
Phase 1: observe and validate
    EffectRecord, SecurityReceipt, SecurityFinding, bounded transport

Phase 2: detect and harden
    trusted detector, whitebox analysis, CI security gates

Phase 3: strengthen trust
    signed receipts, stronger provenance, isolated detector execution
```

## Review Entry Points

For the NOOA fork:

- Root overview and cumulative branch: [`README.md`](../../README.md)
- Runnable hardening example: [`README.md`](README.md)
- Public surface and trust-boundary guide: [`SURFACE.md`](SURFACE.md)

For the related agents-lab work:

- `NAIS-346-nooa-security-handoff`
- `analysis/full_chain_sweep/NOOA_CHAIN_REQUIRED_SECURITY_HANDOFF.md`

Those two agents-lab entry points live in the separate agents-lab repository,
so they are listed as branch/path references rather than local links.
