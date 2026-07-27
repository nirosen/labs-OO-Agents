# Identity Approval Hardening Flow

This offline example shows how the security review slices compose around one identity-changing agent method. It starts after untrusted content has influenced a victim agent to call `grant_access`, then separates observed effect telemetry, a deterministic application-owned defender recipe, backend receipt collection, and application-local finding generation. Each scenario assigns one `run_id` to its out-of-band receipts and findings so a stale receipt from another run cannot suppress the current finding.

```mermaid
flowchart LR
    I["prompt injection or unsafe task context"] --> V["NOOA victim agent"]
    V --> M["grant_access()"]
    M --> O["agent_call recorder<br/>outer wrapper"]
    O --> D["example defender middleware"]
    D -- "missing token" --> X["deny before backend"]
    D -- "otherwise" --> B["identity backend<br/>authoritative"]
    X --> E["EffectRecord<br/>decision_source=defender"]
    B --> E2["EffectRecord<br/>decision_source=backend"]
    E --> J["FdEffectSink<br/>blocking fd"]
    E2 --> J
    J --> C["read_effect_egress()<br/>records + diagnostics"]
    C --> G["require_complete_effect_egress()<br/>fail closed on gap / truncation"]
    C -.->|"gap or truncated tail"| IX["EffectEgressIncompleteError"]
    B --> R["SecurityReceipt collector<br/>run_id"]
    G --> S["application scorer"]
    R --> S
    S --> F["SecurityFinding<br/>run_id"]
```

The same attack-shaped request is replayed across vulnerable, defender-only,
and backend-hardened configurations:

| Scenario | Backend policy | Middleware | Result source | Backend call | Receipt | Finding |
| --- | --- | --- | --- | --- | --- | --- |
| `vulnerable_attack` | Approval not enforced | Off | Backend allowed | Yes | No | Yes |
| `defender_only_attack` | Approval not enforced | Missing-token rule | Defender denied | No | No | No |
| `hardened_attack` | Approval enforced | Off | Backend denied | Yes | No | No |
| `hardened_authorized` | Approval enforced with valid token | Off | Backend allowed | Yes | Yes | No |

The `Finding` column reports only what this narrow scorer emits for these scripted inputs. A zero count is not a general safety claim. `defender_only_attack` has no backend call because the middleware short-circuits the method. The test suite keeps that middleware installed and calls the permissive backend directly to pin the non-claim that any path outside the guarded method can still grant.

Run it with:

```bash
uv run python examples/security_hardening/identity_approval.py
```

Expected table output (the script then prints per-scenario framed egress IDs):

```text
scenario             | decision | source   | backend | effects | receipts | findings
---------------------+----------+----------+---------+---------+----------+---------
vulnerable_attack    | allowed  | backend  | 1       | 1       | 0        | 1
defender_only_attack | denied   | defender | 0       | 1       | 0        | 0
hardened_attack      | denied   | backend  | 1       | 1       | 0        | 0
hardened_authorized  | allowed  | backend  | 1       | 1       | 1        | 0
```

This is a composition example, not a trust claim. The descriptor-backed sink, receipt collector, scorer, and defender middleware all run in one process for deterministic local execution. `run_scenario()` scores the collector-facing records returned by `require_complete_effect_egress(read_effect_egress(...))` rather than the victim's in-memory event store, and the public gate raises instead of scoring when that stream has a sequence discontinuity or truncated trailing frame. A clean result, including an empty stream, means only that the reader saw no known gap or truncation. A same-process descriptor is still not trusted evidence. A production hardening path must hand `FdEffectSink` a separately controlled blocking descriptor, place the receipt source behind a separately trusted boundary, keep detector policy outside the victim process, and keep backend authorization authoritative. The direct-backend bypass probe stays in tests rather than the table because it intentionally leaves the observed agent method path and therefore does not create the `EffectRecord` input this narrow scorer requires.

The demo scopes only the out-of-band transport objects with `run_id`. `EffectRecord` keeps its existing runtime lineage fields; a real collector can stamp copied records through the open metadata dict when it needs the same assessment scope. The egress stream's sequence and truncation status only describe bytes received by the collector; they do not authenticate the writer, prove that omitted effects never happened, or turn transport health into a detector verdict.

The defender recipe is intentionally example-specific: it blocks only `grant_access()` requests without an approval token. It demonstrates existing `agent_call` middleware as a defense-in-depth seam; it does not become a generic NOOA policy API. The recorder is installed before the defender so the outer wrapper still records short-circuited denials; reversing that order would leave an inner recorder unable to observe the block. The demo keeps `grant_access()` async because the current `agent_call` recorder and defender observe async agent methods; a sync tool method would require a different observation seam.

On this composed branch, the same event manager and egress stream can also carry guard-shaped observer records without confusing their label with the application grant effect:

```mermaid
flowchart LR
    A["grant_access()"] --> AE["EffectRecord<br/>observer=agent_call_middleware"]
    B["execute_python result.error<br/>mapped type"] --> FE["EffectRecord<br/>observer=framework_guard"]
    AE --> C["same egress stream"]
    FE --> C
    C --> D["observer labels remain distinct"]
```

The built-in guard record classifies a mapped `ctx.result.error` type; it does not prove that the exception originated in framework code. Generated code that raises the same public exception class can mint an indistinguishable record. The record is not fed into the identity scorer in this example and does not become a vulnerability verdict.

The fake LLM client only satisfies `Agent` construction; no generation method runs in this deterministic flow.

## Out-of-Process Collector Follow-On

`codex/security-hardening-e2e-defender-provenance-egress-contract-collector` adds an example-only supervisor harness around the same identity victim. The supervisor opens one pipe, passes only the write end to the victim subprocess, passes only the read end to the collector subprocess, and joins the collector summary with the victim return code. The collector stays fact-reporting and does not call `require_complete_effect_egress()` so it can preserve truncated or gapped stream diagnostics for the supervisor.

```mermaid
flowchart LR
    S["supervisor"] -- "pipe read fd only" --> C["collector subprocess"]
    S -- "pipe write fd only" --> V["victim subprocess"]
    I["prompt injection<br/>or unsafe task context"] --> A
    V --> A["IdentityApprovalAgent"]
    A --> E["FdEffectSink"]
    E --> P["pipe"]
    P --> C
    C --> R["CollectorSummary<br/>records + stream facts"]
    V --> VX["victim returncode"]
    R --> J["CollectedScenario"]
    VX --> J
```

Run the subprocess demo with:

```bash
uv run python -m examples.security_hardening.effect_collector demo
```

To carry one framework guard-shaped record across the same pipe and show that
the collector still sees distinct `observer` labels, use the example-local
coverage knob:

```bash
uv run python -m examples.security_hardening.effect_collector demo --scenario defender_only_attack --emit-guard-effect
```

That optional path adds one validation-denial record after the identity
decision. It demonstrates label separation across the subprocess boundary; it
does not turn either record into a detector verdict.

The example also exposes one fault-injection mode that writes a partial trailing frame after a real agent effect and exits the victim non-zero, so the supervisor can return the collector's truncated-stream facts beside the victim failure:

```bash
uv run python -m examples.security_hardening.effect_collector demo --victim-fault partial_tail_crash
```

This is a real but narrow boundary improvement: the victim subprocess cannot read back bytes after it writes them into the pipe, and the pipe is not a seekable output file it can truncate. `CollectorSummary` reports the records that arrived, the first sequence discontinuity, and whether the final frame was truncated. `truncated=False` means only that the received byte stream ended between frames; it does not mean the record set is authentic or complete.

The collector path carries effect records and victim status only. It does not move receipts, findings, or the same-process demo's incomplete-stream scoring refusal into the subprocess boundary. The collector still accepts a valid-looking forged frame from any writer holding the write end, and an empty stream followed by a clean victim exit is still indistinguishable from a victim that intentionally omitted an effect and exited cleanly. These are same-user, same-host processes with no privilege boundary between them; this branch demonstrates descriptor separation, not sandboxing, attestation, prevention, or a detector verdict. It keeps process lifecycle in the example instead of adding another core NOOA collector API.
