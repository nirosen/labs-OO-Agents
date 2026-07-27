# Identity Approval Hardening Flow

This offline example shows how the security review slices compose around one identity-changing agent method. It starts after untrusted content has influenced a victim agent to call `grant_access`, then separates observed effect telemetry, backend receipt collection, and application-local finding generation.

```mermaid
flowchart LR
    I["prompt injection or unsafe task context"] --> V["NOOA victim agent"]
    V --> M["grant_access()"]
    M --> O["agent_call observer"]
    O --> E["EffectRecord"]
    E --> J["JsonlEffectSink"]
    M --> B["identity backend"]
    B --> R["SecurityReceipt collector"]
    E --> S["application scorer"]
    R --> S
    S --> F["SecurityFinding"]
```

The same attack-shaped request is run twice:

| Scenario | Backend policy | Result | Receipt | Finding |
| --- | --- | --- | --- | --- |
| `vulnerable_attack` | Approval not enforced | Allowed | No | Yes |
| `hardened_attack` | Approval enforced | Denied | No | No |
| `hardened_authorized` | Approval enforced with valid token | Allowed | Yes | No |

Run it with:

```bash
uv run python examples/security_hardening/identity_approval.py
```

Expected output:

```text
scenario            | decision | effects | receipts | findings
--------------------+----------+---------+----------+---------
vulnerable_attack   | allowed  | 1       | 0        | 1
hardened_attack     | denied   | 1       | 0        | 0
hardened_authorized | allowed  | 1       | 1        | 0
```

This is a composition example, not a trust claim. The JSONL sink, receipt collector, and scorer all run in one process for deterministic local execution. A production hardening path must place the sink and receipt source behind a separately trusted boundary and keep detector policy outside the victim process.
