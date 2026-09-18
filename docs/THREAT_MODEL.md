# secure-agents: Threat Model and Security Posture

**Version** 0.1 (proposed) · **Date** 2026-09-18 · **Owner** Yoan
**Status** Draft for review. Sections marked *Open* are decisions, not gaps to be silently filled.

---

## 0. How to use this document

This is not a list of worries. It is the gate every API decision in secure-agents passes through. It has three parts that do work:

- **Section 6, the invariants.** Ten statements that hold for every build. An API that breaks one is rejected, not debated.
- **Section 7, the threat areas.** Each threat carries a **position**: exactly one of four values, defined below. There is no "we should look into that."
- **Section 9, the API gate.** A five-question checklist with worked rejections, so a contributor can self-serve the answer before opening a PR.

### The four positions

| Position | Meaning | What we may claim publicly |
|---|---|---|
| **Defended** | The SDK enforces a mechanism that stops this, deterministically, outside the model loop. | "secure-agents prevents X." |
| **Bounded** | The threat succeeds. The SDK limits what it reaches. | "secure-agents limits the blast radius of X." |
| **Delegated** | The SDK defines the seam and the default; the deployer supplies the mechanism. | "secure-agents gives you the hook for X; you bring the backend." |
| **Out of scope** | The SDK does nothing. Documented so nobody assumes otherwise. | "secure-agents does not address X." |

A control that only works when the model cooperates is never **Defended**. At best it is **Bounded**.

### Normative language

MUST / MUST NOT are binding on the implementation. SHOULD signals a default that may be overridden by the deployer with an explicit, auditable opt-out. MAY is genuinely optional.

---

## 1. The claim, in one sentence

**secure-agents assumes the model is an untrusted, attacker-influenceable component, and places every security decision outside the model's reach, in code a reviewer can read in one sitting.**

Everything below is a consequence of that sentence. If a proposed feature only works because the model behaves, it does not belong in the security path, though it may belong in the SDK as ergonomics or telemetry.

The adoption argument follows from the same sentence. The reason a developer picks this SDK is not that it has more features than the alternatives. It is that they can read the whole enforcement path and satisfy themselves it is correct. That is a hard constraint on API size, not a marketing line: **if the security-relevant surface cannot be read in an afternoon, the differentiator is gone.**

---

## 2. Scope and system model

### 2.1 The system we are modelling

secure-agents is assumed to be a library, embedded in a host application the deployer writes, that runs an agent loop:

```
  host application (trusted, deployer's code)
        │
        │  constructs Agent(policy, tools, model, budget)
        ▼
  ┌─────────────────────────────────────────────────┐
  │  agent loop  (secure-agents, trusted code)      │
  │                                                 │
  │   context ──► model client ──► model provider   │  B1
  │      ▲                │                         │
  │      │                ▼                         │
  │      │           proposed tool call             │
  │      │                │                         │
  │      │                ▼                         │
  │      │        ┌───────────────┐                 │
  │      │        │ policy engine │  ← no model input│
  │      │        └───────┬───────┘                 │
  │      │                │ decision (allow/deny/ask)│
  │      │                ▼                         │
  │      │           tool invoker                   │  B2
  │      │                │                         │
  │      └──── result ────┤                         │
  └───────────────────────┼─────────────────────────┘
                          ▼
                    sandbox boundary                   B3
                          │
                    egress boundary                    B4
                          ▼
                   downstream systems
```

Three properties of this shape are load-bearing and are themselves design decisions:

1. **The policy engine is not in the conversation.** It takes the proposed call, the declared tool metadata, and the provenance of the arguments. It never takes model-authored free text as an input.
2. **The agent loop is a library, not a service.** There is no secure-agents daemon, control plane, or hosted component. The trust boundary at the top of the diagram is the deployer's process.
3. **Tools are declared, never discovered into authority.** A tool becoming visible to the model is a separate act from a tool becoming callable.

*Open (for the API thread): whether the loop is single-threaded and synchronous by default. Async concurrency across tool calls creates TOCTOU windows in policy evaluation and makes the audit order non-obvious. Recommendation: sequential by default, concurrency opt-in per tool group.*

### 2.2 In scope

The library, its defaults, its declared extension points, its dependency set, its release artifacts, and the guidance it ships.

### 2.3 Out of scope

The deployer's application logic. The correctness of individual tool implementations. The security of downstream systems the tools reach. The model provider's infrastructure. The host operating system and kernel.

---

## 3. Assets

Ordered by what an attacker actually wants.

| ID | Asset | Why it is worth taking |
|---|---|---|
| AS-1 | Credentials the agent can use (API tokens, OAuth grants, cloud creds, DB passwords) | Durable access that outlives the run |
| AS-2 | Data in the agent's context (user data, retrieved documents, prior turns) | Direct exfiltration target |
| AS-3 | The agent's authority over downstream systems | Actions the attacker cannot take directly: the confused-deputy prize |
| AS-4 | The host process and filesystem | Lateral movement, persistence, other tenants' data |
| AS-5 | Outbound network from the host | Exfil channel, pivot into internal networks |
| AS-6 | Persistent agent memory | Poison once, influence every later run |
| AS-7 | The audit record | Cover the tracks; also the deployer's only evidence |
| AS-8 | The policy configuration | Own this and everything else follows |
| AS-9 | Compute and spend | Cost-exhaustion, cryptomining in a code-exec tool |

---

## 4. Adversaries

| ID | Adversary | Capability we assume | Assumed present by default |
|---|---|---|---|
| AD-1 | **Content injector** | Controls text the agent will read: a web page, an email, a PDF, a code comment, a RAG document, a tool's return value, an MCP server's tool description. No other access. | **Yes.** This is the default-on adversary. |
| AD-2 | **Hostile tool / MCP server** | Controls a tool's code, schema and description; can change them after approval (rug pull); can return crafted results. | Yes, for any third-party or remote tool |
| AD-3 | **Malicious agent user** | Talks to the agent through its intended interface, tries to reach beyond their own authority. | Yes, for any multi-user deployment |
| AD-4 | **Supply-chain attacker** | Compromises a dependency of secure-agents, or a release artifact. | Yes |
| AD-5 | **Log or trace reader** | Reads observability output. Internal, semi-trusted, high volume. | Yes |
| AD-6 | **Hostile model endpoint** | Returns arbitrary tool calls, arbitrary text; a MITM or a compromised provider. | Assumed capable, not assumed active |
| AD-7 | **Host-level attacker** | Already has code execution on the host outside the sandbox. | **No.** Game over; see §8. |

AD-1 is the one that shapes the design. Every other adversary is a variation on a well-understood problem. AD-1 is the novel one, and the honest position on it is in §7.1.

---

## 5. Trust boundaries

| ID | Boundary | Crossing inbound is… |
|---|---|---|
| **B1** | Agent loop ↔ model provider | **Untrusted.** Every token the model returns, including tool-call arguments, is attacker-influenceable data. |
| **B2** | Agent loop ↔ tool implementation | **Untrusted in both directions.** Arguments going out may be attacker-shaped; results coming back are content (AD-1's channel) and metadata is AD-2's channel. |
| **B3** | Tool execution ↔ host | **Enforced by the sandbox.** Default-deny on filesystem and process. |
| **B4** | Sandbox ↔ network | **Enforced by egress policy.** Default-deny. |
| **B5** | Agent process ↔ secret material | **One-way.** Handles cross inward; values cross outward only at the transport call site. |
| **B6** | Content ↔ context window | **Labelled.** Nothing enters context without provenance. |

The single most common design mistake in agent frameworks is treating B1 as a trust boundary in one direction only: careful about what you send, careless about what comes back. In this SDK, **B1 inbound is the primary boundary.**

---

## 6. Invariants

These hold in every build. A change that breaks one is a breaking security change and needs an explicit, versioned decision, not a review comment.

- **INV-1 — No implicit authority.** A tool call executes only if it matches a decision derived from statically declared policy. The empty policy permits nothing. There is no code path in which "the model said it was fine" contributes to a decision.

- **INV-2 — Model output is data, never code or control.** No model-produced value is ever `eval`'d, interpolated into a shell string, used as a file path without canonicalisation and containment check, used as a URL without allowlist check, or used as an input to the policy engine.

- **INV-3 — Provenance is carried and is monotone.** Every context element carries a provenance label. Model output produced in a context containing any `Untrusted` element is itself `Untrusted`. Taint never decreases automatically; it is cleared only by an explicit, logged, non-model act.

- **INV-4 — Secrets never enter the context window.** The agent holds credential *handles*. Values are resolved at the transport call site inside the tool, after the policy decision. A secret value appearing in a prompt, a tool argument, a model response, a serialised checkpoint, or a log line is a bug of the highest severity.

- **INV-5 — Egress is default-deny.** A tool reaches only the hosts it declared. Link-local, loopback, and private ranges are denied unless named explicitly.

- **INV-6 — The audit record precedes the effect.** The decision and the resolved call are durably recorded *before* the side effect is attempted, and the outcome is recorded after. A crash mid-call leaves evidence, not silence.

- **INV-7 — The policy path is not model-writable.** No prompt, tool result, memory entry, or tool description can change policy, widen a grant, add a tool, raise a budget, or alter an approval prompt. The policy engine's inputs are: declared tool metadata, resolved call arguments, provenance labels, and deployer configuration. That list is closed.

- **INV-8 — Fail closed.** Any error in policy evaluation, provenance tracking, sandbox setup, or egress enforcement aborts the call. Degraded mode is denial, never permission.

- **INV-9 — Approval text is not model-authored.** When a human is asked to approve, they are shown the resolved call: tool name, arguments, target host, effect class. The model's description of its own intent MAY be shown, clearly separated and clearly labelled as untrusted.

- **INV-10 — Everything security-relevant is declared, not inferred.** Effect class, secrets required, hosts reachable, isolation tier needed, and whether tainted input is acceptable are all declared on the tool. The SDK never guesses from the tool's name, docstring, or behaviour.

---

## 7. Threat areas

### 7.1 Prompt injection

**Position on the class as a whole: Bounded. Not Defended. This is a load-bearing honesty commitment and it goes in the README, not just here.**

There is no known method of reliably distinguishing instructions from data in a natural-language context window. Any SDK claiming to prevent prompt injection is claiming a research result nobody has. secure-agents therefore assumes **injection succeeds** and spends its effort on what the injected model can then reach.

| ID | Threat | Adversary | Position |
|---|---|---|---|
| T-PI-1 | Injected content in a fetched page/email/document redirects the agent's actions | AD-1 | **Bounded** |
| T-PI-2 | Injected content triggers exfiltration of context data through a permitted tool | AD-1 | **Bounded** (see the trifecta check) |
| T-PI-3 | Injected content in a *tool description* steers the model at prompt-assembly time | AD-2 | **Defended** (digest pinning, §7.2) |
| T-PI-4 | Injected content persisted into memory and replayed in later runs | AD-1 | **Defended** (provenance on memory writes, §7.6) |
| T-PI-5 | Injection escalates the agent's own authority (adds a tool, widens a grant) | AD-1 | **Defended** (INV-7) |
| T-PI-6 | Injection causes an irreversible external action (payment, send, delete, deploy) | AD-1 | **Bounded**, → **Defended** when an approval gate is configured on `External` |
| T-PI-7 | Invisible-text injection (zero-width, white-on-white, HTML comments, alt text) | AD-1 | **Out of scope** as a detection problem; irrelevant because T-PI-1's bounds do not depend on visibility |

**Mechanisms**

1. **Provenance labelling (INV-3).** Every context element is `Trusted` (the deployer's system prompt, the authenticated principal's direct instruction) or `Untrusted` (everything else: tool results, retrieved documents, fetched content, tool descriptions from remote servers, memory written during a tainted run).

2. **Effect classes on tools (INV-10).** Every tool declares exactly one:
   - `Pure` — no side effect, no secrets, no egress
   - `Read` — reads data inside the trust domain
   - `Write` — mutates state the principal owns
   - `External` — moves data or causes effects outside the trust domain (send, post, pay, publish, call a third-party API)

3. **The tainted-call rule.** A tool with effect `Write` or `External` MUST NOT be invoked with `Untrusted`-derived arguments unless the deployer has either declared `accepts_tainted=True` on that tool or configured an approval gate. This is the single rule that converts "the model got hijacked" into "the model got hijacked and could only read."

4. **The trifecta check (static, at construction).** Borrowing Simon Willison's framing: the dangerous combination is *access to private data* + *exposure to untrusted content* + *ability to communicate externally*. All three are computable from the declared tool set before the agent ever runs. When all three are present, `Agent(...)` **fails construction** unless the deployer passes an explicit acknowledgement or attaches an approval gate to `External`. Concretely:

   ```python
   Agent(tools=[read_inbox, fetch_url, send_email])
   # SecurityConfigError: this agent can read private data (read_inbox),
   # ingest untrusted content (fetch_url), and communicate externally
   # (send_email). An injected page can exfiltrate the inbox.
   # Resolve by one of:
   #   - approval_gate=HumanApproval(on=Effect.External)
   #   - send_email.restrict(recipients=["..."])
   #   - acknowledge_exfiltration_risk="<reason recorded in the audit log>"
   ```

   This is the highest-value thing in the SDK and it costs about eighty lines. It catches the actual CVE-shaped mistakes people are shipping today, it fires at build time rather than at 3am, and it teaches the threat model by existing. **Design this before designing anything else.**

5. **Context minimisation.** Tool results are size-capped and truncated deterministically. URLs in model output are never auto-fetched. Content is never auto-followed across a fetch.

**Explicit non-mechanisms.** The following MUST NOT ship as security controls, and MUST NOT be described as such if they ship as telemetry:
- Injection classifiers or "prompt firewalls" as an allow/deny gate. They may emit a signal; the signal may be logged; it MUST NOT gate.
- Delimiter schemes, spotlighting, or "ignore instructions in the following text" preambles, presented as protection. They may raise the attacker's cost. They do not change any position in the table above.
- Asking the model to self-assess whether it is being manipulated.

*Open: whether to ship a `plan_then_execute` mode (plan fixed before untrusted content is read, capability-constrained execution afterwards, in the spirit of the CaMeL work) as a first-class construct or as an example. It is genuinely stronger than the tainted-call rule for some workloads and genuinely more restrictive to write against. Recommendation: example first, promote if adopted.*

**Residual risk.** An agent whose legitimate job is to read untrusted content and act on it externally can be made to act wrongly, within the bounds of its declared authority, by whoever controls that content. No configuration removes this. The SDK's job is to make the bound visible and small, and to make the deployer say so out loud.

---

### 7.2 Tool abuse and over-broad permissions

**Position: mostly Defended. This is the area where an SDK can honestly claim prevention.**

| ID | Threat | Adversary | Position |
|---|---|---|---|
| T-TA-1 | Tool granted broader scope than the task needs (`admin` where `read` suffices) | AD-1, AD-3 | **Delegated** (SDK makes scope declarable and audits it; the deployer chooses) |
| T-TA-2 | Confused deputy: agent acts with authority the requesting user lacks | AD-3 | **Delegated** (principal propagation seam; downstream authz is the deployer's) |
| T-TA-3 | Argument injection: model-authored string reaches a shell, SQL, or template | AD-1 | **Defended** (INV-2; no string-command API exists) |
| T-TA-4 | Path traversal out of a permitted directory | AD-1 | **Defended** (canonicalise, then containment check, then open; no TOCTOU re-resolution) |
| T-TA-5 | Tool name shadowing: a second server registers `send_email` over the first | AD-2 | **Defended** (namespaced addressing; collisions are a construction error) |
| T-TA-6 | Rug pull: an approved MCP server changes a tool's description or schema later | AD-2 | **Defended** (digest pinning) |
| T-TA-7 | Malicious tool description poisons the system prompt | AD-2 | **Defended** (digest pinning + `Untrusted` provenance on remote descriptions) |
| T-TA-8 | Unbounded loop or cost exhaustion | AD-1, AD-9 | **Defended** (hard budgets, abort not warn) |
| T-TA-9 | Non-idempotent retry duplicates an effect (double payment, double send) | — | **Defended** (idempotency key required for `Write`/`External` retries) |
| T-TA-10 | The tool implementation is itself buggy or hostile in its own domain | AD-2 | **Out of scope** — the sandbox bounds it (§7.4), the SDK does not audit it |

**Mechanisms**

- **Capability handles, not ambient tools.** A tool is callable because a capability for it was passed into the agent, not because it exists in a registry. Visibility to the model and callability are separate.
- **Typed arguments, strict validation, reject not coerce.** A schema violation is a denial and an audit event, not a repair attempt. Do not "helpfully" fix the model's malformed JSON into a valid dangerous call.
- **No string-command surface.** `run(argv: list[str])` exists; `run(cmd: str)` does not, anywhere, at any privilege level. Same for SQL: parameterised only. This is an API-shape rule, which is why it is here rather than in a lint.
- **Digest pinning.** At construction the SDK hashes each tool's `(namespace, name, description, schema, effect, hosts, secrets)`. The deployer MAY pin the set. A changed digest fails construction with a diff. This is the cheapest defence in the whole document against the most under-appreciated supply-chain path in agent systems.
- **Argument-level policy.** Policy sees resolved arguments, not just tool names. `delete_file` on `/tmp/x` and on `/etc/passwd` are different decisions.
- **Budgets.** Per run: max tool calls, max tokens, max wall-clock, max spend, max calls per tool. Exceeding aborts the run and records why.

**Non-goals.** The SDK does not evaluate whether a tool's declared scope is appropriate for the task, does not perform authorization for downstream systems, and does not sanitise a tool's return value.

---

### 7.3 Secret handling

**Position: Defended for the leak paths the SDK controls; Delegated for storage and lifecycle.**

| ID | Threat | Position |
|---|---|---|
| T-SE-1 | Secret placed in a prompt or system prompt | **Defended** (type-level; a `Secret` has no path into context) |
| T-SE-2 | Secret appears in a tool argument the model produced | **Defended** (secrets resolve inside the tool, after policy; the model never sees or names a value) |
| T-SE-3 | Secret written to logs, traces, or spans | **Defended** (redacting `__repr__`/`Display`, no `Serialize`) plus **Bounded** (sink-side redaction as defence in depth) |
| T-SE-4 | Secret in an exception message or stack trace | **Defended** (same type property; error paths carry handles) |
| T-SE-5 | Secret persisted in a checkpoint or memory snapshot | **Defended** (non-serialisable by construction) |
| T-SE-6 | Secret exfiltrated by a tool that legitimately holds it | **Bounded** (per-tool grants + egress allowlist limit where it can go) |
| T-SE-7 | Secret storage, rotation, expiry, revocation | **Delegated** — the SDK is not a secret manager |

**Mechanisms**

- A `Secret[T]` wrapper whose only accessor is `.expose()`, callable at the transport boundary. Redacted `repr`, no serialisation, no `__str__` leak, no logging adapter that unwraps it.
- **Per-tool grants.** `tool.requires_secret("GITHUB_TOKEN")`. A tool that did not declare a secret cannot obtain it, including inside the same process, including via the environment: the sandbox environment is constructed per-tool from declared grants, not inherited.
- **Environment hygiene.** The sandbox starts from an empty environment. `AWS_*`, `GITHUB_TOKEN`, and everything else in the host's environment is absent unless granted. This matters more than any redaction filter: the common real-world leak is not a log line, it is a code-execution tool inheriting the host's environment and printing it.
- Short-lived credentials preferred; the grant API SHOULD accept a callable resolver so the deployer can mint a scoped token per call.

**Residual.** A tool that holds a credential and can reach the network can send that credential somewhere the allowlist permits. Nothing here prevents a hostile tool implementation from abusing a credential it was legitimately granted. That is AD-2 plus a grant, and the answer is the grant, not a filter.

---

### 7.4 Sandboxing and process isolation

**Position: Delegated. The SDK defines the boundary and enforces the tier requirement. It does not implement isolation and MUST NOT claim to.**

This is where agent SDKs most often overclaim. A Python library cannot contain code it executes in the same interpreter. Saying so plainly is worth more to a security-engineer audience than any feature.

**Isolation tiers**

| Tier | Mechanism | What it actually stops | Honest use |
|---|---|---|---|
| `none` | In-process call | Nothing. A bug in the tool is a bug in your process. | Pure functions over validated inputs |
| `process` | Subprocess, clean env, rlimits, seccomp/landlock where available, no inherited fds | Accidental damage, resource exhaustion, casual filesystem reads | First-party tools you wrote |
| `container` | OCI container, read-only rootfs, no host mounts, own netns, dropped caps, non-root, no new privileges | Filesystem access to the host, most persistence, network by default | Third-party tools; **minimum for any code execution** |
| `vm` | microVM / hypervisor, deployer-supplied | Kernel-surface attacks, container escapes | Untrusted code at scale, multi-tenant |

**Rules**

- Every tool declares the minimum tier it needs (INV-10). The runtime refuses to run a tool below its declared tier. Fail closed (INV-8).
- **Any tool that executes model-authored code — shell, interpreter, notebook, `eval` of any kind — MUST declare at least `container`.** The SDK refuses in-process code execution outright. No flag overrides this; a deployer who wants it can call `subprocess` themselves and own it.
- The SDK ships `none` and `process` backends because they can be implemented correctly in a small amount of code. `container` and `vm` are interface + reference adapter; the deployer supplies the runtime.
- Filesystem access is an explicit mount list, never "the current working directory."

**Out of scope, stated plainly.** Container escapes. Kernel vulnerabilities. Side channels between tenants on shared hardware. Anything requiring a hypervisor we do not ship. **secure-agents does not claim multi-tenant isolation on a shared kernel.** If you need that, you need `vm`, and that is your infrastructure decision, not ours.

---

### 7.5 Network egress

**Position: Defended for the mechanical paths; Bounded for anything flowing through a channel you deliberately opened.**

| ID | Threat | Position |
|---|---|---|
| T-NE-1 | Exfiltration to an attacker-chosen URL from a fetch tool | **Defended** (allowlist) |
| T-NE-2 | SSRF to cloud metadata (`169.254.169.254`, `metadata.google.internal`) | **Defended** (link-local and metadata names denied by default) |
| T-NE-3 | SSRF into internal RFC1918 / CGNAT ranges | **Defended** (denied by default, nameable explicitly) |
| T-NE-4 | DNS rebinding after the allowlist check | **Defended** (resolve once, pin the IP, connect to the pinned IP) |
| T-NE-5 | Redirect chain to a non-allowlisted host | **Defended** (each hop re-checked; no transparent redirect following) |
| T-NE-6 | Exfiltration via markdown image/link rendered by a UI | **Defended** in first-party helpers (no auto-rendering of model-produced image URLs); **Delegated** in the deployer's UI, and called out loudly in the docs |
| T-NE-7 | DNS-based exfiltration (data in subdomain labels) | **Bounded** — only meaningful at `container`+ where the SDK controls the resolver; **Out of scope** at `none`/`process` |
| T-NE-8 | Exfiltration through a permitted channel (the agent can email, so it can email data out) | **Bounded** — this is the trifecta case; the answer is §7.1's check, not a network control |
| T-NE-9 | Timing and covert channels | **Out of scope** |

**Mechanisms.** Default-deny egress; per-tool declared `hosts` with scheme and port; deny-list for loopback, link-local, RFC1918, CGNAT (100.64/10), unique-local IPv6, and known metadata hostnames, applied *after* resolution; resolve-then-pin; explicit per-hop redirect checks; request and response size caps.

**Where enforcement lives matters.** At tier `container` the egress rules are enforced at the network namespace and are real. At tier `process` and `none` they are enforced in the SDK's HTTP client, which a tool can simply not use. Document per tier: **egress policy is advisory below `container`.** Saying this is what makes the rest of the table believable.

---

### 7.6 Memory and persistent state

**Position: Defended for the contamination paths; Delegated for storage.**

| ID | Threat | Position |
|---|---|---|
| T-ME-1 | Injected content written to long-term memory, influencing later runs | **Defended** (provenance persists with the entry; tainted memory is `Untrusted` on read, forever) |
| T-ME-2 | Memory bleed across users or tenants | **Defended** (memory is namespaced by principal; no global namespace exists in the API) |
| T-ME-3 | Memory entry influences a policy decision | **Defended** (INV-7) |
| T-ME-4 | Unbounded memory growth used as a denial or cost attack | **Defended** (per-namespace caps) |
| T-ME-5 | Memory store confidentiality at rest | **Delegated** |

**Mechanism worth stating explicitly.** Memory writes are an **explicit tool call with `Write` effect**, not an automatic side effect of the loop. Automatic memory is a persistence primitive handed to AD-1 for free, and the convenience is not worth it. A deployer who wants automatic memory can wire it in three lines and will then understand what they did.

---

### 7.7 Multi-agent delegation

**Position: Defended for authority; Bounded for correctness.**

| ID | Threat | Position |
|---|---|---|
| T-MA-1 | Sub-agent inherits the parent's full authority | **Defended** (delegation attenuates; a sub-agent's capability set MUST be a subset of the parent's) |
| T-MA-2 | Trust laundering: a sub-agent's output is treated as `Trusted` by the parent | **Defended** (INV-3 — sub-agent output carries the maximum taint of its inputs) |
| T-MA-3 | Injection propagates across agents, each widening the reach | **Bounded** (attenuation bounds the ceiling; the propagation still happens) |
| T-MA-4 | Cycles and runaway spawning | **Defended** (depth limit and shared budget across the tree, not per agent) |

The rule that does the work: **budgets and capabilities are held by the run, not by the agent.** A tree of agents shares one budget and one shrinking capability set. Anything else turns delegation into privilege escalation with extra steps.

---

### 7.8 Supply chain of secure-agents itself

**Position: Defended to the limits of current tooling.**

For a security SDK, the dependency graph *is* part of the threat model, and it is also part of the adoption argument. A security library with two hundred transitive dependencies has a credibility problem before anyone reads the code.

- **Hard cap on direct runtime dependencies.** Proposed: **five.** A dependency is added only if it removes more attack surface than it adds. This is a project rule with a number in it, enforced in CI, because "we try to keep deps minimal" is not a control.
- Pinned, hashed lockfile. Reproducible builds where the ecosystem allows.
- Signed releases with provenance attestation (SLSA build level 3 target) and a published SBOM.
- **No install-time code execution.** No build hooks, no postinstall scripts, no network access during install.
- Optional integrations (containers, MCP clients, specific model providers) are extras, not core. Installing the core installs the enforcement path and nothing else.
- Security policy: `SECURITY.md`, a disclosure address, a stated response window, and CVE issuance. This is table stakes for anyone deciding whether to depend on it.

---

### 7.9 Audit and observability

**Position: Defended for completeness and ordering; Delegated for retention and tamper-proofing.**

Every policy decision emits a record, before the effect (INV-6), containing at minimum:

```
run_id, step, timestamp, principal,
tool (namespace.name), tool_digest,
arguments (redacted, hashed where large),
provenance of each argument, effect class,
decision (allow | deny | approved_by:<id>), policy_rule_id,
isolation_tier, egress_targets,
outcome (ok | error | denied | aborted), duration, cost
```

Properties: append-only; hash-chained so a gap or edit is detectable; redaction applied at construction, not at the sink; structured, with an OpenTelemetry mapping.

**Non-goals.** The SDK is not a SIEM. Hash chaining gives tamper-*evidence*, not tamper-*proofing*; real integrity needs external anchoring, which is the deployer's to arrange. Retention, access control on the log, and alerting are all **Delegated**, and the log itself is an asset (AS-7) that will contain sensitive argument data.

---

## 8. Explicit non-goals

State these in the README, not only here. For a security audience, a crisp non-goals list is a stronger adoption signal than a feature list.

secure-agents does **not**:

1. Prevent prompt injection, or claim to detect it.
2. Provide model safety, alignment, content moderation, or jailbreak filtering.
3. Implement a sandbox. It defines the boundary and enforces tier requirements.
4. Act as a secret manager, identity provider, or policy server.
5. Perform DLP or PII detection.
6. Make an unsafe tool safe. A tool that deletes production, invoked correctly, deletes production.
7. Defend against a malicious model provider beyond TLS verification and optional pinning.
8. Guarantee multi-tenant isolation on a shared kernel.
9. Defend against an attacker who already has code execution on the host outside the sandbox (AD-7).
10. Provide compliance certification. The mappings in §11 are a convenience for the person filling in the questionnaire, and nothing more.
11. Protect against a deployer who disables the checks. Every override is explicit, logged, and named so it shows up in a code review.

---

## 9. The API gate

Every API proposal answers these five. A "yes" to any of 1 through 4 is a rejection, not a discussion.

1. **Does any model-produced value reach the policy path?** (INV-7)
2. **Does this create authority that was not explicitly declared?** (INV-1, INV-10)
3. **Does it require the model to behave correctly for the security property to hold?** (§1)
4. **Does it fail open on error?** (INV-8)
5. **Can a reader tell, from the call site alone, what this agent can reach?**

Question 5 has no mechanical answer but it is the adoption question. If reading `Agent(...)` does not tell you the blast radius, the API is wrong even when it is safe.

### Worked rejections

| Proposal | Verdict | Rule |
|---|---|---|
| `tool(confirm: bool)` where the model sets `confirm` | Reject | INV-7. The model cannot be an input to its own authorisation. |
| `run_shell(cmd: str)` | Reject | INV-2. Ship `run(argv: list[str])`. |
| Auto-register every tool an MCP server advertises | Reject | INV-1, T-TA-6. Discovery is not approval. |
| `safe_mode=True` that enables an injection classifier gate | Reject | §1, §7.1. Classifiers do not gate. |
| `Agent(tools=[...])` with no policy, permitting everything by default | Reject | INV-1. Empty policy permits nothing. |
| An approval prompt rendering the model's summary of the action | Reject | INV-9. Show the resolved call. |
| `on_policy_error: 'continue'` | Reject | INV-8. |
| `memory.auto_write=True` by default | Reject | §7.6. A persistence primitive for AD-1. |
| `Agent(...)` raising on the trifecta | **Accept** | §7.1. The flagship check. |
| `tool.requires_secret("X")` with sandbox env built from grants | **Accept** | INV-4. |
| Async concurrent tool execution | **Open** | TOCTOU in policy evaluation; decide in the API thread. |

---

## 10. Residual risk register

Risks we accept, in writing, with the reason.

| ID | Residual risk | Why accepted | What would change it |
|---|---|---|---|
| R-1 | An agent with legitimate `External` authority can be steered by injected content within that authority | No known solution; bounding it is the whole design | A reliable instruction/data separation result |
| R-2 | Egress policy is advisory below isolation tier `container` | Tier `container` is not always available; forcing it would kill adoption | Cheap, ubiquitous local isolation |
| R-3 | A granted credential can be abused by the tool that holds it | Grants are the control; filtering inside a tool is theatre | Per-call scoped credential minting, where the downstream supports it |
| R-4 | Human approvers habituate and click through | Known failure mode of every approval system | Rate-limit approvals; surface the diff; do not ask for routine things |
| R-5 | The deployer misconfigures and we permitted the override | Overrides are explicit, named, and logged | Ship a `--audit` command that prints every override in a config |
| R-6 | The model provider sees all context data | Inherent to using a hosted model | Local inference; deployer's call |
| R-7 | The audit log contains sensitive argument data and is itself an asset | Unavoidable if the log is to be useful | Field-level encryption; not in v1 |

---

## 11. Mapping to Agentic Trust Controls and other frameworks

### 11.1 Sourcing caveat, read this first

`trustcontrols.ai` returned HTTP 429 to every fetch attempt during this work, so **the control text has not been read directly.** What follows is reconstructed from a secondary write-up and search metadata and is explicitly provisional: it names the structure, not the individual controls. The mapping table below needs one pass against the primary source before it is quoted anywhere external. Treat that as an open action, not a footnote.

### 11.2 What Agentic Trust Controls appears to be

A public control set for agentic AI: **65 controls across 12 domains**, split into two baselines.

- **Developer baseline (43 controls)**, covering agent identity and authority, action guardrails, memory protection, instruction integrity, adversarial testing, and runtime instrumentation.
- **User baseline (22 controls)**, aimed at organisations deploying third-party agents: inventory and intake, credential control, oversight assignment, vendor review, runtime monitoring, and team training.

It maps to ISO 27001, ISO 42001, NIST AI RMF, MITRE, OWASP, and CSA AICM, so one control can be cited in several vocabularies. That cross-walk is its real utility for us.

### 11.3 Where our sections land against its developer baseline

| ATC developer area | Our section | Fit |
|---|---|---|
| Agent identity and authority | §7.2, §7.7, INV-1, INV-10 | Strong. Capability handles and delegation attenuation are directly this. |
| Action guardrails | §7.2, §7.5, INV-1, INV-8 | Strong. Policy engine and egress allowlists. |
| Memory protection | §7.6 | Strong. Provenance-on-memory is a concrete implementation of it. |
| Instruction integrity | §7.1, INV-3, §7.2 digest pinning | Partial by design. We do not attempt to keep injected instructions out; we make instruction provenance explicit and bound what instructions can cause. **Worth flagging: if ATC reads "instruction integrity" as preventing injection, we do not meet it and will say so rather than claim it.** |
| Adversarial testing | *Not yet covered here* | **Gap.** Belongs in the API and launch threads: an injection corpus in CI, a red-team harness, and a documented "here is how to attack your own agent" example. Add as §12 work. |
| Runtime instrumentation | §7.9 | Strong. |

### 11.4 Where ATC does not reach, and we still need an answer

ATC is an **organisational control set**: it tells a team what to have in place. It does not tell an SDK author what the API must look like, which is the question this project actually turns on. The following are ours to decide with no help from it:

- The taint model and how provenance propagates through a context window.
- Where enforcement sits relative to the model loop, which is the single most consequential architectural decision here.
- Isolation tiers and what each honestly guarantees.
- Egress mechanics: rebinding, redirects, metadata endpoints.
- The trifecta construction-time check.
- The SDK's own supply chain.

### 11.5 Other references worth citing in the README

OWASP LLM Top 10 and its Agentic Security Initiative; MITRE ATLAS for adversary technique vocabulary; NIST AI RMF for the governance framing; the CaMeL line of work for capability-based injection defence; Simon Willison's "lethal trifecta" framing, which §7.1's check implements directly. Citing these is not decoration: a security engineer evaluating an SDK looks for whether the authors have read the literature.

---

## 12. Open decisions

These need Yoan's call, or the API thread's, before v0.1 of the SDK is designed.

1. **Language and runtime.** Python first, or Rust core with bindings? The isolation and secret-type guarantees in §7.3 and §7.4 are meaningfully stronger with a typed core, and meaningfully worse for adoption. Recommendation: Python first, design the secret and capability types so a Rust core is a later swap rather than a rewrite.
2. **Sequential vs concurrent tool execution by default.** §2.1. Recommendation: sequential.
3. **`plan_then_execute` as a construct or an example.** §7.1. Recommendation: example first.
4. **Adversarial testing surface.** §11.3 gap. Recommendation: ship an injection corpus and a `secure-agents attack` command; it is also excellent marketing.
5. **The dependency cap number.** §7.8 proposes five. Confirm or set a different number, because it needs to be in CI.
6. **Whether the trifecta check fails construction or warns loudly.** Recommendation: fails. A warning in a log nobody reads is not a control, and failing at construction is what makes this the SDK people talk about.

---

## Appendix A: Threat index

| ID range | Area |
|---|---|
| T-PI-* | Prompt injection (§7.1) |
| T-TA-* | Tool abuse and permissions (§7.2) |
| T-SE-* | Secrets (§7.3) |
| T-NE-* | Network egress (§7.5) |
| T-ME-* | Memory (§7.6) |
| T-MA-* | Multi-agent (§7.7) |
| AS-* | Assets (§3) · AD-* Adversaries (§4) · B* Boundaries (§5) · INV-* Invariants (§6) · R-* Residual (§10) |
