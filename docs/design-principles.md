# Design Principles — Agentic Identity Security

**Author:** Karthik Reddy  
**Version:** 1.0  
**Last Updated:** June 2026  

---

## Overview

These principles guide every decision in this framework — from how
we design IAM policies to how we write detection rules. They are
not aspirational. Every artifact in this repo was built to embody
them concretely.

The core problem we are solving: **AI agents are becoming
first-class infrastructure actors, but our identity and access
frameworks were never designed for them.**

A human engineer requests access, gets reviewed, and operates
within understood behavioral norms. An LLM agent requests nothing
— it simply acts, autonomously, at machine speed, with whatever
permissions its role allows. That asymmetry is the security problem
this framework addresses.

---

## Principle 1: Least Privilege Is Non-Negotiable

**The rule:** Every AI agent gets exactly the permissions it needs
for its specific task — nothing more, ever.

**Why it matters for agents specifically:**

Traditional least privilege assumes a human who will notice when
something goes wrong. Agents don't notice. A misconfigured agent
with broad permissions will quietly abuse those permissions —
either through a bug, a prompt injection attack, or a compromised
credential — and nothing will stop it except the permission
boundary itself.

**What this looks like in practice:**

- Per-agent IAM roles — never shared service accounts
- Resource-level scoping — not `s3:GetObject` on `*`,
  but `s3:GetObject` on `arn:aws:s3:::bucket/prefix/*`
- Explicit Deny statements for high-risk actions (IAM modification,
  CloudTrail tampering) that no agent should ever perform
- Time-bounded credentials — 1 hour max session duration,
  forcing regular rotation

**The hard question to ask:** If this agent's credentials were
stolen today, what is the blast radius? If the answer is
"significant," the policy is wrong.

---

## Principle 2: Ephemeral Identities Over Persistent Ones

**The rule:** Agent identities should live only as long as the
task they were created for.

**Why it matters:**

A persistent service account that an agent uses for months is a
persistent target. Every day that credential exists is another
day it can be stolen, leaked through a log, or abused by a
compromised agent instance.

Ephemeral identities — credentials that expire after minutes or
hours — dramatically reduce the window of opportunity for an
attacker who has obtained them.

**What this looks like in practice:**

- AWS STS AssumeRole with 1-hour session duration maximum
- GCP Workload Identity Federation — no long-lived service
  account keys, ever
- Task-scoped credentials — each agent invocation gets fresh
  credentials tied to that specific task context
- Automatic credential rotation enforced at the infrastructure
  level, not the application level

**The key insight:** An attacker who steals a credential that
expires in 45 minutes has 45 minutes. An attacker who steals
a credential that never expires has forever.

---

## Principle 3: Assume the Agent Will Be Compromised

**The rule:** Design every control assuming the agent itself
is adversarial or has been manipulated.

**Why it matters:**

Prompt injection is not a theoretical attack. It is happening
in production systems today. An agent that reads external data —
web pages, documents, API responses, emails — can be manipulated
by content embedded in that data to take actions its operators
never intended.

This means we cannot trust the agent's behavior even when we
trust its identity. The controls at the infrastructure layer
must be strong enough to contain a fully compromised agent.

**What this looks like in practice:**

- Permission boundaries that make harmful actions impossible
  regardless of what instructions the agent receives
- Explicit Deny for IAM modifications — a compromised agent
  cannot create backdoor identities even if instructed to
- Rate limits and budget caps — a manipulated agent cannot
  cause runaway resource consumption or API abuse
- Human-in-the-loop requirements for high-stakes actions —
  some things agents should never be able to do autonomously

**The mental model:** Treat your agent the same way you treat
untrusted user input. Validate, constrain, and contain it.

---

## Principle 4: Audit Everything, Attribute Everything

**The rule:** Every action an agent takes must be logged,
attributed to a specific agent identity and session, and
monitored for anomalies in real time.

**Why it matters:**

Without complete audit trails, incident response for an agent
compromise is nearly impossible. You cannot answer the questions
that matter: Which agent? Which session? What data did it access?
What did it do with it? When did the compromise start?

Most organizations today cannot answer these questions for their
AI workloads. That is a critical gap.

**What this looks like in practice:**

- Per-agent IAM roles — every CloudTrail event is attributed
  to a specific named agent, not a shared service account
- Session IDs propagated through all downstream API calls —
  a single agent session can be traced end-to-end
- CloudTrail log file validation enabled — SHA-256 integrity
  hashing ensures logs cannot be tampered with silently
- Logs written to append-only, write-once S3 buckets — agents
  have no read or delete access to their own audit trail
- Real-time anomaly detection — the Splunk rules in this repo
  are designed to surface compromise indicators within minutes,
  not hours

**The standard to meet:** Given a security incident, you should
be able to reconstruct exactly what any agent did, when, and why,
with confidence that the audit trail has not been tampered with.

---

## Principle 5: Secure by Default, Not by Configuration

**The rule:** The paved path must be the secure path. Engineers
building on top of this framework should not have to opt into
security controls — they should have to explicitly opt out.

**Why it matters:**

Security controls that require manual configuration will be
misconfigured. At scale, across hundreds of agent deployments,
the only way to maintain consistent security posture is to
make the secure option the default option.

**What this looks like in practice:**

- Terraform module outputs a hardened IAM role by default —
  engineers pass in agent name and environment, they get a
  secure identity out
- Explicit Deny statements are non-negotiable — they cannot
  be overridden by permissive policies elsewhere
- KMS encryption is on by default for all secrets and logs —
  plaintext is never an option in the module
- CloudTrail with log file validation is on by default —
  audit integrity is not optional
- The burden of proof is on disabling a control, not enabling one

**The design test:** Could a junior engineer use this module
and accidentally create an insecure agent identity? If yes,
fix the module, not the documentation.

---

## Principle 6: Blast Radius Containment Over Perimeter Defense

**The rule:** Assume the perimeter will be breached. Design
controls that limit the damage when — not if — a breach occurs.

**Why it matters for agentic systems:**

Traditional security thinking focuses on keeping attackers out.
Agentic systems change this calculus — the agent itself operates
inside the perimeter, has credentials, and can take actions.
If the agent is compromised, perimeter defenses are irrelevant.

What matters is: when this agent is compromised, how much
damage can the attacker do? The answer should be: very little.

**What this looks like in practice:**

- Scoped IAM policies limit what a compromised agent can access
- Resource tagging and data classification prevent agents from
  accessing data above their clearance level
- Network segmentation isolates AI workloads from sensitive
  internal services
- Cross-account access requires explicit, audited approval —
  a compromised agent in one account cannot pivot to another
- Separate AWS accounts for AI workloads — blast radius is
  contained to the AI account, not the entire organization

---

## Applying These Principles

Every artifact in this repo was evaluated against these principles:

| Artifact | Principles Applied |
|---|---|
| `LLM-agent-threat-model.md` | P3, P6 — maps compromise scenarios and blast radius |
| `ai-workload-least-privilege.json` | P1, P5 — least privilege with secure defaults |
| `terraform/ai-workload-identity/` | P1, P2, P4, P5 — ephemeral creds, audit, defaults |
| `ai-identity-anomaly.spl` | P4 — real-time attribution and anomaly detection |
| `ai-data-exfiltration.spl` | P4, P6 — blast radius detection and containment |
| `ai-privilege-escalation.spl` | P3, P4 — assume compromise, detect escalation |

---

## What This Framework Does Not Cover

Honest acknowledgment of current scope limits:

- **Azure** — IAM policies and Terraform modules are AWS/GCP only
  currently. Azure Managed Identity support is on the roadmap.
- **Multi-cloud agent pipelines** — agents that span AWS and GCP
  within a single session introduce trust boundary complexity
  not yet fully addressed here.
- **LLM provider security** — this framework addresses the
  infrastructure identity layer. Security of the LLM provider
  itself (OpenAI, Anthropic, Bedrock) is out of scope.
- **Agent-to-agent authentication protocols** — mTLS between
  agents is referenced but not fully implemented yet.

Contributions addressing these gaps are very welcome.

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI RMF](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
- [SPIFFE/SPIRE](https://spiffe.io/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [HashiCorp Vault](https://www.vaultproject.io/)