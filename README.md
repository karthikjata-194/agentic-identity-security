# Agentic Identity Security

A practical reference framework for securing agentic AI systems, LLM workloads,
and machine identities in cloud environments.

Built by a cloud security engineer with 10+ years of experience in enterprise
security infrastructure, FedRAMP compliance, and AI/LLM security governance.

---

## Why This Exists

As AI agents become first-class actors in cloud infrastructure — calling APIs,
accessing secrets, spinning up resources, and making decisions autonomously —
the traditional identity perimeter breaks down.

Most workload identity frameworks were designed for humans and static services.
They were not designed for:

- LLM agents that dynamically decide what APIs to call
- Multi-agent pipelines where trust flows between autonomous systems
- AI workloads that access sensitive data without human review in the loop
- Ephemeral agent sessions that need scoped, time-bound identities

This repo is a structured attempt to fill that gap — with threat models,
IAM policy templates, Terraform configs, and detection rules that treat
agentic identity as a first-class security problem.

---

## Repository Structure
agentic-identity-security/
├── threat-model/
│   ├── LLM-agent-threat-model.md      # STRIDE-based threat model for agentic AI
│   └── attack-trees/                   # Attack trees for key threat scenarios
├── iam-policies/
│   ├── aws/                            # Least-privilege IAM for AI workloads on AWS
│   └── gcp/                            # Workload identity configs for GCP
├── terraform/
│   └── modules/
│       └── ai-workload-identity/       # Hardened identity infrastructure as code
├── detection-rules/
│   └── splunk/                         # SPL detection rules for AI misuse
└── docs/
├── design-principles.md            # Guiding principles for agentic identity
└── threat-taxonomy.md              # Taxonomy of agentic AI threat classes

---

## Core Principles

**1. Least Privilege by Default**
Every AI agent gets the minimum identity scope needed for its specific task.
No shared service accounts. No wildcard permissions.

**2. Ephemeral Over Persistent**
Agent identities should be short-lived and task-scoped. A persistent identity
that can be stolen is a persistent risk.

**3. Assume Breach at the Agent Layer**
Design controls assuming an agent will be compromised, manipulated via prompt
injection, or misused. Blast radius containment matters more than perimeter defense.

**4. Audit Everything**
Every API call an agent makes, every secret it accesses, every downstream
service it touches — logged, attributed, and anomaly-detected.

**5. Secure by Default, Not by Configuration**
The paved path should be the secure path. Engineers should not have to opt
into security controls — they should have to opt out.

---

## Contents

### Threat Model
STRIDE-based threat analysis covering the full agentic identity attack surface —
from prompt injection to credential theft to cross-agent privilege escalation.

### IAM Policies
Least-privilege IAM templates for AWS and GCP, specifically designed for
AI/LLM workload identity patterns including:
- Scoped execution roles for LLM inference workloads
- Secrets Manager access policies for agent credential retrieval
- Cross-account trust policies for multi-agent architectures

### Terraform Modules
Production-ready infrastructure-as-code for hardened agentic identity,
including KMS key management, IAM role provisioning, and CloudTrail
audit logging configured for AI workload patterns.

### Detection Rules
Splunk SPL detection rules for identifying AI workload misuse, including:
- Anomalous API call patterns from AI workloads
- Prompt injection indicators in application logs
- Credential access anomalies from agent identities
- Data exfiltration patterns via LLM interfaces

---

## Who This Is For

- Security engineers designing identity controls for AI/LLM platforms
- Cloud architects building secure agentic AI infrastructure
- Detection engineers building SOC coverage for AI workloads
- Platform security teams establishing secure-by-default AI primitives

---

## Contributing

Contributions welcome — particularly around:
- Additional cloud provider IAM templates (Azure)
- New detection rules for emerging agentic AI frameworks
- Threat model updates as new attack patterns emerge
- Real-world case studies (anonymized)

Please open an issue before submitting a PR for significant changes.

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [SPIFFE/SPIRE Workload Identity](https://spiffe.io/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)

---

## License

MIT — use freely, attribution appreciated.