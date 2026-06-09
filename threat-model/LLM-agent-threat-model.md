# LLM Agent Threat Model — Agentic Identity Security

**Framework:** STRIDE  
**Author:** Karthik Reddy  
**Version:** 1.0  
**Last Updated:** June 2026  

---

## Overview

This threat model analyzes the identity and authentication attack surface
of agentic AI systems — specifically LLM-based agents that autonomously
call APIs, access secrets, and interact with cloud infrastructure.

Traditional threat models assume human actors or static services.
Agentic systems introduce a fundamentally different threat landscape:

- Agents make autonomous decisions about what resources to access
- Agent behavior can be manipulated via prompt injection
- Multi-agent pipelines create transitive trust relationships
- Agent identities are often over-privileged and persistent
- Audit trails are frequently incomplete or absent

---

## System Description

### What We Are Modeling

A typical enterprise agentic AI deployment:
User / Orchestrator
│
▼
┌─────────────┐
│  LLM Agent  │  ← receives instructions, makes decisions
└─────────────┘
│
├──► Cloud APIs (AWS, GCP)
├──► Internal APIs / Microservices
├──► Secret Store (Vault, Secrets Manager)
├──► Database / Data Store
├──► Sub-Agents (multi-agent pipelines)
└──► External APIs (third-party services)

### Trust Boundaries

| Boundary | Description |
|---|---|
| TB-1 | User/Orchestrator → Agent |
| TB-2 | Agent → Cloud Provider APIs |
| TB-3 | Agent → Internal Services |
| TB-4 | Agent → Secret Store |
| TB-5 | Agent → Sub-Agents |
| TB-6 | Agent → External APIs |

---

## STRIDE Threat Analysis

### S — Spoofing

**S-1: Agent Identity Spoofing**
- Threat: A malicious actor or compromised sub-agent spoofs the identity
  of a trusted agent to gain elevated access to APIs or secrets
- Attack Vector: Stolen agent credentials, forged JWT tokens, or
  misconfigured service account trust policies
- Affected Boundary: TB-2, TB-3, TB-5
- Likelihood: High
- Impact: Critical

**Mitigations:**
- Use short-lived, workload-scoped credentials (AWS STS, GCP Workload Identity)
- Enforce mTLS between agents and internal services
- Bind agent identities to specific task contexts — not reusable across sessions
- Validate agent identity at every trust boundary, not just entry points

---

**S-2: Prompt Injection Leading to Identity Abuse**
- Threat: Attacker injects malicious instructions into data an agent
  processes, causing the agent to act under a false identity context
  or impersonate another principal
- Attack Vector: Malicious content in documents, web pages, or API
  responses that the agent reads and acts on
- Affected Boundary: TB-1, TB-3, TB-6
- Likelihood: High
- Impact: High

**Mitigations:**
- Treat all external data as untrusted — never allow it to modify
  agent identity or permission scope
- Implement instruction hierarchy — system prompts take precedence
  over user and external data inputs
- Log all prompt inputs and flag anomalous instruction patterns
- Enforce output validation before any API calls are executed

---

### T — Tampering

**T-1: Agent Credential Tampering**
- Threat: Credentials injected into an agent's environment are
  intercepted and modified in transit, redirecting agent actions
  to attacker-controlled infrastructure
- Attack Vector: Man-in-the-middle on unencrypted credential delivery,
  environment variable injection in container workloads
- Affected Boundary: TB-4
- Likelihood: Medium
- Impact: Critical

**Mitigations:**
- Never pass credentials via environment variables in plaintext
- Use IAM roles and instance profiles — agents should never hold
  long-lived static credentials
- Enforce TLS 1.3 for all credential retrieval from secret stores
- Implement credential integrity validation at retrieval time

---

**T-2: Audit Log Tampering**
- Threat: An attacker with write access to logging infrastructure
  modifies or deletes agent activity logs to cover tracks after
  a credential compromise or data exfiltration event
- Attack Vector: Overly permissive IAM on CloudTrail or logging buckets,
  missing log integrity controls
- Affected Boundary: TB-2, TB-3
- Likelihood: Medium
- Impact: High

**Mitigations:**
- Enable CloudTrail log file validation (SHA-256 integrity hashing)
- Write agent audit logs to append-only, write-once S3 buckets
- Separate log write and log read permissions — agents should
  never have read access to their own audit logs
- Replicate logs to a separate AWS account for tamper resistance

---

### R — Repudiation

**R-1: Agent Action Repudiation**
- Threat: No reliable audit trail exists to attribute specific API
  calls, data access, or resource modifications to a specific agent
  identity and task context — making incident investigation impossible
- Attack Vector: Shared service accounts across multiple agents,
  missing request correlation IDs, incomplete CloudTrail coverage
- Affected Boundary: TB-2, TB-3, TB-4
- Likelihood: High
- Impact: High

**Mitigations:**
- Every agent session must have a unique, traceable session ID
  propagated through all downstream API calls
- Use per-agent IAM roles, never shared service accounts
- Enforce CloudTrail data events for all S3 and Lambda interactions
- Correlate agent session IDs with CloudTrail request IDs in SIEM

---

### I — Information Disclosure

**I-1: Sensitive Data Exfiltration via LLM Interface**
- Threat: An agent with access to sensitive data (PII, credentials,
  IP) leaks that data through LLM output — either to the user,
  external APIs, or logged in plaintext
- Attack Vector: Overly broad data access scope, missing output
  filtering, plaintext logging of LLM prompts and completions
- Affected Boundary: TB-1, TB-3, TB-6
- Likelihood: High
- Impact: Critical

**Mitigations:**
- Apply data classification labels before any data enters agent context
- Implement output filtering to detect and redact PII, credentials,
  and sensitive patterns before LLM responses are returned
- Never log full prompt/completion pairs in plaintext — hash or
  redact sensitive fields before writing to log systems
- Scope agent data access to specific datasets, not entire data stores

---

**I-2: Secret Leakage Through Agent Logs**
- Threat: API keys, tokens, or passwords retrieved by an agent from
  a secret store are inadvertently written to application logs,
  container stdout, or telemetry pipelines
- Attack Vector: Poor secret handling in agent code, overly verbose
  debug logging, exception stack traces that include credential values
- Affected Boundary: TB-4
- Likelihood: High
- Impact: Critical

**Mitigations:**
- Implement secret scanning in CI/CD pipelines for agent code
- Configure log scrubbing rules to detect and redact credential patterns
- Use AWS Secrets Manager SDK with automatic rotation — agents
  retrieve secrets by reference, not by value where possible
- Set logging level to WARN or ERROR in production agent workloads

---

### D — Denial of Service

**D-1: Agent Resource Exhaustion**
- Threat: A malicious actor or runaway agent consumes excessive
  cloud resources — API calls, compute, storage — causing service
  degradation for legitimate workloads
- Attack Vector: Prompt injection causing infinite loops, missing
  rate limits on agent API calls, no budget controls on AI inference
- Affected Boundary: TB-2, TB-3, TB-6
- Likelihood: Medium
- Impact: High

**Mitigations:**
- Implement per-agent API call rate limits and hard budget caps
- Set maximum token limits and session timeouts for all agent runs
- Monitor agent API call velocity — alert on anomalous spikes
- Use AWS Service Quotas and GCP Quotas to cap resource consumption

---

### E — Elevation of Privilege

**E-1: Cross-Agent Privilege Escalation**
- Threat: A low-privilege agent passes instructions or forged context
  to a high-privilege agent in a multi-agent pipeline, causing
  the high-privilege agent to perform unauthorized actions
- Attack Vector: Missing trust validation between agents, overly
  permissive inter-agent communication, no privilege boundary
  enforcement at agent handoff points
- Affected Boundary: TB-5
- Likelihood: High
- Impact: Critical

**Mitigations:**
- Enforce least-privilege at every agent boundary — downstream agents
  must not inherit the full scope of upstream agent permissions
- Validate and sanitize all inter-agent messages — treat them as
  untrusted external input, not trusted internal communication
- Implement explicit permission delegation — a high-privilege agent
  should require explicit human or system authorization before acting
  on instructions from a lower-privilege agent
- Log all inter-agent communication with full context for audit

---

**E-2: Tool Use Abuse for Privilege Escalation**
- Threat: An agent with access to infrastructure tools (Terraform,
  AWS CLI, kubectl) is manipulated into using those tools to
  create new privileged identities or modify existing IAM policies
- Attack Vector: Prompt injection targeting agent tool use,
  overly broad tool permissions, missing human-in-the-loop
  controls for privileged infrastructure actions
- Affected Boundary: TB-2, TB-3
- Likelihood: Medium
- Impact: Critical

**Mitigations:**
- Never grant agents write access to IAM policies or permission boundaries
- Require human approval for any agent-initiated infrastructure changes
- Implement tool use allowlists — agents should only access
  pre-approved, scoped tools for their specific task
- Audit all agent tool invocations in real time

---

## Risk Summary

| ID | Threat | Likelihood | Impact | Priority |
|---|---|---|---|---|
| S-1 | Agent Identity Spoofing | High | Critical | P0 |
| S-2 | Prompt Injection Identity Abuse | High | High | P0 |
| I-1 | Sensitive Data Exfiltration | High | Critical | P0 |
| I-2 | Secret Leakage via Logs | High | Critical | P0 |
| E-1 | Cross-Agent Privilege Escalation | High | Critical | P0 |
| T-1 | Credential Tampering | Medium | Critical | P1 |
| T-2 | Audit Log Tampering | Medium | High | P1 |
| R-1 | Agent Action Repudiation | High | High | P1 |
| E-2 | Tool Use Privilege Escalation | Medium | Critical | P1 |
| D-1 | Agent Resource Exhaustion | Medium | High | P2 |

---

## Detection Opportunities

Each threat above maps to detection rules in `detection-rules/splunk/`:

| Threat | Detection Rule |
|---|---|
| S-1, S-2 | `ai-identity-anomaly.spl` |
| I-1, I-2 | `ai-data-exfiltration.spl` |
| E-1, E-2 | `ai-privilege-escalation.spl` |
| T-2 | `ai-log-integrity.spl` |
| D-1 | `ai-resource-exhaustion.spl` |

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
- [SPIFFE Workload Identity Standard](https://spiffe.io/)
