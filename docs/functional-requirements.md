# Functional Requirements
## AI-Powered Key Management System (AIKMS)

**Document Version:** 1.0  
**Date:** March 29, 2026  
**Status:** Draft

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Scope](#2-scope)
3. [User Roles & Permissions](#3-user-roles--permissions)
4. [Functional Requirements](#4-functional-requirements)
   - 4.1 [Key Lifecycle Management](#41-key-lifecycle-management)
   - 4.2 [AI-Driven Anomaly Detection](#42-ai-driven-anomaly-detection)
   - 4.3 [Automated Key Rotation](#43-automated-key-rotation)
   - 4.4 [Risk Scoring & Threat Intelligence](#44-risk-scoring--threat-intelligence)
   - 4.5 [Access Control & Authentication](#45-access-control--authentication)
   - 4.6 [Audit Logging & Compliance](#46-audit-logging--compliance)
   - 4.7 [Policy Management](#47-policy-management)
   - 4.8 [Secrets & Certificate Management](#48-secrets--certificate-management)
   - 4.9 [Integrations & API Gateway](#49-integrations--api-gateway)
   - 4.10 [Dashboard & Reporting](#410-dashboard--reporting)
   - 4.11 [Notifications & Alerting](#411-notifications--alerting)
   - 4.12 [Disaster Recovery & High Availability](#412-disaster-recovery--high-availability)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [Assumptions & Constraints](#6-assumptions--constraints)
7. [Glossary](#7-glossary)
8. [Technical Specification](#8-technical-specification)
   - 8.1 [System Architecture](#81-system-architecture)
   - 8.2 [Technology Stack](#82-technology-stack)
   - 8.3 [Cryptographic Standards](#83-cryptographic-standards)
   - 8.4 [AI/ML Architecture](#84-aiml-architecture)
   - 8.5 [Data Models](#85-data-models)
   - 8.6 [API Specification](#86-api-specification)
   - 8.7 [Infrastructure & Deployment](#87-infrastructure--deployment)
   - 8.8 [Security Architecture](#88-security-architecture)
   - 8.9 [Performance & Scalability Design](#89-performance--scalability-design)
9. [User Stories & Acceptance Criteria](#9-user-stories--acceptance-criteria)
10. [Key Lifecycle State Machine](#10-key-lifecycle-state-machine)
11. [Critical Flow Sequence Diagrams](#11-critical-flow-sequence-diagrams)
12. [Complete Database Schema](#12-complete-database-schema)
13. [API Contract Reference](#13-api-contract-reference)
14. [Environment & Configuration Reference](#14-environment--configuration-reference)
15. [Error Handling & Resilience](#15-error-handling--resilience)
16. [Multi-Tenancy & Namespace Isolation](#16-multi-tenancy--namespace-isolation)
17. [Testing Strategy](#17-testing-strategy)
18. [Operational Runbooks](#18-operational-runbooks)
19. [HSM Simulator](#19-hsm-simulator)

---

## 1. Introduction

The **AI-Powered Key Management System (AIKMS)** is an enterprise-grade platform for creating, storing, distributing, rotating, and retiring cryptographic keys and secrets. It augments traditional key management with AI/ML capabilities to detect anomalies, predict key compromise, automate lifecycle decisions, and provide intelligent policy recommendations — reducing human error and operational overhead.

### 1.1 Purpose

This document defines the functional requirements that the AIKMS must satisfy. It serves as the authoritative reference for development, testing, and stakeholder alignment.

### 1.2 Intended Audience

- Product Owners & Business Analysts
- Software Architects & Engineers
- Security Engineers & Compliance Officers
- QA Engineers

---

## 2. Scope

AIKMS covers the end-to-end lifecycle of:

- Symmetric keys (AES-128, AES-256)
- Asymmetric key pairs (RSA-2048/4096, EC P-256/P-384/P-521, Ed25519)
- HMAC secrets and API keys
- TLS/SSL certificates (X.509)
- SSH keys
- Passwords and application secrets (vault-style)

Out of scope:
- Hardware Security Module (HSM) firmware development (HSMs are treated as external backends)
- Certificate Authority (CA) root key ceremonies (AIKMS acts as a subordinate or RA)

---

## 3. User Roles & Permissions

| Role | Description |
|------|-------------|
| **Super Admin** | Full system access; manages roles, system configuration, and global policies |
| **Security Admin** | Manages keys, policies, certificates, and audit reports |
| **Key Operator** | Creates and manages keys within assigned namespaces; cannot modify policies |
| **Auditor** | Read-only access to audit logs, reports, and compliance dashboards |
| **Developer / Service Account** | Programmatic access via API; scoped to permitted key operations only |
| **AI Engine (System)** | Internal role for AI modules to read events and write risk scores/recommendations |

---

## 4. Functional Requirements

### 4.1 Key Lifecycle Management

#### FR-KLM-001 — Key Creation
- The system **shall** allow authorized users to generate cryptographic keys specifying: algorithm, key size, purpose (encrypt/sign/wrap/authenticate), expiry date, namespace/project, and metadata tags.
- The system **shall** support both software-based key generation and HSM-backed key generation.
- The system **shall** enforce minimum key strength requirements per algorithm (e.g., RSA ≥ 2048 bits, AES ≥ 128 bits).
- The system **shall** assign a globally unique Key ID (UUID v4) and record the creation timestamp, creator identity, and originating namespace.

#### FR-KLM-002 — Key Storage
- The system **shall** store all key material in encrypted form at rest using envelope encryption (a root key encrypting a data encryption key).
- The system **shall** support multiple backend storage options: software keystore, cloud KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS), and FIPS 140-2/3 Level 3 HSMs.
- The system **shall** prevent plaintext key material from ever being exposed in logs, error messages, or API responses.

#### FR-KLM-003 — Key Retrieval & Usage
- The system **shall** allow authorized entities to retrieve a key by Key ID for cryptographic operations.
- The system **shall** support in-service cryptographic operations (encrypt, decrypt, sign, verify, wrap, unwrap) such that raw key material is never sent to the caller unless an explicit key export is authorized.
- The system **shall** enforce purpose restrictions on key usage (e.g., a signing key cannot be used for encryption).
- The system **shall** enforce usage quotas and rate limits per key and per caller identity.

#### FR-KLM-004 — Key Versioning
- The system **shall** maintain an immutable version history for each key, incrementing the version on every rotation or manual update.
- The system **shall** allow decryption using any previous active version while defaulting encryption to the current version.
- The system **shall** allow administrators to explicitly deprecate or retire a specific key version.

#### FR-KLM-005 — Key Retirement & Destruction
- The system **shall** support the following key states: `Pending`, `Active`, `Suspended`, `Deprecated`, `Scheduled for Destruction`, `Destroyed`.
- The system **shall** require dual-control approval (two authorized administrators) before transitioning a key to `Scheduled for Destruction`.
- The system **shall** perform a 7-day (configurable) cooling-off period before physical destruction, during which destruction can be cancelled.
- The system **shall** cryptographically overwrite all copies of key material upon destruction and record a destruction certificate in the audit log.

---

### 4.2 AI-Driven Anomaly Detection

#### FR-AI-001 — Behavioral Baseline Learning
- The system **shall** continuously collect and process key-usage events (caller identity, timestamp, source IP, geolocation, operation type, volume) to build per-entity behavioral baselines using unsupervised ML models.
- The system **shall** update behavioral baselines on a configurable rolling window (default: 30 days).
- The system **shall** store behavioral models in a versioned model registry with rollback capability.

#### FR-AI-002 — Real-Time Anomaly Detection
- The system **shall** evaluate every key-access event against the current behavioral model within 500 ms.
- The system **shall** flag events as anomalous when they deviate from the baseline by a configurable statistical threshold (default: 3σ).
- The system **shall** detect the following anomaly categories:
  - *Volumetric anomalies*: Sudden spike in decryption operations.
  - *Temporal anomalies*: Access outside normal operating hours.
  - *Geographic anomalies*: Access from a new or high-risk country/region.
  - *Lateral movement*: A service account accessing keys outside its typical namespace.
  - *Impossible travel*: Two authentications from geographically distant locations within an implausible timeframe.
  - *Credential reuse*: API keys used simultaneously from multiple IP addresses.

#### FR-AI-003 — Anomaly Scoring & Triage
- The system **shall** assign a numeric anomaly score (0–100) to each detected event.
- The system **shall** aggregate anomaly scores over a configurable time window to compute a *Session Risk Score* per caller.
- The system **shall** automatically escalate events that exceed a configurable risk threshold to the alerting and incident management pipeline.

#### FR-AI-004 — AI Model Management
- The system **shall** allow Security Admins to view current model metadata (version, training date, accuracy metrics, feature importance).
- The system **shall** support A/B testing of new models against the current production model before promotion.
- The system **shall** prevent deletion of a model version that is referenced by historical anomaly records.

---

### 4.3 Automated Key Rotation

#### FR-ROT-001 — Policy-Based Rotation Scheduling
- The system **shall** support configurable key rotation policies defining: rotation interval (time-based), rotation trigger (usage-count-based, anomaly-score-based), and notification lead time.
- The system **shall** allow policies to be set at the global, namespace, key-type, or individual key level, with more-specific policies overriding less-specific ones.

#### FR-ROT-002 — AI-Recommended Rotation
- The system **shall**, using its AI engine, proactively recommend early rotation when a key's risk score exceeds a configurable threshold.
- The system **shall** present rotation recommendations to authorized users with an explanation of the contributing risk factors.
- The system **shall** allow users to accept, defer, or dismiss AI-generated rotation recommendations; dismissals **shall** require a written justification stored in the audit log.

#### FR-ROT-003 — Zero-Downtime Rotation
- The system **shall** execute rotation by creating a new key version, updating all registered consumers via push notification or pull-on-next-use, and only retiring the previous version after all consumers have acknowledged the new version or a grace period has elapsed.
- The system **shall** expose a rotation status dashboard showing consumer acknowledgment progress in real time.
- The system **shall** roll back to the previous key version automatically if more than a configurable percentage of consumers report errors during the grace period.

#### FR-ROT-004 — Certificate Rotation
- The system **shall** support automated renewal of X.509 certificates before their expiry, configurable from 1 to 90 days before expiry.
- The system **shall** integrate with ACME protocol (Let's Encrypt), internal PKI, and manual CSR upload workflows.
- The system **shall** automatically push renewed certificates to registered endpoints (web servers, load balancers, secret stores) via plugins.

---

### 4.4 Risk Scoring & Threat Intelligence

#### FR-RISK-001 — Key Risk Score
- The system **shall** maintain a continuous *Key Risk Score* (0–100) for every active key, derived from: age, usage anomalies, associated caller risk, algorithm strength, compliance status, and threat intelligence feeds.
- The system **shall** recalculate Key Risk Scores at a configurable interval (default: every 15 minutes) and on every anomalous usage event.

#### FR-RISK-002 — Threat Intelligence Integration
- The system **shall** ingest threat intelligence feeds (STIX/TAXII, commercial feeds) to enrich anomaly detection with known malicious IP addresses, compromised credentials, and CVE advisories relevant to cryptographic libraries.
- The system **shall** automatically elevate the risk score of keys whose associated services are affected by newly disclosed vulnerabilities.

#### FR-RISK-003 — Predictive Compromise Detection
- The system **shall** use a trained classification model to estimate the probability that a key has been compromised, surfacing keys in the top 5% of predicted compromise probability to the Security Admin dashboard.
- The system **shall** retrain the predictive model on a scheduled basis (default: weekly) and upon significant drift in key-usage patterns.

---

### 4.5 Access Control & Authentication

#### FR-AC-001 — Identity & Authentication
- The system **shall** support authentication via: username/password with MFA (TOTP/FIDO2/WebAuthn), OIDC/OAuth 2.0 (integration with enterprise IdPs such as Okta, Azure AD, Ping Identity), SAML 2.0 SSO, and mutual TLS (mTLS) for service accounts.
- The system **shall** enforce MFA for all human users accessing Security Admin or Super Admin roles.
- The system **shall** support just-in-time (JIT) provisioning of user accounts via SCIM 2.0.

#### FR-AC-002 — Attribute-Based Access Control (ABAC)
- The system **shall** implement ABAC allowing policies to define access based on: subject attributes (role, department, clearance level), resource attributes (key purpose, classification, namespace), environment attributes (time of day, IP range, geolocation), and action (create, read, use, rotate, delete).
- The system **shall** evaluate ABAC policies using a deny-by-default model; access is granted only when an explicit allow policy matches.

#### FR-AC-003 — Privileged Access Workstation (PAW) Enforcement
- The system **shall** allow administrators to restrict Super Admin and Security Admin operations to pre-registered, certificate-authenticated workstation identities.

#### FR-AC-004 — Session Management
- The system **shall** enforce configurable session timeouts (default: 30 minutes of inactivity for human users).
- The system **shall** allow administrators to terminate any active session immediately.
- The system **shall** invalidate all active sessions for a user upon password reset, MFA re-enrollment, or account suspension.

---

### 4.6 Audit Logging & Compliance

#### FR-AUDIT-001 — Immutable Audit Log
- The system **shall** record an immutable, tamper-evident audit log entry for every state-changing event including: key creation/rotation/destruction, access grants/revocations, policy changes, login/logout events, failed authentication attempts, and AI recommendations with user responses.
- Each log entry **shall** include: event ID, timestamp (UTC, millisecond precision), actor identity, source IP, action, target resource, outcome (success/failure), and session ID.
- The system **shall** use a cryptographic hash chain (each log entry includes the hash of the previous entry) to detect tampering.

#### FR-AUDIT-002 — Log Retention & Export
- The system **shall** retain audit logs for a configurable period (default: 7 years) with tiered storage (hot/warm/cold).
- The system **shall** support export of audit logs in JSON, CSV, and CEF formats for SIEM integration.
- The system **shall** integrate natively with Splunk, Elasticsearch/OpenSearch, and AWS CloudWatch Logs via configurable log forwarding adapters.

#### FR-AUDIT-003 — Compliance Reporting
- The system **shall** provide pre-built compliance report templates for: PCI-DSS (Key Management requirements), FIPS 140-3, NIST SP 800-57, SOC 2 Type II, ISO 27001, GDPR (encryption evidence), and HIPAA.
- The system **shall** allow Auditors to generate on-demand compliance reports scoped by date range, namespace, key type, or regulation.
- The system **shall** track and display the compliance posture score per regulation, updated daily.

---

### 4.7 Policy Management

#### FR-POL-001 — Policy Definition
- The system **shall** allow Security Admins to define, version, and manage cryptographic policies specifying: allowed algorithms and key sizes, maximum key age, mandatory rotation intervals, permitted key purposes, required approval workflows, and export restrictions.
- The system **shall** support policy inheritance: child namespaces inherit parent policies unless explicitly overridden.
- The system **shall** validate all new policies against a built-in rule engine to prevent conflicting or insecure configurations before saving.

#### FR-POL-002 — AI Policy Recommendations
- The system **shall** use the AI engine to analyze current key usage patterns, compliance gaps, and industry benchmarks to generate policy recommendations.
- Policy recommendations **shall** include: the proposed change, affected keys/namespaces, estimated compliance improvement, and risk reduction delta.
- Users **shall** be able to accept recommendations with one click, which automatically creates a new policy version pending approval.

#### FR-POL-003 — Approval Workflows
- The system **shall** support configurable multi-stage approval workflows for sensitive operations (key creation, policy change, key export, destruction).
- The system **shall** integrate with ticketing systems (Jira, ServiceNow) to create approval tickets and track approvals bi-directionally.
- The system **shall** enforce a quorum approval model, requiring M-of-N approvers to proceed.

---

### 4.8 Secrets & Certificate Management

#### FR-SEC-001 — Secrets Vault
- The system **shall** provide a secrets vault for storing application secrets (database passwords, API tokens, OAuth credentials) with version history, namespace isolation, and lease-based dynamic secrets.
- The system **shall** support dynamic secret generation for supported backends (PostgreSQL, MySQL, MongoDB, AWS IAM, Azure Service Principal) with configurable TTL and automatic revocation.
- The system **shall** allow secrets to be injected into workloads at runtime via: environment variable injection (Kubernetes mutating webhook), mounted file volumes, and REST API pull.

#### FR-SEC-002 — Certificate Lifecycle Management
- The system **shall** maintain a certificate inventory across all registered environments, displaying: subject, issuer, expiry date, associated service, and current status.
- The system **shall** alert when certificates are within the configured expiry warning window (default: 30 days).
- The system **shall** track certificate revocation status via OCSP and CRL, alerting immediately on revocation of any monitored certificate.

#### FR-SEC-003 — SSH Key Management
- The system **shall** manage SSH public/private key pairs for host and user authentication, including creation, distribution to target hosts via SSH CA, rotation, and revocation.
- The system **shall** enforce maximum lifetime for SSH certificates (signed by the SSH CA) with configurable TTL.

---

### 4.9 Integrations & API Gateway

#### FR-INT-001 — RESTful API
- The system **shall** expose a comprehensive REST API (OpenAPI 3.1 specification) covering all functional capabilities.
- All API endpoints **shall** require authentication (OAuth 2.0 Bearer token or mTLS) and enforce ABAC authorization.
- The system **shall** version the API (e.g., `/api/v1/`, `/api/v2/`) and maintain backward compatibility for at least two major versions.
- The API **shall** enforce rate limiting per client identity with configurable thresholds and return HTTP 429 with `Retry-After` headers when limits are exceeded.

#### FR-INT-002 — SDK Support
- The system **shall** provide client SDKs for: Go, Python, Java, Node.js, and .NET/C#.
- Each SDK **shall** handle authentication, token refresh, retry logic with exponential backoff, and transparent key caching.

#### FR-INT-003 — Cloud & Infrastructure Integrations
- The system **shall** integrate with: AWS (KMS, Secrets Manager, IAM), Azure (Key Vault, Managed Identities), GCP (Cloud KMS, Secret Manager), HashiCorp Vault (as a sync target), Kubernetes (external secrets operator, CSI driver), and Terraform (provider plugin).

#### FR-INT-004 — CI/CD Pipeline Integration
- The system **shall** provide plugins for GitHub Actions, GitLab CI, and Jenkins enabling pipelines to retrieve secrets and keys securely without storing credentials in pipeline configuration.

---

### 4.10 Dashboard & Reporting

#### FR-DASH-001 — Security Operations Dashboard
- The system **shall** provide a real-time dashboard displaying: total active keys by type, keys nearing expiry (next 7/30/90 days), current anomaly feed with severity, top risky keys ranked by AI risk score, recent audit events, and compliance posture summary.
- The system **shall** support customizable dashboard widgets with drag-and-drop layout persistence per user.

#### FR-DASH-002 — AI Insights Panel
- The system **shall** display an AI Insights panel showing: active anomaly investigations, pending AI rotation recommendations, predictive compromise alerts, and model performance metrics (precision, recall, F1).
- The system **shall** allow Security Admins to provide feedback on AI recommendations (correct/incorrect) to improve model accuracy over time.

#### FR-DASH-003 — Key Inventory View
- The system **shall** provide a searchable, filterable key inventory with columns for: Key ID, name, type, algorithm, status, namespace, expiry, risk score, and last used.
- The system **shall** support bulk operations on selected keys: tag, rotate, suspend, and export to CSV.

---

### 4.11 Notifications & Alerting

#### FR-NOTIF-001 — Alert Channels
- The system **shall** support delivery of alerts and notifications via: email (SMTP/STARTTLS), Slack, Microsoft Teams, PagerDuty, OpsGenie, webhook (HTTP POST JSON), and SMS (via Twilio or AWS SNS).
- Each alert channel **shall** be configurable per alert severity level (Info, Warning, Critical).

#### FR-NOTIF-002 — Alert Types
- The system **shall** generate alerts for: key expiry approaching, certificate expiry approaching, anomaly detected (with risk score), AI-recommended rotation available, key destruction scheduled, policy violation, authentication failure (threshold-based), HSM connectivity loss, and compliance score degradation.

#### FR-NOTIF-003 — Alert Deduplication & Throttling
- The system **shall** deduplicate identical alerts within a configurable suppression window (default: 1 hour) to prevent alert fatigue.
- The system **shall** support alert escalation: if a Warning alert is not acknowledged within a configurable SLA, it is automatically escalated to Critical.

---

### 4.12 Disaster Recovery & High Availability

#### FR-DR-001 — High Availability
- The system **shall** support active-active multi-node deployment with no single point of failure for the API tier, AI inference tier, and storage tier.
- The system **shall** achieve an RTO (Recovery Time Objective) of ≤ 5 minutes and RPO (Recovery Point Objective) of ≤ 1 minute for any single node failure.

#### FR-DR-002 — Backup & Restore
- The system **shall** perform encrypted backups of all key material and configuration on a configurable schedule (default: hourly incremental, daily full).
- The system **shall** support off-site backup replication to a secondary region or cloud storage bucket.
- The system **shall** provide a tested, documented restore procedure with estimated time-to-restore displayed in the admin interface.

#### FR-DR-003 — Key Split & Escrow
- The system **shall** support Shamir's Secret Sharing to split sensitive master key material into N shares requiring M shares to reconstruct (configurable M-of-N).
- The system **shall** allow escrowed key shares to be securely distributed to designated custodians with hardware-token-protected delivery.

---

## 5. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-01 | Performance | API p99 latency ≤ 100 ms for key retrieval operations under normal load |
| NFR-02 | Performance | AI anomaly scoring latency ≤ 500 ms per event |
| NFR-03 | Scalability | Support ≥ 10,000 concurrent API clients and ≥ 100 million key-operation events per day |
| NFR-04 | Availability | System availability ≥ 99.99% uptime annually (≤ 52 min planned/unplanned downtime) |
| NFR-05 | Security | All data in transit encrypted using TLS 1.2+ (TLS 1.3 preferred); TLS 1.0/1.1 disabled |
| NFR-06 | Security | All cryptographic operations compliant with FIPS 140-3 when HSM backend is enabled |
| NFR-07 | Security | Zero trust architecture: every internal service-to-service call authenticated and authorized |
| NFR-08 | Usability | Web UI fully functional on modern browsers (Chrome, Firefox, Edge, Safari latest 2 versions) |
| NFR-09 | Maintainability | System deployed as containerized microservices (Kubernetes-native); infrastructure as code |
| NFR-10 | Observability | Expose Prometheus metrics for all services; distributed tracing via OpenTelemetry |

---

## 6. Assumptions & Constraints

- **A1:** AIKMS will be deployed on-premises, in a private cloud, or in a hybrid cloud environment. Multi-tenancy is achieved via namespace isolation, not separate deployments.
- **A2:** HSM devices are procured and physically managed by the customer. AIKMS communicates with HSMs over PKCS#11 or vendor-specific APIs.
- **A3:** The AI/ML training pipeline requires access to a minimum of 90 days of historical key-usage event data before producing reliable behavioral baselines.
- **A4:** Internet access from the AIKMS deployment is not required for core key management operations; threat intelligence feeds may be configured to operate in air-gapped mode via manual import.
- **C1:** AIKMS must not store cleartext private key material in any relational database, log file, or object store.
- **C2:** All changes to the AI model in production must pass a staged rollout with at least 48-hour soak testing in shadow mode before replacing the current model.
- **C3:** The system must be deployable in an air-gapped environment with no dependency on public internet services for core functionality.

---

## 7. Glossary

| Term | Definition |
|------|------------|
| **ABAC** | Attribute-Based Access Control — access decisions based on attributes of subject, resource, and environment |
| **ACME** | Automated Certificate Management Environment — protocol for automatic X.509 certificate issuance |
| **AI Engine** | The internal system component responsible for ML model inference, anomaly detection, and risk scoring |
| **Behavioral Baseline** | A statistical model of normal usage patterns for a given entity, derived from historical events |
| **DEK** | Data Encryption Key — a symmetric key used directly for encrypting data |
| **Envelope Encryption** | Encrypting a DEK with a Key Encryption Key (KEK) so that only the KEK needs to be tightly protected |
| **FIDO2 / WebAuthn** | Web Authentication standard for phishing-resistant hardware-backed MFA |
| **HSM** | Hardware Security Module — a tamper-resistant hardware device for secure key storage and cryptographic operations |
| **JIT Provisioning** | Just-In-Time user account creation triggered by the first SSO login |
| **KEK** | Key Encryption Key — a key used to encrypt/wrap other keys |
| **mTLS** | Mutual TLS — both client and server present certificates for authentication |
| **OIDC** | OpenID Connect — identity layer on top of OAuth 2.0 |
| **PKI** | Public Key Infrastructure — the framework of CAs, certificates, and policies |
| **PKCS#11** | Cryptographic Token Interface Standard — API for interacting with HSMs |
| **RPO** | Recovery Point Objective — maximum acceptable data loss measured in time |
| **RTO** | Recovery Time Objective — maximum tolerable downtime after a failure |
| **SCIM** | System for Cross-domain Identity Management — standard for user provisioning |
| **STIX/TAXII** | Structured Threat Information eXpression / Trusted Automated eXchange of Indicator Information — threat intel standards |
| **TTL** | Time-to-Live — duration before a dynamic secret or certificate is automatically revoked |

---

## 8. Technical Specification

### 8.1 System Architecture

AIKMS is built as a set of loosely coupled microservices communicating over mTLS-secured gRPC (internal) and REST/HTTP 2 (external). All services are stateless where possible; state is persisted in dedicated, independently scalable data stores.

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Gateway / Load Balancer              │
│              (Rate Limiting · Auth Enforcement · TLS Termination)│
└────────┬────────────────────────────────────────┬──────────────┘
         │ REST / HTTP2                            │ REST / HTTP2
┌────────▼──────────┐                   ┌─────────▼──────────────┐
│  Key Management   │◄──gRPC────────────► Policy Engine Service  │
│  Service (KMS)    │                   │  (OPA / Rego)          │
└────────┬──────────┘                   └────────────────────────┘
         │ gRPC
┌────────▼──────────┐   ┌────────────────────┐   ┌──────────────┐
│  AI/ML Engine     │   │  Audit Service      │   │  Secrets     │
│  Service          │   │  (Immutable Log)    │   │  Vault Svc   │
└────────┬──────────┘   └────────┬───────────┘   └──────┬───────┘
         │                       │                       │
┌────────▼───────────────────────▼───────────────────────▼───────┐
│              Event Bus  (Apache Kafka / NATS JetStream)         │
└────────┬───────────────────────┬───────────────────────┬───────┘
         │                       │                       │
┌────────▼──────────┐  ┌─────────▼──────────┐  ┌────────▼───────┐
│  Auth & Identity  │  │  Notification Svc  │  │  Certificate   │
│  Service (OIDC)   │  │  (Alert Dispatch)  │  │  Manager Svc   │
└────────┬──────────┘  └────────────────────┘  └────────────────┘
         │
┌────────▼────────────────────────────────────────────────────────┐
│              Storage Layer                                       │
│  PostgreSQL (metadata) · Redis (cache/session) · HSM (keys)     │
│  Object Store S3-compat (audit archive) · Vector DB (AI models) │
└─────────────────────────────────────────────────────────────────┘
```

#### Core Services

| Service | Responsibility |
|---------|---------------|
| **API Gateway** | TLS termination, rate limiting, OAuth 2.0 token introspection, request routing |
| **Key Management Service (KMS)** | Key CRUD, lifecycle state machine, versioning, envelope encryption, HSM offload |
| **Policy Engine Service** | ABAC policy evaluation (Open Policy Agent), policy CRUD, approval workflow orchestration |
| **AI/ML Engine Service** | Behavioral baseline training, real-time anomaly scoring, risk score computation, model registry |
| **Audit Service** | Immutable log ingestion, hash-chain maintenance, log export, SIEM forwarding |
| **Auth & Identity Service** | OIDC/SAML IdP federation, session management, SCIM provisioning, token issuance |
| **Secrets Vault Service** | Dynamic secret generation, lease management, secret versioning, injection adapters |
| **Certificate Manager Service** | X.509 lifecycle, ACME client, OCSP/CRL monitoring, push distribution |
| **Notification Service** | Alert routing, deduplication, escalation, multi-channel dispatch |

---

### 8.2 Technology Stack

#### Backend

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Service runtime | Java 21 (LTS) + Spring Boot 3.3 | Long-term support, virtual threads (Project Loom), mature security ecosystem |
| Web framework | Spring WebFlux (reactive) | Non-blocking I/O for high-concurrency key operation endpoints |
| Build tool | Gradle 8 (multi-module) | Fast incremental builds, dependency management across microservices |
| AI/ML inference | Python 3.12 + FastAPI | Ecosystem compatibility (scikit-learn, PyTorch, Hugging Face) |
| Java-Python bridge | gRPC (Protocol Buffers 3) | Strongly typed contracts between Java services and Python AI engine |
| Inter-service RPC | gRPC + Spring gRPC | Bidirectional streaming for event feeds between Java microservices |
| API gateway | Spring Cloud Gateway 4 + Envoy Proxy | Spring-native routing; Envoy for sidecar L7 policies and mTLS |
| Policy engine | Open Policy Agent (OPA) 0.65 + Java OPA client | Declarative Rego policies evaluated from Spring Security filter chain |
| Security framework | Spring Security 6 + Nimbus JOSE JWT | OAuth 2.0 resource server, mTLS client auth, JWT validation |
| Event bus | Apache Kafka 3.7 + Spring Kafka | Durable event log, @KafkaListener, replay support for ML retraining |
| Primary database | PostgreSQL 16 + Spring Data JPA / Hibernate 6 | ACID guarantees, row-level security for namespace isolation |
| Cache / session | Redis 7.2 (Sentinel mode) + Spring Data Redis | Sub-millisecond key metadata cache, session token storage |
| HSM interface | PKCS#11 v2.40 via Java PKCS11 Provider (SunPKCS11) | JCA/JCE integration with Thales, Entrust, AWS CloudHSM |
| Object storage | S3-compatible (MinIO / AWS S3) + AWS SDK v2 for Java | Audit log archiving, encrypted backup storage |
| Container orchestration | Kubernetes 1.30 | Service deployment, auto-scaling, rolling updates |
| Service mesh | Istio 1.21 | mTLS enforcement between all pods, traffic policies |
| Secrets bootstrap | HashiCorp Vault Agent / Spring Cloud Vault | AIKMS own secrets injected securely at startup via Spring Environment |

#### Frontend

| Layer | Technology |
|-------|------------|
| UI framework | React 18 + TypeScript 5 |
| State management | Zustand + React Query |
| Charts / dashboards | Apache ECharts |
| Design system | Tailwind CSS + Radix UI primitives |
| Build tool | Vite 5 |

#### Infrastructure

| Layer | Technology |
|-------|------------|
| Infrastructure as code | Terraform 1.8 + Helm 3 |
| CI/CD | GitHub Actions / GitLab CI |
| Observability | Prometheus + Grafana + Jaeger (OpenTelemetry) |
| Log aggregation | Fluent Bit → Elasticsearch/OpenSearch |
| Container registry | OCI-compliant (Harbor / ECR / ACR) |

---

### 8.3 Cryptographic Standards

#### Supported Key Algorithms

| Algorithm | Key Sizes | Permitted Purposes | Status |
|-----------|-----------|-------------------|--------|
| AES-GCM | 128, 256 bit | Encrypt, Decrypt, Wrap, Unwrap | ✅ Recommended |
| AES-CBC | 128, 256 bit | Encrypt, Decrypt (legacy interop only) | ⚠️ Legacy |
| RSA-OAEP | 2048, 3072, 4096 bit | Encrypt, Decrypt, Wrap | ✅ Supported |
| RSA-PSS | 2048, 3072, 4096 bit | Sign, Verify | ✅ Supported |
| ECDSA | P-256, P-384, P-521 | Sign, Verify | ✅ Recommended |
| ECDH | P-256, P-384, P-521 | Key Agreement | ✅ Supported |
| Ed25519 | 256 bit | Sign, Verify | ✅ Recommended |
| HMAC | SHA-256, SHA-384, SHA-512 | MAC, Authenticate | ✅ Supported |
| X25519 | 256 bit | Key Agreement | ✅ Supported |

#### Prohibited Algorithms

The system **shall** reject key creation requests using: DES, 3DES, RC4, MD5-based MACs, RSA < 2048 bits, EC curves other than NIST-approved or Curve25519.

#### Envelope Encryption Scheme

```
Plaintext Key Material
        │
        ▼  AES-256-GCM (random per-key DEK)
  Encrypted Key Material  ──stored in PostgreSQL──►  key_versions table
        │
   DEK encrypted with namespace KEK (AES-256-GCM)
        │
   KEK encrypted with Master Key (stored in HSM or cloud KMS root)
```

#### Random Number Generation

- All key material generated using CSPRNG: `/dev/urandom` (Linux), `BCryptGenRandom` (Windows), or HSM on-board RNG when HSM backend is active.
- Entropy health checks run at service startup; service refuses to start if available entropy < 256 bits.

---

### 8.4 AI/ML Architecture

#### Anomaly Detection Pipeline

```
Kafka Topic: key-usage-events
        │
        ▼
  Feature Extraction Service
  (caller_id, key_id, op_type, src_ip, geo, hour_of_day,
   day_of_week, ops_per_minute, namespace, key_age)
        │
        ▼
  Online Scoring Engine  ──────────────────────────────────►  Anomaly Score (0-100)
  (Isolation Forest + Autoencoder ensemble,                          │
   served via ONNX Runtime, p99 < 20 ms)                            ▼
        │                                               Kafka Topic: anomaly-events
        ▼                                                           │
  Behavioral Baseline Store                                         ▼
  (per-entity rolling statistics,                         Alert & Incident Pipeline
   updated every 5 minutes,
   stored in Redis TimeSeries)
        │
        ▼
  Batch Retraining Pipeline  (weekly, Apache Spark / Ray)
  └── Feature store: Delta Lake
  └── Model registry: MLflow
  └── Shadow eval: 48-hour A/B soak before promotion
```

#### ML Models

| Model | Type | Purpose | Retraining Cadence |
|-------|------|---------|--------------------|
| Behavioral Anomaly Detector | Isolation Forest | Per-event unsupervised anomaly scoring | Weekly + on significant drift |
| Autoencoder Reconstruction | LSTM Autoencoder | Temporal sequence anomaly detection | Weekly |
| Compromise Classifier | Gradient Boosted Trees (XGBoost) | Predict key compromise probability | Weekly |
| Policy Recommendation Engine | Rule-based + LLM-assisted (offline) | Suggest policy improvements | On-demand |

#### Feature Engineering

| Feature | Type | Description |
|---------|------|-------------|
| `ops_per_minute` | Numeric | Rolling 1-min operation count per caller |
| `geo_risk_score` | Numeric | Country-level threat score from threat intel feed |
| `hour_sin` / `hour_cos` | Cyclic encoding | Time of day (cyclically encoded) |
| `is_new_ip` | Boolean | Source IP not seen in past 30 days for this caller |
| `key_age_days` | Numeric | Days since key creation |
| `cross_namespace` | Boolean | Operation targets a namespace atypical for caller |
| `concurrent_ip_count` | Numeric | Distinct IPs seen for same credential in past 5 min |
| `velocity_delta` | Numeric | % change in ops/min vs 7-day baseline |

---

### 8.5 Data Models

#### Key Entity

```sql
CREATE TABLE keys (
  key_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  namespace_id     UUID NOT NULL REFERENCES namespaces(namespace_id),
  algorithm        TEXT NOT NULL,            -- e.g. 'AES-256-GCM'
  key_size_bits    INTEGER NOT NULL,
  purpose          TEXT[] NOT NULL,           -- ['ENCRYPT','DECRYPT']
  state            TEXT NOT NULL,             -- enum: PENDING|ACTIVE|SUSPENDED|DEPRECATED|SCHEDULED_DESTROY|DESTROYED
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by       UUID NOT NULL REFERENCES identities(identity_id),
  expires_at       TIMESTAMPTZ,
  current_version  INTEGER NOT NULL DEFAULT 1,
  risk_score       NUMERIC(5,2) DEFAULT 0,
  tags             JSONB DEFAULT '{}',
  hsm_backed       BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE key_versions (
  version_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id               UUID NOT NULL REFERENCES keys(key_id),
  version_number       INTEGER NOT NULL,
  encrypted_key_dek    BYTEA NOT NULL,        -- DEK wrapped with namespace KEK
  dek_iv               BYTEA NOT NULL,
  dek_tag              BYTEA NOT NULL,
  key_checksum         TEXT NOT NULL,         -- SHA-256 of plaintext key (for integrity)
  state                TEXT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at           TIMESTAMPTZ,
  UNIQUE (key_id, version_number)
);
```

#### Audit Log Entry

```sql
CREATE TABLE audit_log (
  event_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sequence_number  BIGSERIAL UNIQUE NOT NULL,  -- monotonic, gap-free
  prev_hash        TEXT NOT NULL,              -- SHA-256 of previous row
  event_hash       TEXT NOT NULL,              -- SHA-256 of this row content
  timestamp_utc    TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id         UUID,
  actor_type       TEXT NOT NULL,              -- HUMAN | SERVICE_ACCOUNT | AI_ENGINE
  source_ip        INET,
  session_id       UUID,
  action           TEXT NOT NULL,              -- e.g. 'KEY_CREATE', 'KEY_ROTATE'
  resource_type    TEXT NOT NULL,
  resource_id      UUID,
  outcome          TEXT NOT NULL,              -- SUCCESS | FAILURE
  detail           JSONB DEFAULT '{}'
);
-- Append-only enforced via PostgreSQL row security:
-- REVOKE UPDATE, DELETE ON audit_log FROM aikms_app;
```

#### Policy Definition

```json
{
  "policy_id": "uuid",
  "name": "production-crypto-policy",
  "namespace_id": "uuid | null (global)",
  "version": 3,
  "rules": {
    "allowed_algorithms": ["AES-256-GCM", "RSA-4096", "ECDSA-P384"],
    "min_key_size_bits": 256,
    "max_key_age_days": 90,
    "rotation_interval_days": 30,
    "rotation_triggers": ["ANOMALY_SCORE_GT_70", "TIME_BASED"],
    "export_allowed": false,
    "approval_required_for": ["KEY_CREATE", "KEY_DESTROY", "POLICY_CHANGE"],
    "approval_quorum": { "required": 2, "of": 3 }
  },
  "created_by": "uuid",
  "created_at": "ISO-8601",
  "effective_from": "ISO-8601",
  "supersedes": "policy_id | null"
}
```

---

### 8.6 API Specification

#### Authentication Flows

| Client Type | Flow | Token Lifetime |
|-------------|------|----------------|
| Human user (browser) | OIDC Authorization Code + PKCE | Access: 15 min, Refresh: 8 hr |
| Service account (API) | OAuth 2.0 Client Credentials | Access: 60 min |
| Service account (zero-trust) | mTLS (cert-bound token) | TLS session lifetime |
| CI/CD pipeline | Short-lived JWT via OIDC federation | 5 min |

#### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/keys` | Create a new key |
| `GET` | `/api/v1/keys/{keyId}` | Retrieve key metadata |
| `GET` | `/api/v1/keys` | List keys (paginated, filterable) |
| `PATCH` | `/api/v1/keys/{keyId}` | Update key metadata / state |
| `DELETE` | `/api/v1/keys/{keyId}` | Schedule key for destruction |
| `POST` | `/api/v1/keys/{keyId}/rotate` | Trigger manual rotation |
| `POST` | `/api/v1/keys/{keyId}/encrypt` | Encrypt data with key |
| `POST` | `/api/v1/keys/{keyId}/decrypt` | Decrypt data with key |
| `POST` | `/api/v1/keys/{keyId}/sign` | Sign data with key |
| `POST` | `/api/v1/keys/{keyId}/verify` | Verify signature with key |
| `GET` | `/api/v1/keys/{keyId}/versions` | List all versions |

#### Error Response Schema

```json
{
  "error": {
    "code": "KEY_NOT_FOUND",
    "message": "The requested key does not exist or is not accessible.",
    "request_id": "uuid",
    "timestamp": "ISO-8601",
    "details": {}
  }
}
```

#### Standard Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `INVALID_ALGORITHM` | Requested algorithm is not permitted by policy |
| 401 | `UNAUTHENTICATED` | Missing or invalid bearer token / client cert |
| 403 | `POLICY_DENIED` | ABAC policy evaluation returned deny |
| 404 | `KEY_NOT_FOUND` | Key ID does not exist in caller's namespace |
| 409 | `KEY_STATE_CONFLICT` | Operation not permitted in current key state |
| 422 | `KEY_PURPOSE_MISMATCH` | Key purpose does not allow requested operation |
| 429 | `RATE_LIMIT_EXCEEDED` | Caller has exceeded configured rate limit |
| 503 | `HSM_UNAVAILABLE` | Backing HSM is unreachable; operation cannot proceed |

---

### 8.7 Infrastructure & Deployment

#### Minimum Production Cluster (Kubernetes)

| Component | Min Replicas | CPU Request | Memory Request | Notes |
|-----------|-------------|-------------|----------------|-------|
| API Gateway (Envoy) | 3 | 500m | 256 Mi | Anti-affinity across nodes |
| Key Management Service | 3 | 1000m | 512 Mi | Stateless; scales horizontally |
| AI/ML Engine (Python) | 2 | 2000m | 2 Gi | GPU optional for training |
| Policy Engine (OPA) | 2 | 250m | 128 Mi | Sidecar or standalone |
| Audit Service | 2 | 500m | 256 Mi | Append-only write path |
| Auth & Identity Service | 2 | 500m | 256 Mi | |
| Notification Service | 2 | 250m | 128 Mi | |
| PostgreSQL (primary + replica) | 2 | 2000m | 4 Gi | Synchronous replication |
| Redis Sentinel | 3 | 500m | 1 Gi | |
| Kafka brokers | 3 | 2000m | 4 Gi | Replication factor 3 |

#### Network Topology

- **Ingress zone:** API Gateway only; all external traffic terminates here.
- **Service zone:** Internal microservices communicate over the Istio service mesh with mTLS enforced; no direct external exposure.
- **Data zone:** PostgreSQL, Redis, Kafka, and HSM network segments are isolated with Kubernetes `NetworkPolicy`; only whitelisted service pods may connect.
- **HSM zone:** Dedicated network segment or dedicated HSM VLAN; PKCS#11 traffic travels only within this zone.

#### HSM Connectivity

| HSM Product | Interface | AIKMS Driver |
|-------------|-----------|-------------|
| Thales Luna Network HSM | PKCS#11 over HSM client library | `thales-pkcs11` plugin |
| Entrust nShield | PKCS#11 | `nshield-pkcs11` plugin |
| AWS CloudHSM | PKCS#11 + JCE | `aws-cloudhsm` plugin |
| Azure Dedicated HSM | PKCS#11 | `azure-dhsm-pkcs11` plugin |
| Soft-HSM (dev/test) | PKCS#11 | `softhsm2` plugin |

---

### 8.8 Security Architecture

#### Zero Trust Model

- **No implicit trust:** Every request — internal or external — presents a credential and is evaluated against policy.
- **Short-lived credentials:** All service-to-service tokens have a maximum TTL of 60 minutes; HSM session tokens rotate every 15 minutes.
- **Continuous verification:** AI Engine evaluates risk score on each API call; elevated scores trigger additional step-up authentication challenges.
- **Least privilege:** Each microservice has a distinct Kubernetes `ServiceAccount` mapped to a minimally scoped Vault role; services cannot read secrets not relevant to their function.

#### AIKMS Own Secret Bootstrap

```
Kubernetes Secrets Operator (CSI driver)
        │
        ▼
  Vault AppRole (short-lived token)
        │
        ▼
  AIKMS Service receives:
    - DB connection credentials (dynamic, 1-hr lease)
    - JWT signing private key (rotated daily)
    - Kafka SASL credentials (rotated hourly)
  None of these are stored in container images or ConfigMaps.
```

#### TLS Configuration

| Context | Protocol | Cipher Suites |
|---------|----------|---------------|
| External (client ↔ Gateway) | TLS 1.3 preferred, TLS 1.2 min | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE-RSA-AES256-GCM-SHA384 |
| Internal (service ↔ service) | TLS 1.3 (Istio mTLS) | TLS_AES_256_GCM_SHA384 |
| HSM channel | TLS 1.2+ per HSM vendor | Vendor-specified; AES-256-GCM minimum |

TLS 1.0, TLS 1.1, SSLv3, RC4, export ciphers, and anonymous DH are explicitly disabled in all Envoy proxy and Java (`SSLContext`) TLS configurations.

#### Container Security

- All container images built from `distroless` base images (Google or Chainguard) to minimize attack surface.
- Images are signed with Sigstore/Cosign; admission webhook (`Kyverno`) enforces signature verification before pod scheduling.
- All containers run as non-root (`runAsNonRoot: true`), with read-only root filesystems and dropped Linux capabilities (`ALL` dropped, only `NET_BIND_SERVICE` added where needed).
- Trivy vulnerability scanning integrated in CI/CD; High or Critical CVEs block image promotion.

---

### 8.9 Performance & Scalability Design

#### Caching Strategy

| Data | Cache Layer | TTL | Invalidation Trigger |
|------|-------------|-----|---------------------|
| Key metadata | Redis (per-namespace) | 60 s | Key state change event on Kafka |
| ABAC policy decisions | OPA in-process | 30 s | Policy version change |
| User session tokens | Redis | Session TTL | Logout / forced expiry |
| Behavioral baseline vectors | Redis TimeSeries | Rolling 30 days | Continuous update |
| Threat intel IP blocklist | Redis Set | 15 min | Feed refresh cycle |
| Certificate status (OCSP) | Redis | 1 hr | Revocation event |

#### Auto-Scaling Thresholds

| Service | Scale-Out Trigger | Max Replicas |
|---------|------------------|-------------|
| Key Management Service | CPU > 70% or p95 latency > 80 ms | 20 |
| AI/ML Engine | Queue depth > 500 events or CPU > 80% | 10 |
| API Gateway (Envoy) | RPS > 5,000 / replica | 10 |
| Audit Service | Kafka consumer lag > 10,000 events | 8 |

#### Database Connection Pooling

- PgBouncer in transaction pooling mode deployed as a sidecar per KMS pod.
- Maximum pool size: 20 connections per pod; idle timeout: 300 s.
- PostgreSQL configured with `max_connections = 500`; connection slots reserved per service tier.

#### Kafka Topic Configuration

| Topic | Partitions | Replication Factor | Retention | Compaction |
|-------|-----------|-------------------|-----------|------------|
| `key-usage-events` | 24 | 3 | 30 days | None |
| `anomaly-events` | 12 | 3 | 90 days | None |
| `audit-events` | 12 | 3 | 7 years (tiered) | None |
| `rotation-commands` | 6 | 3 | 7 days | Log compacted |
| `notification-dispatch` | 6 | 3 | 24 hours | None |

---

## 9. User Stories & Acceptance Criteria

### 9.1 Key Lifecycle

#### US-KLM-001 — Create a Cryptographic Key
**As a** Key Operator,  
**I want to** create a new cryptographic key with a specified algorithm, purpose, and expiry,  
**So that** my application can use it for encryption without managing raw key material.

**Acceptance Criteria:**
- [ ] Given valid inputs, the API returns HTTP 201 with a `key_id` (UUID v4) and `version = 1`.
- [ ] Given a prohibited algorithm (e.g., DES), the API returns HTTP 400 with `INVALID_ALGORITHM`.
- [ ] Given a key size below the configured minimum, the API returns HTTP 400 with `INVALID_KEY_SIZE`.
- [ ] The key is created in `Pending` state and transitions to `Active` only after successful HSM/software generation.
- [ ] An audit log entry with `action = KEY_CREATE` and `outcome = SUCCESS` is written within 1 second.
- [ ] The key is not usable for encryption until state is `Active`.

#### US-KLM-002 — Encrypt Data Using a Key
**As a** Developer (Service Account),  
**I want to** encrypt a plaintext payload via the API using a named key,  
**So that** my service never handles raw key material.

**Acceptance Criteria:**
- [ ] Given a valid `keyId` and base64-encoded plaintext, the API returns HTTP 200 with a base64-encoded ciphertext and the `key_version` used.
- [ ] Given a key in `Suspended` or `Destroyed` state, the API returns HTTP 409 `KEY_STATE_CONFLICT`.
- [ ] Given a signing key used for encrypt, the API returns HTTP 422 `KEY_PURPOSE_MISMATCH`.
- [ ] The raw key material is never present in the API response.
- [ ] Rate limit is enforced per caller; HTTP 429 is returned when exceeded.

#### US-KLM-003 — Retire and Destroy a Key
**As a** Security Admin,  
**I want to** schedule a key for destruction with dual-control approval,  
**So that** sensitive key material is securely erased and non-recoverable.

**Acceptance Criteria:**
- [ ] A single admin cannot move a key to `Scheduled for Destruction` — a second admin approval is required.
- [ ] After scheduling, the key enters a configurable cooling-off period (default 7 days) before physical destruction.
- [ ] During the cooling-off period, destruction can be cancelled by an authorized admin.
- [ ] After destruction, all key versions are cryptographically overwritten.
- [ ] A destruction certificate entry is written to the audit log.
- [ ] Any subsequent use attempt on a destroyed key returns HTTP 409 `KEY_STATE_CONFLICT`.

---

### 9.2 AI & Anomaly Detection

#### US-AI-001 — View Anomaly Alerts
**As a** Security Admin,  
**I want to** see real-time anomaly alerts with risk scores and explanations,  
**So that** I can investigate and respond to potential key compromise.

**Acceptance Criteria:**
- [ ] The dashboard displays all anomaly events with score, timestamp, caller, and anomaly category.
- [ ] Anomaly events are surfaced within 5 seconds of detection.
- [ ] Each alert links to the affected key, caller identity, and contributing factor breakdown.
- [ ] Alerts can be filtered by severity (score threshold), date range, namespace, and key.

#### US-AI-002 — Accept or Dismiss AI Rotation Recommendation
**As a** Security Admin,  
**I want to** accept or dismiss AI-generated key rotation recommendations,  
**So that** I have final control over rotation decisions while benefiting from AI insight.

**Acceptance Criteria:**
- [ ] Pending recommendations are shown in the AI Insights panel with risk factors listed.
- [ ] Accepting a recommendation immediately triggers the zero-downtime rotation workflow.
- [ ] Dismissing a recommendation requires a written justification (minimum 20 characters).
- [ ] The dismissal reason and admin identity are recorded in the audit log.
- [ ] Deferred recommendations re-surface after a configurable reminder interval (default 24 hours).

---

### 9.3 Access Control

#### US-AC-001 — Log In with SSO and MFA
**As a** Security Admin,  
**I want to** authenticate via my enterprise SSO (OIDC) with FIDO2 MFA,  
**So that** I can access the system without a separate password.

**Acceptance Criteria:**
- [ ] The login page redirects to the configured OIDC IdP.
- [ ] After IdP authentication, FIDO2/WebAuthn challenge is presented before dashboard access is granted.
- [ ] Failed MFA results in session termination and an audit log entry.
- [ ] Session expires after 30 minutes of inactivity and requires re-authentication.
- [ ] JIT provisioning creates a user account if one does not exist and the IdP group mapping permits it.

#### US-AC-002 — Service Account API Access
**As a** Developer,  
**I want to** authenticate my service using OAuth 2.0 Client Credentials,  
**So that** my application can access keys programmatically without user interaction.

**Acceptance Criteria:**
- [ ] A valid `client_id` + `client_secret` exchange returns a Bearer token (TTL 60 min).
- [ ] The token is scoped to the namespaces and operations permitted by the ABAC policy.
- [ ] An expired or revoked token returns HTTP 401 `UNAUTHENTICATED`.
- [ ] mTLS client certificate authentication is an alternative to client secret.

---

### 9.4 Compliance & Audit

#### US-AUDIT-001 — Generate a PCI-DSS Compliance Report
**As an** Auditor,  
**I want to** generate a PCI-DSS compliance report for a specific date range,  
**So that** I can provide evidence for our annual QSA audit.

**Acceptance Criteria:**
- [ ] Report includes: all key creation/rotation/destruction events, policy change events, access control changes, and failed authentication attempts within the date range.
- [ ] Report is exportable as PDF and CSV.
- [ ] Report generation completes within 60 seconds for a 12-month range.
- [ ] Only users with the `Auditor` role can generate compliance reports.
- [ ] Report includes a compliance posture score and a list of open findings.

---

## 10. Key Lifecycle State Machine

### 10.1 Key States

| State | Description |
|-------|-------------|
| `PENDING` | Key material is being generated; not yet usable |
| `ACTIVE` | Key is fully operational for all permitted purposes |
| `SUSPENDED` | Key is temporarily disabled; operations blocked but material retained |
| `DEPRECATED` | Key is superseded by a new version; decryption allowed, encryption blocked |
| `SCHEDULED_DESTROY` | Destruction approved; cooling-off period in progress |
| `DESTROYED` | Key material cryptographically overwritten; record retained for audit |

### 10.2 State Transition Table

| From State | Trigger | To State | Who Can Trigger | Side Effects |
|------------|---------|----------|-----------------|--------------|
| *(new)* | Key generation complete | `PENDING → ACTIVE` | System (KMS) | Kafka `KEY_CREATED` event; audit log entry |
| `ACTIVE` | Admin suspends key | `ACTIVE → SUSPENDED` | Security Admin | Kafka `KEY_SUSPENDED`; cache invalidated; consumers notified |
| `ACTIVE` | Rotation triggered | `ACTIVE → DEPRECATED` | System / Admin | New version created as `ACTIVE`; consumers notified |
| `ACTIVE` | Dual-control approval | `ACTIVE → SCHEDULED_DESTROY` | 2× Security Admins | Cooling-off timer started; Kafka `KEY_DESTRUCTION_SCHEDULED` |
| `SUSPENDED` | Admin re-enables | `SUSPENDED → ACTIVE` | Security Admin | Kafka `KEY_RESUMED`; cache updated |
| `SUSPENDED` | Dual-control approval | `SUSPENDED → SCHEDULED_DESTROY` | 2× Security Admins | Cooling-off timer started |
| `DEPRECATED` | All consumers migrated OR grace period expires | `DEPRECATED → SCHEDULED_DESTROY` | System | Kafka `KEY_DEPRECATION_COMPLETE` |
| `SCHEDULED_DESTROY` | Admin cancels during cooling-off | `SCHEDULED_DESTROY → SUSPENDED` | Security Admin | Cooling-off timer cancelled; audit log entry |
| `SCHEDULED_DESTROY` | Cooling-off period elapses | `SCHEDULED_DESTROY → DESTROYED` | System (scheduler) | Key material overwritten; destruction certificate in audit log |
| `DEPRECATED` | Admin explicitly retires | `DEPRECATED → SUSPENDED` | Security Admin | Kafka `KEY_SUSPENDED` |

### 10.3 Transition Rules

- Only `ACTIVE` and `SUSPENDED` keys can be used for decryption/verification (for previous-version interop).
- Only `ACTIVE` keys can be used for encryption/signing.
- Any transition into `SCHEDULED_DESTROY` requires two distinct Security Admin identities recorded as approvers.
- `DESTROYED` is a terminal state — no transitions out are permitted.
- If key generation fails, the key record is deleted entirely (no `PENDING` state persists).

---

## 11. Critical Flow Sequence Diagrams

### 11.1 Key Creation (HSM-Backed)

```
Client          API Gateway       KMS Service       Policy Engine     HSM               Audit Service
  |                  |                 |                  |              |                     |
  |--POST /keys ----->|                 |                  |              |                     |
  |                  |--Validate JWT-->|                  |              |                     |
  |                  |                 |--Evaluate ABAC-->|              |                     |
  |                  |                 |<--ALLOW----------|              |                     |
  |                  |                 |--Generate Key---------------------->|               |
  |                  |                 |                  |              |--RNG + Store------>|
  |                  |                 |<--Key Handle (no material)---------|               |
  |                  |                 |--Write key metadata (PostgreSQL)                    |
  |                  |                 |--Publish KEY_CREATED (Kafka)----------------------->|
  |                  |                 |                  |              |                     |--Write audit entry
  |                  |<--201 key_id----|                  |              |                     |
  |<--201 key_id------|                 |                  |              |                     |
```

### 11.2 Zero-Downtime Key Rotation

```
Scheduler / Admin    KMS Service         Consumer Registry    Consumers (N)        Audit Service
       |                  |                     |                    |                    |
       |--Trigger Rotate-->|                     |                    |                    |
       |                  |--Create new version (v+1) in HSM/software                     |
       |                  |--Deprecate old version (vN → DEPRECATED)                      |
       |                  |--Publish ROTATION_STARTED (Kafka)-------->|                   |
       |                  |                     |<--Fetch consumers--->|                   |
       |                  |                     |--Notify each consumer (push/pull)-------->|
       |                  |                     |<--Consumer ACK (per consumer)------------|
       |                  |--Track ACK progress (rotation status dashboard)               |
       |                  |                     |                                           |
       |    [All ACKed OR grace period elapsed]                                            |
       |                  |--Retire old version (DEPRECATED → SCHEDULED_DESTROY)          |
       |                  |--Publish ROTATION_COMPLETE (Kafka)------------------------>|  |
       |                  |                     |                    |                    |--Write audit entry
       |
       |    [>N% consumers report errors during grace period]
       |                  |--Rollback: promote old version back to ACTIVE
       |                  |--Publish ROTATION_ROLLED_BACK (Kafka)
```

### 11.3 Anomaly Detection → AI Rotation Recommendation

```
App / Service     Kafka               AI Engine             Risk Engine        KMS Service     Security Admin (UI)
      |              |                    |                     |                   |                  |
      |--Key op------>|                    |                    |                   |                  |
      |              |--key-usage-event-->|                    |                   |                  |
      |              |                    |--Extract features   |                   |                  |
      |              |                    |--Score (Isolation Forest + LSTM)        |                   |
      |              |                    |--Anomaly score = 87                     |                   |
      |              |                    |--Publish ANOMALY_DETECTED (score=87)--->|                  |
      |              |                    |                     |--Recompute Key Risk Score             |
      |              |                    |                     | (risk_score → 92)                     |
      |              |                    |                     |--Publish KEY_RISK_UPDATED------------>|
      |              |                    |                     |                   |--Threshold > 80   |
      |              |                    |                     |                   |--Create Rotation Recommendation
      |              |                    |                     |                   |--Notify Admin UI-->|
      |              |                    |                     |                   |         [Admin accepts]
      |              |                    |                     |                   |<--POST /keys/{id}/rotate
      |              |                    |                     |                   |--Trigger rotation workflow (see 11.2)
```

### 11.4 Dual-Control Key Destruction

```
Admin A              KMS Service           Approval Service       Admin B           Audit Service
   |                     |                      |                     |                   |
   |--POST /keys/{id}/destroy-request-->|        |                   |                   |
   |                     |--Create ApprovalRequest (quorum 2/2)----->|                   |
   |                     |                      |--Notify Admin B (email + UI)----------->|
   |                     |                      |                     |                   |
   |                     |                      |<--Admin B approves--|                   |
   |                     |--2/2 approvals met                         |                   |
   |                     |--Transition key: ACTIVE → SCHEDULED_DESTROY                   |
   |                     |--Start cooling-off timer (7 days)          |                   |
   |                     |--Publish KEY_DESTRUCTION_SCHEDULED-------->|                  |
   |                     |                      |                     |                   |--Write audit (both approvers recorded)
   |
   [7 days elapse, no cancellation]
   |                     |--Crypto-overwrite all key material in HSM/store
   |                     |--Transition: SCHEDULED_DESTROY → DESTROYED
   |                     |--Write destruction certificate to audit log------------>|
```

---

## 12. Complete Database Schema

### 12.1 Core Tables

```sql
-- Namespaces (tenant/project isolation units)
CREATE TABLE namespaces (
  namespace_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL UNIQUE,
  parent_id        UUID REFERENCES namespaces(namespace_id),  -- for hierarchy
  description      TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by       UUID,
  is_active        BOOLEAN NOT NULL DEFAULT true
);

-- Identities (humans and service accounts)
CREATE TABLE identities (
  identity_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id      TEXT UNIQUE,             -- IdP subject claim
  identity_type    TEXT NOT NULL,           -- HUMAN | SERVICE_ACCOUNT | AI_ENGINE
  name             TEXT NOT NULL,
  email            TEXT,
  role             TEXT NOT NULL,           -- SUPER_ADMIN | SECURITY_ADMIN | KEY_OPERATOR | AUDITOR | DEVELOPER
  namespace_id     UUID REFERENCES namespaces(namespace_id),
  is_active        BOOLEAN NOT NULL DEFAULT true,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at    TIMESTAMPTZ,
  mfa_enrolled     BOOLEAN NOT NULL DEFAULT false
);

-- Sessions
CREATE TABLE sessions (
  session_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id      UUID NOT NULL REFERENCES identities(identity_id),
  issued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  last_active_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_ip        INET,
  user_agent       TEXT,
  is_revoked       BOOLEAN NOT NULL DEFAULT false,
  revoked_reason   TEXT
);
CREATE INDEX idx_sessions_identity ON sessions(identity_id) WHERE NOT is_revoked;
```

### 12.2 Key Tables (full schema)

```sql
-- Namespaces KEK references
CREATE TABLE namespace_keks (
  kek_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id     UUID NOT NULL REFERENCES namespaces(namespace_id),
  kek_reference    TEXT NOT NULL,           -- HSM handle or cloud KMS key ARN
  version          INTEGER NOT NULL DEFAULT 1,
  is_active        BOOLEAN NOT NULL DEFAULT true,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Keys (see §8.5 for base definition — extended here)
-- (key_id, name, namespace_id, algorithm, etc. per §8.5)
ALTER TABLE keys ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES identities(identity_id);
ALTER TABLE keys ADD COLUMN IF NOT EXISTS rotation_policy_id UUID;  -- FK added below
CREATE INDEX idx_keys_namespace ON keys(namespace_id);
CREATE INDEX idx_keys_state ON keys(state);
CREATE INDEX idx_keys_expires ON keys(expires_at) WHERE state = 'ACTIVE';
CREATE INDEX idx_keys_risk ON keys(risk_score DESC) WHERE state = 'ACTIVE';

-- Key versions (extended from §8.5)
CREATE INDEX idx_key_versions_key ON key_versions(key_id);

-- Approval requests (dual-control)
CREATE TABLE approval_requests (
  request_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_type    TEXT NOT NULL,           -- KEY | POLICY | SECRET
  resource_id      UUID NOT NULL,
  operation        TEXT NOT NULL,           -- DESTROY | EXPORT | POLICY_CHANGE
  requested_by     UUID NOT NULL REFERENCES identities(identity_id),
  requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  required_quorum  INTEGER NOT NULL,
  status           TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING | APPROVED | REJECTED | CANCELLED
  expires_at       TIMESTAMPTZ,
  external_ticket  TEXT                     -- Jira/ServiceNow ticket reference
);

CREATE TABLE approval_votes (
  vote_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id       UUID NOT NULL REFERENCES approval_requests(request_id),
  approver_id      UUID NOT NULL REFERENCES identities(identity_id),
  decision         TEXT NOT NULL,           -- APPROVE | REJECT
  comment          TEXT,
  voted_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (request_id, approver_id)
);
```

### 12.3 Policy Tables

```sql
CREATE TABLE policies (
  policy_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  namespace_id     UUID REFERENCES namespaces(namespace_id),  -- NULL = global
  current_version  INTEGER NOT NULL DEFAULT 1,
  created_by       UUID NOT NULL REFERENCES identities(identity_id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  is_active        BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE policy_versions (
  version_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id        UUID NOT NULL REFERENCES policies(policy_id),
  version_number   INTEGER NOT NULL,
  rules            JSONB NOT NULL,          -- full policy rules object (see §8.5)
  created_by       UUID NOT NULL REFERENCES identities(identity_id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  effective_from   TIMESTAMPTZ,
  supersedes       UUID REFERENCES policy_versions(version_id),
  UNIQUE (policy_id, version_number)
);

CREATE TABLE rotation_policies (
  rotation_policy_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id             UUID REFERENCES namespaces(namespace_id),
  applies_to_algorithm     TEXT,            -- NULL = all algorithms
  rotation_interval_days   INTEGER,
  max_usage_count          BIGINT,
  anomaly_score_threshold  NUMERIC(5,2),
  notify_lead_days         INTEGER NOT NULL DEFAULT 14,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE keys ADD CONSTRAINT fk_keys_rotation_policy
  FOREIGN KEY (rotation_policy_id) REFERENCES rotation_policies(rotation_policy_id);
```

### 12.4 Secrets & Certificate Tables

```sql
CREATE TABLE secrets (
  secret_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL,
  namespace_id     UUID NOT NULL REFERENCES namespaces(namespace_id),
  secret_type      TEXT NOT NULL,           -- STATIC | DYNAMIC
  backend_type     TEXT,                    -- POSTGRESQL | MYSQL | AWS_IAM | etc.
  current_version  INTEGER NOT NULL DEFAULT 1,
  lease_ttl_seconds INTEGER,
  state            TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by       UUID NOT NULL REFERENCES identities(identity_id),
  expires_at       TIMESTAMPTZ,
  UNIQUE (name, namespace_id)
);

CREATE TABLE secret_versions (
  version_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id        UUID NOT NULL REFERENCES secrets(secret_id),
  version_number   INTEGER NOT NULL,
  encrypted_value  BYTEA NOT NULL,
  iv               BYTEA NOT NULL,
  tag              BYTEA NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ,
  UNIQUE (secret_id, version_number)
);

CREATE TABLE certificates (
  certificate_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id     UUID NOT NULL REFERENCES namespaces(namespace_id),
  common_name      TEXT NOT NULL,
  subject          TEXT NOT NULL,
  issuer           TEXT NOT NULL,
  serial_number    TEXT NOT NULL,
  not_before       TIMESTAMPTZ NOT NULL,
  not_after        TIMESTAMPTZ NOT NULL,
  associated_service TEXT,
  pem_certificate  TEXT NOT NULL,          -- stored encrypted at rest
  status           TEXT NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | EXPIRED | REVOKED
  renewal_source   TEXT,                   -- ACME | INTERNAL_PKI | MANUAL
  last_checked_at  TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_certs_expiry ON certificates(not_after) WHERE status = 'ACTIVE';
```

### 12.5 AI/ML & Anomaly Tables

```sql
CREATE TABLE ai_models (
  model_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_type       TEXT NOT NULL,           -- ANOMALY_DETECTOR | COMPROMISE_CLASSIFIER | POLICY_REC
  version          TEXT NOT NULL,
  mlflow_run_id    TEXT,
  onnx_artifact_path TEXT,
  precision_score  NUMERIC(5,4),
  recall_score     NUMERIC(5,4),
  f1_score         NUMERIC(5,4),
  training_date    TIMESTAMPTZ NOT NULL,
  promoted_at      TIMESTAMPTZ,
  is_production    BOOLEAN NOT NULL DEFAULT false,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE anomaly_events (
  anomaly_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id         UUID,                    -- source key-usage event ID
  key_id           UUID REFERENCES keys(key_id),
  caller_id        UUID REFERENCES identities(identity_id),
  anomaly_score    NUMERIC(5,2) NOT NULL,
  anomaly_types    TEXT[] NOT NULL,         -- ['VOLUMETRIC','TEMPORAL', etc.]
  model_id         UUID REFERENCES ai_models(model_id),
  detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  session_risk_score NUMERIC(5,2),
  status           TEXT NOT NULL DEFAULT 'OPEN',  -- OPEN | INVESTIGATING | RESOLVED | FALSE_POSITIVE
  feedback         TEXT                     -- CORRECT | INCORRECT (from admin)
);
CREATE INDEX idx_anomaly_key ON anomaly_events(key_id);
CREATE INDEX idx_anomaly_status ON anomaly_events(status) WHERE status = 'OPEN';
```

### 12.6 SSH Key Tables

```sql
CREATE TABLE ssh_keys (
  ssh_key_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id     UUID NOT NULL REFERENCES namespaces(namespace_id),
  name             TEXT NOT NULL,
  key_type         TEXT NOT NULL DEFAULT 'ED25519',
  public_key       TEXT NOT NULL,
  fingerprint      TEXT NOT NULL UNIQUE,
  target_hosts     TEXT[],
  signed_cert      TEXT,                   -- CA-signed certificate
  cert_expires_at  TIMESTAMPTZ,
  state            TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by       UUID NOT NULL REFERENCES identities(identity_id),
  expires_at       TIMESTAMPTZ
);
```

### 12.7 Schema Conventions

- **Primary Keys:** UUID v4 (`gen_random_uuid()`) for all entities.
- **Timestamps:** All timestamps stored as `TIMESTAMPTZ` in UTC.
- **Soft Deletes:** No `DELETE` statements on core entities; use `state` or `is_active` fields.
- **Row-Level Security (RLS):** All tables with `namespace_id` enforce RLS policies binding `current_setting('app.current_namespace_id')` to prevent cross-namespace data access.
- **Migrations:** Managed by Flyway; versioned scripts in `db/migration/V{n}__{description}.sql`.
- **Sensitive Columns:** `encrypted_key_dek`, `encrypted_value`, `pem_certificate` contain only cipher material — never plaintext. Enforced by application-layer validation and DB CHECK constraints.

---

## 13. API Contract Reference

### 13.1 Global Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <access_token>` or omitted for mTLS |
| `X-Namespace-ID` | Yes (human users) | Target namespace UUID; service accounts derive namespace from ABAC policy |
| `X-Request-ID` | Recommended | Client-generated UUID for distributed tracing (echoed in response) |
| `Idempotency-Key` | Required for POST | UUID to ensure at-most-once semantics for mutating operations |
| `Content-Type` | Yes | `application/json` |
| `Accept` | No | `application/json` (default) |

### 13.2 Global Response Headers

| Header | Description |
|--------|-------------|
| `X-Request-ID` | Echoed from request; generated by gateway if absent |
| `X-RateLimit-Limit` | Total requests allowed per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when the window resets |
| `X-Key-Version` | Present on crypto operation responses; indicates key version used |

### 13.3 Key Object Schema

```json
{
  "keyId": "uuid",
  "name": "string (3–128 chars)",
  "namespaceId": "uuid",
  "algorithm": "AES-256-GCM | RSA-4096 | ECDSA-P384 | Ed25519 | HMAC-SHA256 | ...",
  "keySizeBits": 256,
  "purpose": ["ENCRYPT", "DECRYPT"],
  "state": "PENDING | ACTIVE | SUSPENDED | DEPRECATED | SCHEDULED_DESTROY | DESTROYED",
  "currentVersion": 1,
  "riskScore": 12.5,
  "hsmBacked": true,
  "expiresAt": "ISO-8601 | null",
  "createdAt": "ISO-8601",
  "createdBy": "uuid",
  "tags": { "env": "production", "team": "platform" },
  "rotationPolicyId": "uuid | null"
}
```

### 13.4 Crypto Operation Request/Response

**Encrypt Request:**
```json
{
  "plaintext": "<base64-encoded bytes>",
  "aad": "<base64-encoded additional authenticated data, optional>",
  "keyVersion": null
}
```

**Encrypt Response:**
```json
{
  "ciphertext": "<base64-encoded bytes>",
  "iv": "<base64-encoded nonce>",
  "tag": "<base64-encoded GCM auth tag>",
  "keyId": "uuid",
  "keyVersion": 3,
  "algorithm": "AES-256-GCM"
}
```

**Decrypt Request:**
```json
{
  "ciphertext": "<base64-encoded bytes>",
  "iv": "<base64-encoded nonce>",
  "tag": "<base64-encoded GCM auth tag>",
  "aad": "<optional>",
  "keyVersion": 3
}
```

**Sign Request:**
```json
{ "message": "<base64-encoded bytes>", "signingAlgorithm": "SHA256withECDSA" }
```

**Sign Response:**
```json
{ "signature": "<base64-encoded>", "keyId": "uuid", "keyVersion": 2, "signingAlgorithm": "SHA256withECDSA" }
```

### 13.5 Pagination

All list endpoints (`GET /api/v1/keys`, `GET /api/v1/secrets`, etc.) support:

| Query Param | Default | Description |
|-------------|---------|-------------|
| `page` | 0 | Zero-based page number |
| `size` | 20 | Page size (max 100) |
| `sort` | `createdAt,desc` | Field and direction |
| `filter` | — | Field-specific filters (e.g., `state=ACTIVE`, `algorithm=AES-256-GCM`) |

**Paginated Response Envelope:**
```json
{
  "data": [ ...items... ],
  "pagination": {
    "page": 0,
    "size": 20,
    "totalElements": 847,
    "totalPages": 43
  }
}
```

---

## 14. Environment & Configuration Reference

### 14.1 Key Management Service (`kms-service`)

| Property | Env Variable | Default | Description |
|----------|-------------|---------|-------------|
| `server.port` | `KMS_PORT` | `8080` | HTTP server port |
| `spring.datasource.url` | `KMS_DB_URL` | — | PostgreSQL JDBC URL |
| `spring.datasource.username` | `KMS_DB_USER` | — | DB username (from Vault) |
| `spring.datasource.password` | `KMS_DB_PASSWORD` | — | DB password (from Vault) |
| `spring.redis.host` | `REDIS_HOST` | `redis` | Redis hostname |
| `spring.redis.port` | `REDIS_PORT` | `6379` | Redis port |
| `spring.kafka.bootstrap-servers` | `KAFKA_BROKERS` | — | Kafka broker list |
| `aikms.hsm.provider` | `HSM_PROVIDER` | `SOFTHSM` | `THALES | ENTRUST | AWS_CLOUDHSM | SOFTHSM` |
| `aikms.hsm.pkcs11-config-path` | `HSM_CONFIG_PATH` | — | Path to PKCS#11 config file |
| `aikms.hsm.slot-pin` | `HSM_SLOT_PIN` | — | HSM slot PIN (from Vault) |
| `aikms.envelope.kek-namespace` | `KEK_NAMESPACE` | — | Cloud KMS key resource for master KEK |
| `aikms.key.min-size.aes` | `MIN_AES_KEY_SIZE` | `128` | Minimum AES key size bits |
| `aikms.key.min-size.rsa` | `MIN_RSA_KEY_SIZE` | `2048` | Minimum RSA key size bits |
| `aikms.key.cooling-off-days` | `KEY_COOLING_OFF_DAYS` | `7` | Cooling-off period before destruction |
| `aikms.rate-limit.default-rps` | `DEFAULT_RATE_LIMIT_RPS` | `100` | Default requests/sec per client |
| `management.endpoints.web.exposure.include` | — | `health,info,prometheus` | Actuator endpoints |

### 14.2 AI/ML Engine Service (`aiml-service`)

| Property | Env Variable | Default | Description |
|----------|-------------|---------|-------------|
| `KAFKA_BROKERS` | — | — | Kafka bootstrap servers |
| `KAFKA_TOPIC_USAGE_EVENTS` | — | `key-usage-events` | Input topic |
| `KAFKA_TOPIC_ANOMALY_EVENTS` | — | `anomaly-events` | Output topic |
| `REDIS_URL` | — | — | Redis connection URL for baseline store |
| `MLFLOW_TRACKING_URI` | — | — | MLflow server URL |
| `MODEL_REGISTRY_PATH` | — | `/models` | Local path to ONNX model artifacts |
| `ANOMALY_SCORE_THRESHOLD` | — | `70` | Score above which events are escalated |
| `BASELINE_WINDOW_DAYS` | — | `30` | Rolling window for behavioral baseline |
| `RETRAIN_SCHEDULE_CRON` | — | `0 2 * * 0` | Weekly retraining schedule (UTC) |
| `FEATURE_GEO_RISK_FEED_URL` | — | — | URL for geo-risk lookup service |

### 14.3 Auth & Identity Service (`auth-service`)

| Property | Env Variable | Default | Description |
|----------|-------------|---------|-------------|
| `OIDC_ISSUER_URI` | — | — | OIDC provider issuer URL (e.g., Okta, Azure AD) |
| `OAUTH2_CLIENT_ID` | — | — | Client ID for OIDC federation |
| `OAUTH2_CLIENT_SECRET` | — | — | Client secret (from Vault) |
| `JWT_PRIVATE_KEY_PATH` | — | — | Path to JWT signing private key |
| `JWT_ACCESS_TOKEN_TTL_SECONDS` | — | `900` | Access token TTL (15 min) |
| `JWT_REFRESH_TOKEN_TTL_SECONDS` | — | `28800` | Refresh token TTL (8 hr) |
| `SESSION_INACTIVITY_TIMEOUT_SECONDS` | — | `1800` | Session idle timeout (30 min) |
| `MFA_REQUIRED_ROLES` | — | `SUPER_ADMIN,SECURITY_ADMIN` | Roles requiring MFA |
| `SCIM_ENABLED` | — | `true` | Enable SCIM 2.0 provisioning endpoint |

### 14.4 Common Environment Variables (all services)

| Env Variable | Description |
|-------------|-------------|
| `SERVICE_NAME` | Logical service name (used in traces and logs) |
| `ENVIRONMENT` | `development | staging | production` |
| `LOG_LEVEL` | `DEBUG | INFO | WARN | ERROR` (default: `INFO`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint |
| `OTEL_SERVICE_NAME` | Service name for traces (same as `SERVICE_NAME`) |
| `VAULT_ADDR` | HashiCorp Vault address |
| `VAULT_ROLE_ID` | Vault AppRole role ID |
| `VAULT_SECRET_ID` | Vault AppRole secret ID (injected by CSI driver) |
| `TLS_CERT_PATH` | Path to service TLS certificate |
| `TLS_KEY_PATH` | Path to service TLS private key |
| `TLS_CA_PATH` | Path to CA certificate bundle for mTLS |

---

## 15. Error Handling & Resilience

### 15.1 Retry Policies (Resilience4j)

| Operation | Max Attempts | Initial Backoff | Max Backoff | Retryable Conditions |
|-----------|-------------|-----------------|-------------|----------------------|
| HSM key generation | 3 | 500 ms | 5 s | `HSM_TIMEOUT`, `HSM_BUSY` |
| PostgreSQL write | 3 | 100 ms | 2 s | `CONNECTION_TIMEOUT`, transient deadlock |
| Redis read | 2 | 50 ms | 500 ms | `CONNECTION_REFUSED`, timeout |
| Kafka publish (audit event) | 5 | 200 ms | 10 s | Any exception |
| External threat intel feed | 2 | 1 s | 10 s | HTTP 5xx, timeout |
| OCSP check | 2 | 500 ms | 5 s | `OCSP_UNAVAILABLE` |

**Non-retryable conditions:** `POLICY_DENIED`, `KEY_PURPOSE_MISMATCH`, `KEY_STATE_CONFLICT`, `INVALID_ALGORITHM` — these are programming or policy errors; retrying will not resolve them.

### 15.2 Circuit Breakers (Resilience4j `CircuitBreaker`)

| Resource | Failure Rate Threshold | Slow Call Threshold | Wait Duration (Open) | Half-Open Max Calls |
|----------|----------------------|---------------------|----------------------|---------------------|
| HSM | 50% | > 2 s | 30 s | 3 |
| PostgreSQL | 60% | > 1 s | 15 s | 5 |
| AI/ML Engine | 70% | > 600 ms | 20 s | 3 |
| External threat intel | 80% | > 5 s | 60 s | 2 |

**Degraded mode behaviour when circuit is open:**
- **HSM open:** KMS rejects all encrypt/decrypt operations. Returns HTTP 503 `HSM_UNAVAILABLE`. Read-only metadata operations continue.
- **AI/ML Engine open:** Anomaly scoring disabled; all events pass through without scoring. Alert is raised for ops team. Risk scores frozen at last computed value.
- **Threat intel open:** Geo-risk scores frozen at last known values; feed refresh skipped.

### 15.3 Idempotency

- All `POST` endpoints (key creation, encrypt, rotate) require an `Idempotency-Key` header (UUID).
- The server stores idempotency records in Redis for 24 hours.
- A repeated request with the same `Idempotency-Key` returns the original response without re-executing the operation.
- `409 Conflict` is returned if the same `Idempotency-Key` is submitted with a different request body.

### 15.4 Graceful Shutdown

- On SIGTERM, each Spring Boot service stops accepting new requests immediately (Kubernetes `preStop` hook sends SIGTERM).
- In-flight requests are allowed to complete with a configurable drain timeout (default: 30 s).
- Kafka consumers commit offsets for processed messages before shutdown; uncommitted messages are reprocessed by another instance.
- HSM sessions are closed cleanly to release HSM slot resources.

### 15.5 Fallback Behaviour Summary

| Scenario | Impact | Fallback |
|----------|--------|----------|
| HSM unreachable | Cannot encrypt/decrypt/sign | Return 503; queue operations if <5 min outage expected |
| PostgreSQL primary fails | Metadata writes blocked | Automatic failover to replica (Patroni); ~30 s recovery |
| Redis unavailable | Cache miss on all requests | Fall through to PostgreSQL; latency increases |
| Kafka unavailable | Audit events not delivered | Buffer in local in-memory queue (max 10,000 events); flush on reconnect |
| AI Engine down | No anomaly scoring | Pass-through mode; all events logged without score; alert ops team |

---

## 16. Multi-Tenancy & Namespace Isolation

### 16.1 Isolation Model

AIKMS uses **namespace-based logical multi-tenancy** within a single deployment. Physical infrastructure (database, Kafka, Redis) is shared, but data access is strictly isolated using:

1. **Application-layer enforcement:** All service queries include `namespace_id = ?` filters. Service accounts receive a namespace claim in their JWT.
2. **PostgreSQL Row-Level Security (RLS):** All namespace-scoped tables enforce RLS policies that verify `current_setting('app.current_namespace_id')` matches the row's `namespace_id`.
3. **ABAC policies:** Deny-by-default; explicit allow required for cross-namespace operations (only Super Admin role can be granted cross-namespace access).

### 16.2 PostgreSQL RLS Configuration

```sql
-- Enable RLS on all namespace-scoped tables
ALTER TABLE keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Policy: app role can only see rows in its current namespace
CREATE POLICY namespace_isolation ON keys
  USING (namespace_id::TEXT = current_setting('app.current_namespace_id', true));

-- Spring sets the namespace before each query:
-- SET LOCAL app.current_namespace_id = '<uuid>';
-- (wrapped in the same DB transaction)
```

### 16.3 Cross-Namespace Rules

| Operation | Permitted Cross-Namespace | Who Can Authorize |
|-----------|--------------------------|-------------------|
| Read key metadata from another namespace | No | N/A |
| Rotate a key in another namespace | No | N/A |
| View audit logs across all namespaces | Yes (read-only) | Super Admin |
| Apply a global policy to all namespaces | Yes | Super Admin |
| Generate system-wide compliance report | Yes (read-only) | Auditor (Super Admin grants) |

### 16.4 Namespace Hierarchy & Policy Inheritance

```
root (global policies)
  └── org-platform/
        ├── platform-prod/    ← inherits org-platform policies
        └── platform-staging/ ← inherits org-platform policies, overrides rotation interval
  └── org-payments/
        └── payments-prod/    ← inherits org-payments policies
```

- A namespace inherits the `rotation_policies`, `approved_algorithms`, and `export_restrictions` from its parent unless overridden.
- Policy conflict resolution: most-specific namespace policy wins; global policy is the fallback.
- A namespace cannot grant permissions that its parent does not have.

### 16.5 Namespace Lifecycle

| Event | Actions Required | Cascade Effects |
|-------|-----------------|-----------------|
| Create namespace | Assign parent, create namespace KEK, assign default policy | None |
| Deactivate namespace | All active keys must be suspended or destroyed first | Block new key creation |
| Delete namespace | All keys must be `DESTROYED`; no active secrets | Soft-delete namespace record; audit log retained |

---

## 17. Testing Strategy

### 17.1 Test Pyramid

| Layer | Tool | Coverage Target | Scope |
|-------|------|----------------|-------|
| Unit tests | JUnit 5 + Mockito | ≥ 80% line coverage | Business logic, state machine transitions, crypto utility methods |
| Integration tests | Spring Boot Test + Testcontainers | All repository and service layer paths | PostgreSQL, Redis, Kafka, Vault (local) |
| Contract tests | Spring Cloud Contract (provider) / Pact (consumer) | All gRPC + REST inter-service contracts | Between KMS ↔ AI Engine, KMS ↔ Audit, KMS ↔ Policy Engine |
| API tests | REST-assured + Postman/Newman | All API endpoints (happy path + error paths) | Full Spring context with Testcontainers |
| Security tests | OWASP ZAP (DAST) + Trivy (SCA) | All public API endpoints | Run in CI/CD staging environment |
| Load tests | k6 | p99 latency targets per NFR | Key retrieval, encrypt/decrypt, list endpoints |
| Chaos tests | Chaos Monkey for Spring Boot | HA and resilience requirements | PostgreSQL failover, Redis outage, HSM disconnection |

### 17.2 Test Environment Strategy

| Environment | Purpose | Infrastructure | Data |
|-------------|---------|---------------|------|
| `local` | Developer inner loop | Docker Compose (PostgreSQL, Redis, Kafka, SoftHSM) | Seeded fixture data |
| `ci` | Automated test runs on every PR | Testcontainers (ephemeral, per-test-run) | Ephemeral, auto-generated |
| `staging` | Integration + security testing | Kubernetes (dedicated cluster, SoftHSM) | Anonymized production-like data |
| `production` | Live system | Kubernetes (FIPS HSM) | Real data |

### 17.3 Key Test Scenarios

#### Cryptographic Operations
- [ ] AES-256-GCM encrypt → decrypt round-trip produces identical plaintext.
- [ ] ECDSA sign → verify with correct key passes; verify with wrong key fails.
- [ ] Encryption with a `SUSPENDED` key returns HTTP 409.
- [ ] Decryption with the correct `key_version` succeeds after the key is rotated.
- [ ] Key creation with RSA-1024 is rejected with `INVALID_KEY_SIZE`.

#### Key State Machine
- [ ] All valid transitions succeed; all invalid transitions return HTTP 409.
- [ ] Dual-control destruction requires exactly 2 distinct approvers.
- [ ] Single approver attempting both votes returns HTTP 403.
- [ ] Key is not physically destroyed during cooling-off period.
- [ ] Cancellation during cooling-off correctly returns key to `SUSPENDED`.

#### Access Control
- [ ] A Key Operator cannot call `DELETE /api/v1/keys/{id}`.
- [ ] A Developer service account in namespace A cannot read keys from namespace B.
- [ ] Expired JWT returns HTTP 401.
- [ ] mTLS with invalid client certificate returns HTTP 401.
- [ ] Rate limit exceeded returns HTTP 429 with `Retry-After` header.

#### AI Anomaly Detection
- [ ] Injecting 10× normal operation volume triggers a volumetric anomaly event.
- [ ] A request from a new IP after 30 days sets `is_new_ip = true`.
- [ ] Anomaly event is published to Kafka within 500 ms of the triggering key-usage event.
- [ ] AI model promotion fails if soak period < 48 hours.

#### Resilience
- [ ] KMS service remains available when HSM circuit breaker is OPEN (read-only operations).
- [ ] Audit events buffered during Kafka outage are flushed on reconnection without duplicates.
- [ ] PostgreSQL failover completes within 30 s and service resumes without restart.

### 17.4 Load Test Targets (k6)

```javascript
// Target: p99 key retrieval ≤ 100 ms at 10,000 concurrent users
export const options = {
  stages: [
    { duration: '2m', target: 1000 },
    { duration: '5m', target: 10000 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    'http_req_duration{endpoint:retrieve}': ['p(99)<100'],
    'http_req_duration{endpoint:encrypt}':  ['p(99)<150'],
    'http_req_failed': ['rate<0.001'],
  },
};
```

### 17.5 CI/CD Test Gates

| Gate | Blocking | Pipeline Stage |
|------|----------|---------------|
| Unit tests pass (all) | Yes | PR build |
| Code coverage ≥ 80% | Yes | PR build |
| Integration tests pass | Yes | PR build |
| Contract tests pass | Yes | PR build |
| Trivy: no Critical CVEs | Yes | Image build |
| OWASP ZAP: no High findings | Yes | Staging deploy |
| Load test p99 ≤ thresholds | Yes | Pre-production deploy |
| Chaos tests pass | No (advisory) | Staging weekly |

---

## 18. Operational Runbooks

### 18.1 Onboarding a New HSM

**Prerequisites:** HSM is physically installed, network-connected, and initialized by the vendor.

1. Install the vendor PKCS#11 library on all KMS service nodes (or include in container image layer).
2. Configure the PKCS#11 slot in the KMS service config:
   ```yaml
   aikms.hsm.provider: THALES
   aikms.hsm.pkcs11-config-path: /etc/pkcs11/thales.cfg
   ```
3. Set `HSM_SLOT_PIN` in Vault at `secret/kms/hsm-slot-pin`.
4. Run the HSM connectivity health check endpoint: `GET /actuator/health/hsm`.
5. Generate a new namespace KEK via HSM: `POST /api/v1/admin/kek/generate?backend=hsm`.
6. Update `aikms.envelope.kek-namespace` to point to the new HSM-backed KEK.
7. Validate by creating a test key, encrypting, and decrypting a test payload.
8. Record the HSM serial number, slot ID, and KEK reference in the system inventory.

### 18.2 Promoting an AI Model to Production

**Prerequisites:** Model has been trained and registered in MLflow. 48-hour shadow evaluation is complete.

1. Verify shadow evaluation metrics in the AI Insights dashboard: precision ≥ 0.90, recall ≥ 0.85, F1 ≥ 0.87.
2. Review false positive rate from shadow eval: must be < 5%.
3. Security Admin approves promotion via: `POST /api/v1/admin/ai-models/{modelId}/promote`.
4. The system performs a canary rollout: 10% of events scored by new model, 90% by current model.
5. Monitor anomaly event rate for 1 hour. If deviation > 20% from baseline, trigger rollback.
6. If canary is stable, promote to 100%: `POST /api/v1/admin/ai-models/{modelId}/promote?stage=full`.
7. The old model remains in the registry for rollback; it is not deleted.
8. Write a promotion record to the audit log including model IDs, approver, and metrics.

**Rollback:** `POST /api/v1/admin/ai-models/{previousModelId}/promote` — instantly swaps production model back.

### 18.3 Shamir Secret Recovery (Master Key Escrow)

**Use case:** Master KEK must be reconstructed after catastrophic HSM failure.

**Prerequisites:** M-of-N custodians are present; each holds their share on a hardware token.

1. Convene custodians in a secure room; log attendance in the physical security register.
2. Each custodian inserts their hardware token and authenticates.
3. Execute the recovery ceremony tool:
   ```bash
   java -jar aikms-recovery.jar --shares M --total N --output /secure/master.key
   ```
4. Each custodian enters their share PIN when prompted (in separate prompts; no custodian sees another's share).
5. The tool reconstructs the master key in memory and re-wraps all namespace KEKs with the new master.
6. The reconstructed master key is immediately loaded into the replacement HSM.
7. Destroy the temporary `/secure/master.key` file: `shred -u /secure/master.key`.
8. Verify service operation by running HSM health check and a test encrypt/decrypt cycle.
9. Record the ceremony in the audit log with attendees, date, and outcome.

### 18.4 Responding to a High-Risk Anomaly Alert

1. **Acknowledge** the alert in the dashboard within the SLA (default: 15 min for Critical).
2. **Investigate:** Review the anomaly event detail — anomaly types, affected key, caller identity, source IP.
3. **Immediate containment:** If the session risk score > 90, suspend the caller's API credentials: `PATCH /api/v1/identities/{id}` with `{ "state": "SUSPENDED" }`.
4. **Assess key exposure:** Check if the affected key was used for any encrypt/decrypt operations after the anomaly timestamp. Review audit log.
5. **Rotate key** if exposure is confirmed or risk is unresolved: `POST /api/v1/keys/{keyId}/rotate`.
6. **Notify stakeholders** via the incident management system.
7. **Close the anomaly** with feedback: `PATCH /api/v1/anomalies/{anomalyId}` with `{ "status": "RESOLVED", "feedback": "CORRECT" }`.
8. If the alert was a false positive: `{ "status": "FALSE_POSITIVE", "feedback": "INCORRECT" }` — this feeds back into model retraining.

### 18.5 Certificate Expiry Emergency Renewal

**Trigger:** A monitored certificate < 24 hours from expiry without automated renewal completing.

1. Check the certificate manager logs: `kubectl logs -l app=certificate-manager -n aikms | grep <certificate_id>`.
2. If ACME renewal failed, identify the cause (DNS challenge failure, rate limit, CA outage).
3. **Manual renewal option A — ACME retry:** `POST /api/v1/certificates/{id}/renew?force=true`.
4. **Manual renewal option B — Upload:** Generate CSR manually, obtain certificate from CA, upload: `PUT /api/v1/certificates/{id}` with PEM body.
5. After upload, verify new `not_after` in the certificate inventory.
6. Trigger push distribution to registered endpoints: `POST /api/v1/certificates/{id}/distribute`.
7. Verify endpoint health after distribution.

### 18.6 Kafka Consumer Lag Recovery

**Trigger:** Alert fires for `audit-events` consumer lag > 10,000 events.

1. Check Audit Service pod count and health: `kubectl get pods -l app=audit-service -n aikms`.
2. If pods are crashing, inspect logs: `kubectl logs <pod-name> -n aikms --previous`.
3. If lag is due to a processing bottleneck (not crashes), scale up: `kubectl scale deployment audit-service --replicas=6 -n aikms`.
4. Monitor lag metric in Grafana (`aikms_kafka_consumer_lag` by consumer group).
5. Once lag returns below 1,000, scale back to normal replica count.
6. If lag is caused by a bad message (poison pill), identify the offset: use `kafka-consumer-groups.sh` to inspect committed offsets, then skip the offending message by advancing the offset.
7. Investigate root cause and add a DLQ (Dead Letter Queue) handler in `audit-service` if not already present.

---

## 19. HSM Simulator

### 19.1 Overview

The AIKMS HSM Simulator is a purpose-built software component that faithfully emulates a FIPS 140-2/3 Hardware Security Module over the PKCS#11 v2.40 API. It is used exclusively in **development, CI/CD, and integration testing** environments where a physical HSM is unavailable or impractical. It is **not** intended for production use.

The simulator allows any AIKMS service that uses the `SunPKCS11` / `JCA` provider to connect without code changes — only the PKCS#11 library path and slot PIN configuration differ between the simulator and a real HSM.

**Goals:**
- Zero-physical-hardware dependency for developer inner loop and CI pipelines.
- Deterministic, inspectable behavior for test assertions.
- Configurable fault injection to validate AIKMS resilience paths (circuit breakers, retries, fallback modes).
- Drop-in replacement: same PKCS#11 interface as Thales Luna, Entrust nShield, and AWS CloudHSM.

---

### 19.2 Scope of Simulation

| PKCS#11 Capability | Simulated | Notes |
|--------------------|-----------|-------|
| Slot and token management (`C_GetSlotList`, `C_GetTokenInfo`) | Yes | Single configurable slot |
| Session management (`C_OpenSession`, `C_CloseSession`, `C_Login`, `C_Logout`) | Yes | Supports both `USER` and `SO` roles |
| Key generation (`C_GenerateKey`, `C_GenerateKeyPair`) | Yes | AES, RSA, EC (P-256/P-384/P-521), Ed25519 |
| Key import/export (`C_CreateObject`, `C_GetAttributeValue`) | Yes (import only) | Export blocked by default (simulates EXTRACTABLE=false) |
| Symmetric encrypt/decrypt (`C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt`) | Yes | AES-CBC, AES-GCM |
| Asymmetric sign/verify (`C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify`) | Yes | RSA-PKCS1, RSA-PSS, ECDSA, EdDSA |
| Key wrapping/unwrapping (`C_WrapKey`, `C_UnwrapKey`) | Yes | RSA-OAEP, AES-KWP |
| Digest (`C_DigestInit`, `C_Digest`) | Yes | SHA-256, SHA-384, SHA-512 |
| Random number generation (`C_GenerateRandom`) | Yes | Backed by `SecureRandom` (Java) |
| Dual-control PIN enforcement | Yes (configurable) | Simulate M-of-N quorum requirement |
| Physical tamper detection | No | Out of scope for software simulation |
| FIPS 140-3 certified entropy source | No | `SecureRandom` is FIPS-compatible in IBM/Oracle FIPS JVM mode |

---

### 19.3 Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                         AIKMS KMS Service (JVM)                       │
│                                                                       │
│   SunPKCS11 Provider ──────────────────────> PKCS#11 Native Bridge    │
│                                              (JNI / C shared lib)     │
└────────────────────────────────────┬──────────────────────────────────┘
                                     │  PKCS#11 v2.40 C API
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       HSM Simulator (Java)                             │
│                                                                        │
│  ┌────────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  PKCS#11 JNI Shim  │  │  Session Manager  │  │  Slot / Token    │  │
│  │  (C stub → Java)   │  │  (login, sessions)│  │  Registry        │  │
│  └────────┬───────────┘  └────────┬─────────┘  └────────┬─────────┘  │
│           │                       │                       │            │
│           └───────────────────────▼───────────────────────┘            │
│                          ┌────────────────────┐                        │
│                          │  Crypto Engine     │                        │
│                          │ (BouncyCastle/JCE) │                        │
│                          └────────┬───────────┘                        │
│                                   │                                    │
│  ┌────────────────────────────────▼──────────────────────────────────┐ │
│  │                    Key Object Store                                │ │
│  │  (in-memory Map<CKO_handle, KeyObject> + optional file persistence)│ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                 Fault Injection Engine                             │ │
│  │  (configurable error injection: CKR_DEVICE_ERROR, delays, etc.)   │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                  Audit / Inspection API (HTTP)                     │ │
│  │  GET /sim/slots, GET /sim/objects, POST /sim/fault, DELETE /sim/reset│ │
│  └───────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

**Components:**

| Component | Responsibility |
|-----------|---------------|
| **PKCS#11 JNI Shim** | Thin C shared library (`hsm-sim.so` / `hsm-sim.dll`) that forwards all PKCS#11 C function calls to a Java gRPC or JNI interface |
| **Session Manager** | Tracks open sessions, authenticated users, `SO` vs `USER` PIN enforcement, concurrent session limits |
| **Slot / Token Registry** | Configurable slots with label, flags, and PIN. Supports `C_InitToken` and `C_InitPIN` to reset state |
| **Crypto Engine** | Delegates all cryptographic operations to BouncyCastle 1.78 (FIPS build for FIPS mode) |
| **Key Object Store** | Thread-safe in-memory store of all `CKO_*` objects, keyed by CK_OBJECT_HANDLE. Optional JSON/PKCS#12 persistence to disk for long-lived dev tokens |
| **Fault Injection Engine** | Injects configurable errors (see §19.5) via a REST API or YAML configuration |
| **Audit / Inspection HTTP API** | Out-of-band REST API on a separate port (default 9095) for test assertions and simulator state management |

---

### 19.4 Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Language | Java 21 (same JVM as KMS) | Consistent runtime; direct JNI bridging possible |
| Build | Gradle 8 multi-module (`:hsm-simulator`) | Shares build infrastructure with the rest of AIKMS |
| Crypto library | BouncyCastle 1.78 (`bcprov-jdk18on`) | Full PKCS#11 algorithm coverage; FIPS build available |
| JNI bridge | Custom C shim or `sun.security.pkcs11.wrapper` fork | Maps C PKCS#11 structs to Java method calls |
| Native compilation | GraalVM Native Image (optional, for CI performance) | Eliminates JVM warmup in ephemeral containers |
| HTTP inspection API | Spring Boot 3.3 (minimal, embedded Netty) | Consistent with service stack |
| Containerization | Docker image: `aikms/hsm-simulator:<version>` | Ships as a single image; no external dependencies |
| Test integration | Testcontainers `GenericContainer` | Programmatic lifecycle management in integration tests |

---

### 19.5 Fault Injection

The fault injection engine allows tests to simulate HSM failure modes that would be impossible or dangerous to trigger with real hardware.

#### Configurable Fault Types

| Fault ID | PKCS#11 Error Emitted | Description |
|----------|-----------------------|-------------|
| `HSM_BUSY` | `CKR_DEVICE_BUSY` | Simulate HSM slot saturation; configurable delay before returning error |
| `HSM_TIMEOUT` | `CKR_DEVICE_ERROR` | Simulate a slow HSM response exceeding the PKCS#11 operation timeout |
| `HSM_DISCONNECTED` | `CKR_TOKEN_NOT_PRESENT` | Simulate complete loss of HSM connectivity |
| `PIN_LOCKED` | `CKR_PIN_LOCKED` | Simulate PIN locked after too many failed authentication attempts |
| `KEY_NOT_FOUND` | `CKR_OBJECT_HANDLE_INVALID` | Simulate a key that was deleted from HSM outside of AIKMS |
| `RANDOM_FAILURE` | `CKR_RANDOM_NO_RNG` | Simulate RNG subsystem failure during key generation |
| `PARTIAL_FAILURE` | Alternating `CKR_OK` / `CKR_DEVICE_ERROR` | Simulate flapping HSM — succeeds N% of the time (configurable) |
| `SLOW_RESPONSE` | `CKR_OK` (with latency) | Inject artificial latency (ms) without failing — triggers slow-call circuit breaker |

#### Fault Injection REST API

```
POST /sim/fault
{
  "faultId": "HSM_BUSY",
  "operations": ["C_Encrypt", "C_GenerateKey"],  // null = all operations
  "triggerAfterCount": 5,       // inject after N successful calls
  "durationCalls": 10,          // persist for N subsequent calls (0 = permanent until reset)
  "latencyMs": 0                // artificial latency for SLOW_RESPONSE
}

DELETE /sim/fault                // clear all active faults
GET    /sim/fault                // list active faults
```

---

### 19.6 Inspection & Test Assertion API

```
GET  /sim/slots                  // list all configured slots and token info
GET  /sim/sessions               // list all open sessions with state
GET  /sim/objects                // list all key objects (handle, class, label, algorithm, size)
GET  /sim/objects/{handle}       // full attribute dump for a specific object
GET  /sim/calls                  // call log — structured log of every PKCS#11 function call
DELETE /sim/reset                // clear all sessions, objects, and faults (complete reset)
POST /sim/slots/{slotId}/init    // re-initialize a slot (re-runs C_InitToken)
```

**Example: Assert a key was generated in the HSM from a JUnit test**

```java
@Test
void keyCreationUsesHsm() {
    // trigger key creation via AIKMS API
    var response = kmsClient.createKey(CreateKeyRequest.builder()
        .name("test-key").algorithm("AES").keySizeBits(256).hsmBacked(true).build());

    // assert the key exists in the simulator
    var simObjects = simClient.getObjects();  // GET /sim/objects
    assertThat(simObjects)
        .anyMatch(obj -> obj.label().equals("test-key") && obj.ckClass().equals("CKO_SECRET_KEY"));
}
```

---

### 19.7 Configuration

The simulator is configured via YAML or environment variables. It is co-located with the KMS service in `docker-compose.dev.yml` and `docker-compose.test.yml`.

```yaml
# hsm-simulator/src/main/resources/application.yml
hsm-sim:
  slots:
    - slot-id: 0
      label: "AIKMS-DEV-TOKEN"
      so-pin: "administrator"        # Security Officer PIN
      user-pin: "changeit"           # User PIN
      max-sessions: 64
      persistence:
        enabled: false               # set true to persist objects to disk across restarts
        path: "/var/hsm-sim/token0"
  server:
    port: 9094                       # PKCS#11 bridge port (internal)
    inspection-port: 9095            # HTTP inspection API port
  crypto:
    fips-mode: false                 # set true to use BouncyCastle FIPS build
  fault-injection:
    enabled: true                    # must be false in staging, never used in production
  audit:
    log-all-calls: true              # write every PKCS#11 call to structured log
```

**PKCS#11 configuration file for SunPKCS11 (referenced by KMS service):**

```
# /etc/pkcs11/hsm-sim.cfg
name = AIKMS-HSM-Simulator
library = /usr/local/lib/hsm-sim.so
slot = 0
```

**KMS service environment to use the simulator:**

```yaml
aikms.hsm.provider: SOFTHSM       # or a new provider enum: SIMULATOR
aikms.hsm.pkcs11-config-path: /etc/pkcs11/hsm-sim.cfg
HSM_SLOT_PIN: changeit
```

---

### 19.8 Docker & Testcontainers Integration

**`docker-compose.dev.yml` entry:**

```yaml
services:
  hsm-simulator:
    image: aikms/hsm-simulator:latest
    ports:
      - "9094:9094"    # PKCS#11 bridge
      - "9095:9095"    # Inspection API
    environment:
      HSM_SIM_USER_PIN: "changeit"
      HSM_SIM_SO_PIN: "administrator"
      HSM_SIM_FAULT_INJECTION_ENABLED: "true"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9095/sim/slots"]
      interval: 5s
      timeout: 3s
      retries: 5
    volumes:
      - hsm-sim-data:/var/hsm-sim    # optional persistence
```

**Testcontainers usage in integration tests:**

```java
@Container
static GenericContainer<?> hsmSimulator = new GenericContainer<>("aikms/hsm-simulator:latest")
    .withExposedPorts(9094, 9095)
    .withEnv("HSM_SIM_USER_PIN", "changeit")
    .withEnv("HSM_SIM_FAULT_INJECTION_ENABLED", "true")
    .waitingFor(Wait.forHttp("/sim/slots").forPort(9095));

static HsmSimClient simClient;

@BeforeAll
static void setup() {
    simClient = new HsmSimClient("http://localhost:" + hsmSimulator.getMappedPort(9095));
    // Point SunPKCS11 to the simulator via dynamic config
    configurePkcs11Provider(hsmSimulator.getMappedPort(9094));
}

@AfterEach
void resetSimulator() {
    simClient.reset();  // DELETE /sim/reset — clean state between tests
}
```

---

### 19.9 Gradle Module Structure

```
aikms/
└── hsm-simulator/
    ├── build.gradle
    ├── src/
    │   ├── main/
    │   │   ├── c/
    │   │   │   └── pkcs11_shim.c          # JNI C shim implementing PKCS#11 C API
    │   │   └── java/com/aikms/hsmsim/
    │   │       ├── HsmSimulatorApplication.java
    │   │       ├── slot/
    │   │       │   ├── SlotRegistry.java
    │   │       │   └── TokenInfo.java
    │   │       ├── session/
    │   │       │   ├── SessionManager.java
    │   │       │   └── SessionState.java
    │   │       ├── crypto/
    │   │       │   ├── CryptoEngine.java          # BouncyCastle delegate
    │   │       │   ├── KeyObjectStore.java
    │   │       │   └── Pkcs11Operations.java      # maps PKCS#11 ops to CryptoEngine
    │   │       ├── fault/
    │   │       │   ├── FaultInjectionEngine.java
    │   │       │   └── FaultRule.java
    │   │       └── api/
    │   │           └── InspectionController.java   # Spring MVC REST controller
    │   └── test/
    │       └── java/com/aikms/hsmsim/
    │           ├── Pkcs11OperationsTest.java       # unit tests per operation
    │           ├── FaultInjectionTest.java
    │           └── Pkcs11RoundTripIT.java          # integration test via SunPKCS11
    └── docker/
        └── Dockerfile
```

---

### 19.10 Security Constraints

- The simulator **must never** be deployed in production or staging environments. The Docker image tag must include `-dev` suffix; CI/CD pipelines must reject any attempt to deploy the `hsm-simulator` image to `production` namespace.
- Fault injection endpoint (`/sim/fault`) must be protected by a static bearer token in non-development environments to prevent accidental mis-use.
- The inspection API (`/sim/objects`) returns full key object metadata. It must not be exposed outside the internal Docker/Kubernetes network (`NetworkPolicy: deny-all-ingress-except-internal`).
- Key material is stored in JVM heap memory only. No key bytes are written to disk unless `persistence.enabled: true`, in which case the file must be written to a `tmpfs` mount in CI.
- The `SO PIN` (Security Officer PIN) must not be hardcoded in source code — it must be injected via environment variable.

---

### 19.11 Acceptance Criteria (HSM Simulator)

| ID | Criterion |
|----|-----------|
| SIM-AC-01 | All 42 PKCS#11 functions listed in §19.2 return correct results for valid inputs with no physical HSM present. |
| SIM-AC-02 | The KMS service starts and executes key creation, encryption, decryption, and signing using the simulator without any code changes vs. a real HSM. |
| SIM-AC-03 | Injecting `HSM_BUSY` fault triggers the KMS circuit breaker to open after the configured failure rate threshold. |
| SIM-AC-04 | Injecting `HSM_DISCONNECTED` causes the KMS service health endpoint to report `"hsm": "DOWN"`. |
| SIM-AC-05 | `DELETE /sim/reset` clears all key objects and sessions; subsequent operations behave as on a fresh token. |
| SIM-AC-06 | The simulator Docker image starts in < 5 seconds and `GET /sim/slots` returns 200 OK. |
| SIM-AC-07 | `GET /sim/calls` returns a structured log of all PKCS#11 calls including timestamps, operation name, session ID, and return code. |
| SIM-AC-08 | The simulator image is absent from all Helm charts targeting the `production` namespace (enforced by CI policy check). |
