# Compliance Framework Reference

Warlock supports 14 compliance frameworks encompassing 1,996 controls. Each framework is defined as a YAML file that specifies control families, individual controls, the event types that provide evidence, resource types to match, and monitoring frequencies.

This document covers every supported framework, how frameworks relate through crosswalks, how baselines and inheritance work, and how controls flow through the assessment pipeline.

## Framework Summary

| Framework | Controls | Families | OPA Policies | OSCAL Package | Crosswalked |
|---|---|---|---|---|---|
| NIST 800-53 Rev 5 | 1,176 | 20 | 286 | Yes | Yes |
| ISO 27001:2022 | 93 | 4 | 186 | Yes | Yes |
| ISO 27701:2019 | 95 | 3 | -- | Yes | -- |
| ISO 42001:2023 | 39 | 10 | -- | Yes | -- |
| SOC 2 (TSC) | 46 | 9 | 26 | Yes | Yes |
| UCF (Unified) | 115 | 20 | 24 | Yes | Yes |
| FedRAMP Moderate | 26 | 9 | -- | Yes | -- |
| HIPAA Security Rule | 64 | 3 | 40 | Yes | Yes |
| CMMC Level 2 | 110 | 14 | 50 | Yes | Yes |
| GDPR | 15 | 3 | -- | Yes | -- |
| PCI DSS v4.0 | 63 | 12 | 24 | Yes | Yes |
| NIST CSF 2.0 | 101 | 6 | -- | -- | -- |
| EU AI Act | 33 | 4 | -- | -- | -- |
| SEC Cyber | 20 | 4 | -- | -- | -- |
| **Total** | **1,996** | | **670** | **17 packages** | **1,843 edges** |

## Framework Details

### NIST 800-53 Rev 5

**What it is**: The most comprehensive security and privacy control catalog published by the National Institute of Standards and Technology. Revision 5 covers 20 control families from Access Control (AC) through System and Information Integrity (SI).

**Who needs it**: US federal agencies (mandatory), FedRAMP cloud service providers, defense contractors via CMMC, and any organization that wants a rigorous, well-structured control framework.

**Controls**: 1,176 controls including base controls and control enhancements (e.g., AC-2 is the base, AC-2(1) through AC-2(13) are enhancements).

**Control families**: AC (Access Control), AT (Awareness and Training), AU (Audit and Accountability), CA (Assessment, Authorization, and Monitoring), CM (Configuration Management), CP (Contingency Planning), IA (Identification and Authentication), IR (Incident Response), MA (Maintenance), MP (Media Protection), PE (Physical and Environmental Protection), PL (Planning), PM (Program Management), PS (Personnel Security), PT (PII Processing and Transparency), RA (Risk Assessment), SA (System and Services Acquisition), SC (System and Communications Protection), SI (System and Information Integrity), SR (Supply Chain Risk Management).

**Monitoring frequencies**: Each control has a monitoring frequency defined per NIST 800-53A (daily, weekly, monthly, quarterly). Warlock tracks whether each control is assessed within its required cadence.

**OPA policies**: 286 Rego policy files provide automated compliance evaluation.

**OSCAL package**: Full catalog and profile in OSCAL 1.1.2 JSON format.

### ISO 27001:2022

**What it is**: The international standard for Information Security Management Systems (ISMS). The 2022 revision restructured Annex A controls into 4 themes: Organizational, People, Physical, and Technological.

**Who needs it**: Any organization pursuing ISO 27001 certification, which is increasingly required by enterprise customers, especially in Europe and Asia-Pacific.

**Controls**: 93 controls across Annex A.

**Mapping to NIST**: ISO 27001 controls map extensively to NIST 800-53 via crosswalks. For example, ISO A.8.5 (Secure authentication) maps to NIST IA-2 (Identification and Authentication).

**OPA policies**: 186 Rego policy files.

### ISO 27701:2019

**What it is**: Privacy Information Management System (PIMS) extension to ISO 27001. Adds privacy-specific controls from Annex A (PII controllers) and Annex B (PII processors).

**Who needs it**: Organizations that process personal data and want a formal privacy management framework, particularly as a path to demonstrating GDPR compliance.

**Controls**: 95 controls covering consent management, data subject rights, cross-border transfers, and privacy impact assessments.

### ISO 42001:2023

**What it is**: The AI Management System standard. Defines controls for responsible AI development, deployment, and governance.

**Who needs it**: Organizations developing or deploying AI systems, especially those subject to the EU AI Act. Early adopters pursuing certification to demonstrate responsible AI practices.

**Controls**: 39 controls across 10 families covering AI risk assessment, data governance, model lifecycle management, transparency, and human oversight.

### SOC 2 (Trust Services Criteria)

**What it is**: The American Institute of CPAs (AICPA) Trust Services Criteria for service organizations. Covers Security (CC1-CC9), Availability (A1), Confidentiality (C1), Processing Integrity (PI1), and Privacy (P1).

**Who needs it**: SaaS companies, cloud service providers, and any organization whose customers require a SOC 2 Type II report. SOC 2 is the de facto standard for B2B SaaS security assurance.

**Controls**: 46 controls (criteria + points of focus).

**OPA policies**: 26 Rego policy files.

### UCF (Unified Compliance Framework)

**What it is**: A meta-framework that maps controls across multiple compliance standards into a unified taxonomy. UCF domains cover 20 areas from Access Control through Vendor Management.

**Who needs it**: Organizations managing compliance across many frameworks simultaneously. UCF serves as a Rosetta Stone -- assess a UCF control once, and it maps to equivalent controls in NIST, ISO, SOC 2, HIPAA, and PCI DSS.

**Controls**: 115 controls across 20 domains.

**OPA policies**: 24 Rego policy files.

### FedRAMP Moderate

**What it is**: The Federal Risk and Authorization Management Program baseline for cloud services handling controlled unclassified information (CUI). FedRAMP is a NIST 800-53 overlay with additional cloud-specific requirements.

**Who needs it**: Cloud service providers seeking authorization to operate with US federal agencies.

**Controls**: 26 FedRAMP-specific controls (the full NIST 800-53 Moderate baseline applies, with these as the overlay).

**Control inheritance**: FedRAMP uses the Customer Responsibility Matrix (CRM) pattern. Some controls are fully inherited from the cloud provider (e.g., PE-* physical controls in AWS), some are shared responsibility, and some are customer-only. Warlock tracks inheritance status per control per provider.

### HIPAA Security Rule

**What it is**: The Health Insurance Portability and Accountability Act security requirements. Organized into Administrative Safeguards, Physical Safeguards, and Technical Safeguards.

**Who needs it**: Covered entities (hospitals, insurers, clearinghouses) and business associates that handle protected health information (PHI).

**Controls**: 64 controls covering access controls, audit controls, integrity controls, transmission security, and workforce security.

**OPA policies**: 40 Rego policy files.

### CMMC Level 2

**What it is**: Cybersecurity Maturity Model Certification Level 2, aligned with NIST SP 800-171. Covers 14 security domains required for handling Controlled Unclassified Information (CUI).

**Who needs it**: Defense industrial base (DIB) contractors and subcontractors who handle CUI. CMMC Level 2 is required for Department of Defense contracts involving CUI.

**Controls**: 110 controls across 14 families aligned with NIST 800-171 requirements.

**OPA policies**: 50 Rego policy files.

### GDPR

**What it is**: The European Union General Data Protection Regulation. Defines data protection requirements for organizations processing personal data of EU residents.

**Who needs it**: Any organization that processes personal data of EU residents, regardless of where the organization is located.

**Controls**: 15 controls covering data protection principles, lawful processing, data subject rights, data protection by design, breach notification, and international transfers.

**Warlock support**: Beyond the 15 control mappings, Warlock includes dedicated GDPR endpoints -- data subject access export (Article 15) and PII anonymization (Article 17/right to erasure).

### PCI DSS v4.0

**What it is**: Payment Card Industry Data Security Standard version 4.0. Defines 12 requirements for organizations that store, process, or transmit cardholder data.

**Who needs it**: Merchants, payment processors, acquirers, issuers, and service providers in the payment card ecosystem.

**Controls**: 63 controls across 12 requirements covering network security, data protection, vulnerability management, access control, monitoring, and security policies.

**OPA policies**: 24 Rego policy files.

### NIST CSF 2.0

**What it is**: The NIST Cybersecurity Framework version 2.0, organized around six core functions: Govern, Identify, Protect, Detect, Respond, and Recover. Version 2.0 added the Govern function and expanded supply chain risk management.

**Who needs it**: Any organization building or maturing a cybersecurity program. NIST CSF is voluntary but widely adopted as a common language for cybersecurity risk management.

**Controls**: 101 controls (subcategories) across the six functions.

### EU AI Act

**What it is**: The European Union Artificial Intelligence Act, establishing requirements for AI systems based on risk classification. High-risk AI systems face the most stringent requirements.

**Who needs it**: Organizations developing, deploying, or distributing AI systems in the EU market. Applies to high-risk AI systems in areas like critical infrastructure, education, employment, and law enforcement.

**Controls**: 33 controls covering risk management, data governance, technical documentation, transparency, human oversight, accuracy, robustness, and cybersecurity for AI systems.

### SEC Cyber

**What it is**: SEC cybersecurity disclosure rules requiring public companies to disclose material cybersecurity incidents and describe their cybersecurity risk management, strategy, and governance.

**Who needs it**: Public companies registered with the US Securities and Exchange Commission.

**Controls**: 20 controls covering incident disclosure (Form 8-K Item 1.05), annual risk management disclosure (Form 10-K Item 1C), board oversight, and management's role in cybersecurity governance.

## Crosswalks

Crosswalks define relationships between controls in different frameworks. When two controls across two frameworks address the same security requirement, a crosswalk edge connects them with a confidence score.

Warlock maintains 1,843 crosswalk edges. Key crosswalk relationships include:

| Source Framework | Target Framework | Example |
|---|---|---|
| NIST 800-53 | SOC 2 | AC-2 --> CC6.1 (confidence 0.95) |
| NIST 800-53 | SOC 2 | AU-2 --> CC7.2 (confidence 0.90) |
| NIST 800-53 | ISO 27001 | AC-2 --> A.8.5 |
| NIST 800-53 | HIPAA | AC-2 --> 164.312(a)(1) |
| NIST 800-53 | PCI DSS | AC-2 --> 7.1 |
| NIST 800-53 | CMMC L2 | AC-2 --> AC.L2-3.1.1 |
| UCF | NIST 800-53 | UCF-AC-001 --> AC-2 |
| UCF | ISO 27001 | UCF-AC-001 --> A.8.5 |

### How Crosswalks Work

Each crosswalk edge specifies:

- **Source framework and control**: The originating control
- **Target framework and control**: The equivalent control
- **Confidence score**: A float from 0.0 to 1.0 indicating how closely the controls align

When evidence satisfies a NIST 800-53 control, Warlock can propagate that assessment to related controls in other frameworks via the crosswalk graph. This eliminates redundant evidence collection for organizations managing multiple certifications.

### Practical Impact

Consider an organization pursuing SOC 2 + ISO 27001 + HIPAA simultaneously:

- Collecting IAM credential reports from AWS satisfies the MFA requirement for:
  - NIST 800-53 AC-2 (Account Management)
  - SOC 2 CC6.1 (Logical and Physical Access Controls)
  - ISO 27001 A.8.5 (Secure Authentication)
  - HIPAA 164.312(d) (Person or Entity Authentication)
- One piece of evidence, one connector run, one normalization -- four framework controls assessed.

## Baselines

Baselines define subsets of a framework's controls applicable at different impact levels. Warlock includes NIST 800-53 baselines:

| Baseline | Description | Use Case |
|---|---|---|
| Low | Minimum controls for low-impact systems | Non-sensitive internal systems |
| Moderate | Controls for moderate-impact systems | Most federal information systems, FedRAMP |
| High | Full control set for high-impact systems | National security, critical infrastructure |

Baselines allow organizations to scope their compliance posture to the appropriate impact level rather than assessing against the full 1,176-control catalog.

## Control Inheritance

Control inheritance tracks which controls are provided by an underlying platform (typically a cloud service provider) rather than implemented by the customer organization.

Warlock maintains an inherited controls reference with three categories per cloud provider:

| Category | Meaning | Example |
|---|---|---|
| Fully inherited | Cloud provider is solely responsible | PE-* (physical controls) in AWS/Azure/GCP |
| Shared | Both provider and customer have responsibilities | AC-2 (provider manages IAM service; customer manages user accounts) |
| Customer only | Customer is solely responsible | AT-2 (security awareness training for your staff) |

Supported cloud providers for inheritance mapping: AWS, Azure, GCP.

When a control is marked as fully inherited, Warlock assigns the status `inherited_compliant` based on the provider's authorization status (e.g., AWS FedRAMP authorization). Shared controls are assessed based on the customer's implementation of their portion of the responsibility.

## How Controls Flow Through the Pipeline

### Step 1: Framework YAML Defines Evidence Requirements

Each control in a framework YAML specifies which `event_types` provide evidence and which `resource_types` to match:

```yaml
AC-2:
  checks:
    - id: ac2_iam_users
      event_types:
        - iam_credential_report
        - iam_users
        - okta_users
        - entra_users
      resource_types:
        - iam_user
        - iam_account
        - okta_user
        - entra_user
  monitoring_frequency: daily
```

This tells Warlock: "To assess AC-2, look for findings produced from IAM credential reports, user lists from Okta or Entra ID. Check this control daily."

### Step 2: Connectors Collect Raw Events

When connectors run, they produce `RawEventData` tagged with `event_type` values (e.g., `iam_credential_report`, `okta_users`). These event types are the link between raw data and framework controls.

### Step 3: Normalizers Produce Findings

Each raw event is normalized into `FindingData` with structured detail fields. The normalizer preserves the event type so the mapper can match findings to controls.

### Step 4: Control Mapper Assigns Findings to Controls

The mapper reads every framework YAML, matches finding event types to control check definitions, and produces `ControlMappingData` linking each finding to every applicable control across all 14 frameworks.

### Step 5: Assessment Engine Evaluates Each Mapping

For each finding-to-control mapping, the four-tier assessment runs:

1. **Tier 1** -- Deterministic assertions: 101 registered assertion functions check specific conditions (e.g., `mfa_enabled`, `no_open_security_groups`, `encryption_at_rest`). A control can have multiple assertions; all must pass for a compliant status.

2. **Tier 2** -- AI reasoning: If no assertion is available or the result is inconclusive, an LLM evaluates the finding against the control with full compliance context (compensating controls, risk acceptances, posture trends). A confidence floor (default 0.7) rejects unreliable assessments.

3. **Tier 3** -- OPA Rego policies: 670 policy files across 8 frameworks provide automated policy-as-code evaluation.

4. **Tier 4** -- Control inheritance: If the control is still not assessed, and it is a child enhancement (e.g., AC-2(3)), it inherits the parent control's status (AC-2) with reduced confidence.

### Step 6: Results Persist with Full Lineage

Every `ControlResultData` records:
- Which finding produced it (`finding_id`)
- Which control mapping it evaluated (`control_mapping_id`)
- Which assessor determined the status (`assessor` field: `assertion:mfa_enabled`, `ai:claude-sonnet-4-20250514`, `inherited:AC-2`)
- The evidence chain back to raw events (`evidence_ids`)
- Timestamp of assessment (`assessed_at`)

## Status Values

Each control result carries one of seven status values:

| Status | Meaning |
|---|---|
| `compliant` | All applicable assertions passed; evidence confirms the control is implemented |
| `non_compliant` | One or more assertions failed; evidence indicates the control is not fully implemented |
| `partial` | Some aspects of the control are implemented but gaps exist |
| `not_assessed` | No assertion, AI reasoning, or inheritance could evaluate this control |
| `not_applicable` | The control does not apply to this system or finding |
| `risk_accepted` | The control gap is formally accepted via a risk acceptance workflow |
| `inherited_compliant` | The control is inherited from an underlying provider's authorization |

## Adding a New Framework

To add a new compliance framework to Warlock:

1. **Create the framework YAML** in `warlock/frameworks/` following the v2 dict-based structure
2. **Map event types** to controls -- identify which connectors and event types provide evidence for each control
3. **Define monitoring frequencies** per control
4. **Add crosswalk edges** in `crosswalks.yaml` linking to existing framework controls
5. **Optionally write OPA policies** in `policies/` for automated evaluation
6. **Optionally create an OSCAL package** in `frameworks-oscal/` for machine-readable export
7. **Re-run the demo seed** to verify the framework loads and produces control results
