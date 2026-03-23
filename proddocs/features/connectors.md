# Connector Catalog

Warlock includes 165 source connectors that collect security and compliance telemetry from the tools your organization already uses. Each connector follows the same contract: validate configuration, verify connectivity, and produce raw events with verbatim API responses preserved for auditability.

This document catalogs every connector by category, explains how connectors work, and describes how to add new connectors.

## How Connectors Work

Every connector extends `BaseConnector` and implements three methods:

| Method | Purpose | Returns |
|---|---|---|
| `validate()` | Check that configuration and dependencies are present | List of error strings (empty = valid) |
| `health_check()` | Verify connectivity to the source | `True` if reachable, `False` otherwise |
| `collect()` | Fetch data from the source API | `ConnectorResult` containing `RawEventData` |

### The Collection Flow

1. The `ConnectorRegistry` creates and validates connector instances from configuration
2. On a pipeline run, `collect_all()` runs all enabled connectors in parallel using a thread pool (up to 32 workers)
3. Each connector produces a `ConnectorResult` with status (`success`, `partial`, `error`) and a list of `RawEventData` objects
4. Each `RawEventData` includes the verbatim API response, a source type tag, an event type string, and a SHA-256 hash of the raw data for integrity verification

### RawEventData Structure

```
RawEventData:
  source          -- Provider identifier (e.g., "aws", "okta")
  source_type     -- Category enum (e.g., SourceType.CLOUD, SourceType.IAM)
  provider        -- Provider name for registry lookup
  event_type      -- Type string that links to framework control checks
                     (e.g., "iam_credential_report", "okta_users")
  raw_data        -- Verbatim API response as a dictionary
  observed_at     -- UTC timestamp of collection
  id              -- UUID
  sha256          -- SHA-256 hash of raw_data (computed on access)
```

The `event_type` field is the bridge between raw data and compliance frameworks. Framework YAMLs specify which event types provide evidence for each control. When a connector produces events with `event_type: iam_credential_report`, the control mapper knows those events are relevant to controls like NIST AC-2, SOC 2 CC6.1, and ISO 27001 A.8.5.

### ConnectorResult Structure

```
ConnectorResult:
  connector_name  -- Name of the connector instance
  source          -- Provider identifier
  source_type     -- Category enum
  provider        -- Provider name
  status          -- "running", "success", "partial", "error"
  events          -- List of RawEventData collected
  errors          -- List of error strings (if any)
  started_at      -- UTC timestamp when collection began
  completed_at    -- UTC timestamp when collection finished
  duration_seconds -- Computed from start/end timestamps
```

A `partial` status means the connector collected some events but also encountered errors -- common when a provider has multiple API endpoints and some are unavailable.

## Connector Catalog by Category

### Cloud Infrastructure (10 connectors)

Cloud connectors collect configuration, security posture, and activity data from infrastructure providers.

| Connector | Provider | What It Collects |
|---|---|---|
| AWS | Amazon Web Services | IAM credential reports, users, policies, password policy, account summary; CloudTrail trails and status; EC2 security groups, network ACLs, VPCs, flow logs; GuardDuty detectors; SecurityHub hub status; S3 bucket configuration; Config recorders and compliance |
| Azure | Microsoft Azure | Resource Graph queries, Network Security Groups, Activity Log, Defender for Cloud alerts, Key Vault configuration |
| GCP | Google Cloud Platform | IAM policies, Compute firewall rules, audit logs, Security Command Center findings, Cloud KMS keys |
| OCI | Oracle Cloud Infrastructure | Cloud Guard findings, IAM policies, security lists, audit events |
| IBM Cloud | IBM Cloud | Security Advisor findings, IAM policies, activity logs |
| Alibaba | Alibaba Cloud | Security Center findings, RAM policies, ActionTrail events |
| DigitalOcean | DigitalOcean | Firewall rules, database clusters, Kubernetes clusters |
| Huawei | Huawei Cloud | Cloud Eye alarms, IAM policies, Security Center findings |
| OVH | OVH Cloud | IP firewall rules, user accounts, audit logs |
| Cloudflare | Cloudflare | DNS records, WAF rules, SSL settings, audit logs |

**Compliance questions answered**: Is our cloud infrastructure configured securely? Are IAM policies following least privilege? Is audit logging enabled? Are threat detection services active? Are storage buckets publicly accessible?

### Endpoint Detection and Response (4 connectors)

EDR connectors collect threat detection data, device inventory, and incident information.

| Connector | Provider | What It Collects |
|---|---|---|
| CrowdStrike | CrowdStrike Falcon | Detections, device inventory, prevention policies, sensor status |
| Microsoft Defender | Microsoft Defender for Endpoint | Alerts, device inventory, vulnerability findings, secure score |
| SentinelOne | SentinelOne | Threats, agents, policies, exclusions |
| Sophos | Sophos Central | Alerts, endpoint status, tamper protection, policies |

**Compliance questions answered**: Is endpoint protection deployed across all devices? Are threat detections being investigated? Are antivirus definitions current? Is tamper protection enabled?

### Identity and Access Management (8 connectors)

IAM connectors collect user accounts, authentication policies, access reviews, and credential status.

| Connector | Provider | What It Collects |
|---|---|---|
| Okta | Okta | Users, factors (MFA), policies, system log events, groups |
| Entra ID | Microsoft Entra ID | Users, authentication methods, conditional access policies, sign-in logs, directory audits |
| CyberArk | CyberArk | Privileged accounts, session recordings, safe configurations |
| SailPoint | SailPoint IdentityNow | Identities, accounts, roles, certifications (access reviews), entitlements |
| HashiCorp Vault | HashiCorp Vault | Auth methods, policies, secret engines, audit log status |
| JumpCloud | JumpCloud | Users, MFA status, system associations, policies |
| Auth0 | Auth0 | Users, connections, rules, MFA enrollment, logs |
| 1Password | 1Password Business | Vault inventory, user provisioning, security policies |

**Compliance questions answered**: Do all users have MFA enabled? Are access reviews performed regularly? Is privileged access managed through a PAM solution? Are inactive accounts disabled? Are credentials rotated on schedule?

### Vulnerability Scanners (5 connectors)

Scanner connectors collect vulnerability findings, asset inventories, and scan coverage data.

| Connector | Provider | What It Collects |
|---|---|---|
| Tenable | Tenable.io | Vulnerability findings, assets, scan schedules, compliance checks |
| Qualys | Qualys VMDR | Vulnerability detections, host assets, scan lists |
| Wiz | Wiz | Issues, vulnerability findings, cloud configuration findings |
| Nessus | Tenable Nessus | Scan results, vulnerability findings, compliance audits |
| Checkmarx | Checkmarx | SAST/DAST findings, scan results, project risk scores |

**Compliance questions answered**: Are vulnerability scans current? Are critical vulnerabilities remediated within SLA? What is the scan coverage across the asset inventory?

### Cloud Security Posture Management (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| Prisma Cloud | Palo Alto Prisma Cloud | Compliance findings, alerts, asset inventory, policy violations |

**Compliance questions answered**: Are cloud resources compliant with CIS benchmarks? What misconfigurations exist across multi-cloud environments?

### SIEM and Log Management (3 connectors)

SIEM connectors collect security events, correlation rules, and monitoring coverage data.

| Connector | Provider | What It Collects |
|---|---|---|
| Microsoft Sentinel | Microsoft Sentinel | Incidents, analytics rules, data connectors, hunting queries |
| Splunk | Splunk Enterprise/Cloud | Saved searches, notable events, data inputs, indexes |
| Elastic | Elastic Security | Detection rules, alerts, agent status, indices |

**Compliance questions answered**: Is security monitoring active? Are detection rules configured for required event types? Is log data being retained for the required period?

### Network Security (3 connectors)

Network connectors collect firewall rules, network segmentation data, and VPN status.

| Connector | Provider | What It Collects |
|---|---|---|
| Palo Alto Networks | Palo Alto NGFW | Security policies, threat logs, URL filtering, zone configuration |
| Fortinet FortiGate | Fortinet | Firewall policies, VPN tunnels, intrusion prevention, antivirus profiles |
| Zscaler | Zscaler | URL filtering policies, SSL inspection, DLP rules, cloud firewall policies |

**Compliance questions answered**: Is network segmentation enforced? Are firewalls configured to deny by default? Are VPN tunnels active and properly configured? Is network traffic being inspected?

### Code Security (11 connectors)

Code security connectors collect vulnerability findings from static analysis, dependency scanning, and secret detection.

| Connector | Provider | What It Collects |
|---|---|---|
| Snyk | Snyk | Vulnerability findings, license issues, dependency graphs |
| GitHub Advanced Security | GitHub | Code scanning alerts, secret scanning alerts, Dependabot alerts |
| Checkmarx | Checkmarx | SAST findings, DAST findings, SCA findings |
| SonarQube | SonarQube | Code quality issues, security hotspots, vulnerability findings |
| Semgrep | Semgrep | Static analysis findings, custom rule results |
| Trivy | Aqua Trivy | Container image vulnerabilities, filesystem findings, IaC misconfigurations |
| GitGuardian | GitGuardian | Secret detection findings, leaked credential alerts |
| Veracode | Veracode | Static analysis findings, dynamic analysis findings, SCA results |
| GitLab | GitLab Security | SAST, DAST, dependency scanning, container scanning results |
| Terraform Cloud | HashiCorp | Sentinel policy results, run status, workspace configuration |
| GitHub Actions | GitHub | Workflow runs, security alerts, OIDC configuration |

**Compliance questions answered**: Are there critical vulnerabilities in source code or dependencies? Are secrets leaking into repositories? Is infrastructure-as-code validated before deployment? Is the CI/CD pipeline secured?

### HR and Personnel (4 connectors)

HR connectors collect employee data for personnel security controls -- background checks, employment agreements, role changes, and terminations.

| Connector | Provider | What It Collects |
|---|---|---|
| Workday | Workday HCM | Employee records, onboarding status, terminations, role changes |
| BambooHR | BambooHR | Employee records, time-off data, custom fields |
| Gusto | Gusto | Employee records, onboarding checklists, compliance documents |
| Rippling | Rippling | Employee records, device assignments, app provisioning |

**Compliance questions answered**: Do all employees have background checks completed? Are employment agreements signed? Is access revoked promptly upon termination? Are role changes reviewed for access implications?

### IT Service Management (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| ServiceNow | ServiceNow | Change requests, incidents, problem records, CMDB assets |

**Compliance questions answered**: Are changes going through an approved change management process? Are incidents being tracked and resolved?

### Security Awareness Training (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| KnowBe4 | KnowBe4 | Training enrollments, completion rates, phishing simulation results |

**Compliance questions answered**: What percentage of employees have completed security awareness training? What is the phishing click rate?

### Email Security (3 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Proofpoint | Proofpoint | Threat insights, message traces, quarantine data |
| Abnormal Security | Abnormal Security | Threat detections, account compromise events |
| Exchange Online | Microsoft Exchange Online | Message trace logs, transport rules, anti-malware policies |

**Compliance questions answered**: Is email threat protection active? Are anti-phishing and anti-malware policies configured? Is email encryption enforced for sensitive data?

### Data Loss Prevention (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Microsoft Purview | Microsoft Purview | DLP policies, sensitivity labels, data classification results |
| Netskope | Netskope | DLP incidents, CASB policies, cloud app inventory |

**Compliance questions answered**: Are DLP policies active and detecting sensitive data? Is data classified according to organizational policy?

### Backup and Recovery (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| Veeam | Veeam | Backup job status, repository health, restore point data |

**Compliance questions answered**: Are backup jobs completing successfully? Are backups encrypted? Is backup data stored offsite?

### Mobile Device Management (3 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Microsoft Intune | Microsoft Intune | Device compliance, configuration profiles, app protection policies |
| Jamf | Jamf Pro | Device inventory, compliance status, patch management |
| Kandji | Kandji | Device compliance, blueprint enforcement, vulnerability patching |

**Compliance questions answered**: Are mobile devices enrolled in MDM? Are devices compliant with security policies? Are OS patches applied?

### MFA and Password Management (3 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Duo Security | Cisco Duo | Authentication logs, enrolled devices, policy configuration |
| 1Password | 1Password Business | Vault inventory, user provisioning, security policies |
| Bitwarden | Bitwarden | Organization policies, member status, collection access |

**Compliance questions answered**: Is MFA enforced for all access? Are passwords managed through an approved tool? Are password policies compliant?

### Collaboration (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Slack | Slack Enterprise | Workspace settings, app integrations, audit logs |
| Google Workspace | Google Workspace | Admin audit logs, user settings, security health |

### DevOps and Project Management (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| GitLab | GitLab | Repository settings, merge request policies, CI/CD configuration |
| Jira | Atlassian Jira | Issue tracking, workflow configuration, project settings |

### Observability (3 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Datadog | Datadog | Monitors, security signals, audit logs |
| New Relic | New Relic | Alert policies, NRQL alert conditions, synthetic monitors |
| Grafana | Grafana | Alert rules, data sources, dashboard configurations |

**Compliance questions answered**: Is system monitoring active? Are alerting rules configured for security events? Is observability coverage complete?

### Cloud Threat Detection (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| AWS GuardDuty | AWS GuardDuty | Threat findings, detector configuration (also collected via the AWS connector) |

### GRC Platforms (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Confluence | Atlassian Confluence | Policies, procedures, documented evidence pages |
| OneTrust | OneTrust | Privacy assessments, cookie compliance, data mapping |

### Physical Security (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| Verkada | Verkada | Camera status, access control events, door reader logs |

**Compliance questions answered**: Are physical access controls operational? Is visitor access logged?

### Third-Party Risk (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| SecurityScorecard | SecurityScorecard | Vendor risk scores, issue counts, factor grades |
| BitSight | BitSight | Security ratings, risk vectors, company details |

**Compliance questions answered**: Are third-party vendors assessed for security risk? Are vendor SLAs being monitored?

### Container Security (2 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Kubernetes | Kubernetes | Namespaces, pod security policies, RBAC roles, network policies |
| Aqua Security | Aqua | Container vulnerability findings, runtime policies, image assurance |

**Compliance questions answered**: Are container images scanned for vulnerabilities? Are pod security standards enforced? Is container runtime monitored?

### AI/ML Platforms (3 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| MLflow | MLflow | Model registry, experiment tracking, model versions |
| SageMaker | AWS SageMaker | Training jobs, endpoints, model monitoring, notebook instances |
| Databricks | Databricks | Workspace users, cluster policies, Unity Catalog, audit logs |

**Compliance questions answered**: Is the AI model inventory current? Are training experiments tracked? Are AI models monitored for drift and bias?

### CI/CD (4 connectors)

| Connector | Provider | What It Collects |
|---|---|---|
| Jenkins | Jenkins | Build history, plugin inventory, security configuration, credentials |
| GitHub Actions | GitHub | Workflow runs, OIDC configuration, secret usage |
| GitLab CI | GitLab | Pipeline history, runner configuration, variables |
| CircleCI | CircleCI | Pipeline runs, project settings, context variables |

**Compliance questions answered**: Is the CI/CD pipeline secured? Are builds using approved configurations? Are pipeline credentials managed securely?

### Generic Ingest (1 connector)

| Connector | Provider | What It Collects |
|---|---|---|
| Webhook | Generic | Accepts raw events via HTTP POST for custom integrations |

**Use case**: Ingest compliance data from tools that do not have a dedicated connector. Send structured JSON to the webhook endpoint and tag it with the appropriate event type.

## Demo vs Production Connectors

In **demo mode**, connectors generate synthetic data that exercises the full pipeline. The demo seed creates 81 connector instances producing realistic events across all categories. This allows evaluation of the entire platform without configuring real API credentials.

In **production mode**, connectors authenticate against real APIs using credentials stored in environment variables (prefixed with `WLK_`). Each connector's `validate()` method checks for required dependencies (e.g., `boto3` for AWS) and the `health_check()` method verifies connectivity before collection begins.

Enable a connector in production by setting its configuration:

```bash
WLK_AWS_ENABLED=true
WLK_OKTA_ENABLED=true
WLK_OKTA_DOMAIN=your-org.okta.com
WLK_OKTA_API_TOKEN=your-token-here
```

## Source Type Taxonomy

Every connector is classified into a `SourceType` that groups related data sources:

| SourceType | Description |
|---|---|
| `cloud` | Cloud infrastructure providers |
| `edr` | Endpoint detection and response |
| `iam` | Identity and access management |
| `scanner` | Vulnerability scanners |
| `cspm` | Cloud security posture management |
| `siem` | Security information and event management |
| `network` | Network security appliances |
| `code` | Code security and SAST/DAST |
| `hris` | Human resource information systems |
| `itsm` | IT service management |
| `training` | Security awareness training |
| `email_security` | Email threat protection |
| `dlp` | Data loss prevention |
| `backup` | Backup and recovery |
| `mdm` | Mobile device management |
| `observability` | Monitoring and alerting |
| `grc` | GRC platforms and documentation |
| `physical` | Physical security |
| `third_party_risk` | Third-party risk rating |
| `container_security` | Container and Kubernetes security |
| `ai_ml` | AI/ML platform governance |
| `ci_cd` | CI/CD pipeline security |
| `custom` | Custom or generic sources |

## Adding a New Connector

To add a connector for a new data source:

### 1. Create the connector module

Create a new file in `warlock/connectors/` (e.g., `warlock/connectors/my_tool.py`):

```python
from warlock.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorResult,
    RawEventData,
    SourceType,
    registry,
)

class MyToolConnector(BaseConnector):

    def validate(self) -> list[str]:
        errors = []
        # Check for required SDK or credentials
        if not self.get_secret("WLK_MYTOOL_API_KEY"):
            errors.append("WLK_MYTOOL_API_KEY not set")
        return errors

    def health_check(self) -> bool:
        # Verify API connectivity
        try:
            # Make a lightweight API call
            return True
        except Exception:
            return False

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source=self.source,
            source_type=self.source_type,
            provider=self.provider,
        )
        try:
            # Call the source API
            data = self._fetch_from_api()
            event = RawEventData(
                source=self.source,
                source_type=self.source_type,
                provider=self.provider,
                event_type="mytool_findings",  # Links to framework controls
                raw_data=data,
            )
            result.events.append(event)
            result.complete()
        except Exception as e:
            result.errors.append(str(e))
            result.complete("error")
        return result

# Register with the singleton registry
registry.register("mytool", MyToolConnector)
```

### 2. Create the matching normalizer

Every connector needs a normalizer in `warlock/normalizers/` that transforms the raw data into `FindingData`.

### 3. Update the dependency chain

Per the project's dependency chain rules, when adding a connector you must also update:
- `warlock/config.py` (add configuration fields)
- The matching normalizer
- `scripts/demo_seed.py` (add demo data)
- `README.md` (update connector count and list)

### 4. Map event types to framework controls

Add the new connector's `event_type` values to the relevant controls in `warlock/frameworks/*.yaml` so the control mapper links findings to the correct controls.
