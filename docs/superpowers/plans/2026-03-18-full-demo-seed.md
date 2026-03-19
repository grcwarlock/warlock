# Full Demo Seed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `scripts/demo_seed.py` so every `warlock` CLI command returns rich, coherent demo data — no feature left empty.

**Architecture:** Add 4 new mock connectors (Workday, KnowBe4, SecurityScorecard, Confluence) that produce raw events flowing through existing normalizers, then call workflow managers post-pipeline to populate systems, questionnaires, legal holds, issues, and data silos.

**Tech Stack:** Python, SQLAlchemy, existing warlock pipeline infrastructure

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `scripts/demo_seed.py` | Modify | Add 4 mock connectors + post-pipeline seeding steps |

Single file change. All new code goes into `demo_seed.py` following the existing pattern of mock connector classes + a `main()` function.

---

### Task 1: Add DemoWorkdayConnector (HR/Personnel data)

**Files:**
- Modify: `scripts/demo_seed.py`

Adds a mock Workday connector producing 8 employees, background checks, and agreements. The existing `WorkdayNormalizer` handles normalization into `hr_employee` findings that `PersonnelManager.sync_from_hr()` consumes.

- [ ] **Step 1: Add imports for Workday normalizer at top of demo_seed.py**

After the existing normalizer imports, add:

```python
from warlock.normalizers.workday import WorkdayNormalizer
```

- [ ] **Step 2: Add DemoWorkdayConnector class after DemoCrowdStrikeConnector**

```python
class DemoWorkdayConnector(BaseConnector):
    """Simulates Workday HRIS collection — 8 employees."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="workday",
            source_type=SourceType.HRIS,
            provider="workday",
        )

        # Employees
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_employees",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {
                        "id": "WD-001", "descriptor": "Alice Chen",
                        "status": "Active", "department": "Engineering",
                        "manager": "frank.torres@acme.com",
                        "hireDate": "2024-02-01T00:00:00+00:00",
                        "terminationDate": "",
                    },
                    {
                        "id": "WD-002", "descriptor": "Bob Martinez",
                        "status": "Active", "department": "DevOps",
                        "manager": "frank.torres@acme.com",
                        "hireDate": "2023-08-15T00:00:00+00:00",
                        "terminationDate": "",
                    },
                    {
                        "id": "WD-003", "descriptor": "Carol Park",
                        "status": "Active", "department": "Finance",
                        "manager": "hassan.ali@acme.com",
                        "hireDate": "2022-06-01T00:00:00+00:00",
                        "terminationDate": "",
                    },
                    {
                        # Terminated but will still be active in Okta — critical flag
                        "id": "WD-004", "descriptor": "Dave Thompson",
                        "status": "Terminated", "department": "Sales",
                        "manager": "hassan.ali@acme.com",
                        "hireDate": "2023-01-15T00:00:00+00:00",
                        "terminationDate": (NOW - timedelta(days=30)).isoformat(),
                    },
                    {
                        "id": "WD-005", "descriptor": "Eve Nakamura",
                        "status": "Active", "department": "Security",
                        "manager": "grace.kim@acme.com",
                        "hireDate": (NOW - timedelta(days=14)).isoformat(),
                        "terminationDate": "",
                    },
                    {
                        "id": "WD-006", "descriptor": "Frank Torres",
                        "status": "Active", "department": "Engineering",
                        "manager": "hassan.ali@acme.com",
                        "hireDate": "2021-03-01T00:00:00+00:00",
                        "terminationDate": "",
                    },
                    {
                        "id": "WD-007", "descriptor": "Grace Kim",
                        "status": "Active", "department": "Legal",
                        "manager": "hassan.ali@acme.com",
                        "hireDate": "2023-11-01T00:00:00+00:00",
                        "terminationDate": "",
                    },
                    {
                        "id": "WD-008", "descriptor": "Hassan Ali",
                        "status": "Active", "department": "Product",
                        "manager": "",  # Missing manager — triggers flag
                        "hireDate": "2022-01-10T00:00:00+00:00",
                        "terminationDate": "",
                    },
                ],
            },
        ))

        # Background checks
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_background_checks",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {"worker_id": "WD-001", "worker_name": "Alice Chen",
                     "background_check": {"status": "completed", "date": "2024-01-15"}},
                    {"worker_id": "WD-002", "worker_name": "Bob Martinez",
                     "background_check": {"status": "completed", "date": "2023-07-20"}},
                    {"worker_id": "WD-003", "worker_name": "Carol Park",
                     "background_check": {"status": "completed", "date": "2022-05-10"}},
                    {"worker_id": "WD-004", "worker_name": "Dave Thompson",
                     "background_check": {"status": "completed", "date": "2023-01-05"}},
                    {"worker_id": "WD-005", "worker_name": "Eve Nakamura",
                     "background_check": {"status": "in_progress", "date": ""}},
                    {"worker_id": "WD-006", "worker_name": "Frank Torres",
                     "background_check": {"status": "completed", "date": "2021-02-20"}},
                    {"worker_id": "WD-007", "worker_name": "Grace Kim",
                     "background_check": {"status": "pending", "date": ""}},
                    {"worker_id": "WD-008", "worker_name": "Hassan Ali",
                     "background_check": {"status": "completed", "date": "2021-12-15"}},
                ],
            },
        ))

        # Agreements
        result.events.append(RawEventData(
            source="workday", source_type=SourceType.HRIS, provider="workday",
            event_type="workday_agreements",
            raw_data={
                "tenant": "acme-prod",
                "response": [
                    {"worker_id": "WD-001", "worker_name": "Alice Chen",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-002", "worker_name": "Bob Martinez",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-003", "worker_name": "Carol Park",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-004", "worker_name": "Dave Thompson",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-005", "worker_name": "Eve Nakamura",
                     "employment_agreement_signed": True, "nda_signed": False},
                    {"worker_id": "WD-006", "worker_name": "Frank Torres",
                     "employment_agreement_signed": True, "nda_signed": True},
                    {"worker_id": "WD-007", "worker_name": "Grace Kim",
                     "employment_agreement_signed": False, "nda_signed": False},
                    {"worker_id": "WD-008", "worker_name": "Hassan Ali",
                     "employment_agreement_signed": True, "nda_signed": True},
                ],
            },
        ))

        result.complete()
        return result
```

- [ ] **Step 3: Register connector and normalizer in main()**

In the connector registration block, add:

```python
connectors.register("workday", DemoWorkdayConnector)
connectors.create(ConnectorConfig(
    name="demo-workday", source_type=SourceType.HRIS, provider="workday",
))
normalizers.register(WorkdayNormalizer())
```

- [ ] **Step 4: Run demo seed and verify Workday findings appear**

```bash
cd /Users/jsn/Coding/GitHub/warlock/warlock && source .venv/bin/activate && python scripts/demo_seed.py
warlock findings | grep -i workday | head -5
```

Expected: Workday employee, background check, and agreement findings visible.

---

### Task 2: Add DemoKnowBe4Connector (Training data)

**Files:**
- Modify: `scripts/demo_seed.py`

Adds mock KnowBe4 training enrollments and phishing results for the same 8 employees.

- [ ] **Step 1: Add import**

```python
from warlock.normalizers.knowbe4 import KnowBe4Normalizer
```

- [ ] **Step 2: Add DemoKnowBe4Connector class**

```python
class DemoKnowBe4Connector(BaseConnector):
    """Simulates KnowBe4 training and phishing data."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="knowbe4",
            source_type=SourceType.TRAINING,
            provider="knowbe4",
        )

        # Training enrollments — mix of completed, overdue, in-progress
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_training_enrollments",
            raw_data={
                "response": [
                    {"enrollment_id": "enr-001", "user_name": "Alice Chen",
                     "user": {"name": "Alice Chen"}, "module_name": "Security Awareness 2025",
                     "status": "not_started",
                     "due_date": (NOW - timedelta(days=30)).isoformat()},
                    {"enrollment_id": "enr-002", "user_name": "Bob Martinez",
                     "user": {"name": "Bob Martinez"}, "module_name": "Security Awareness 2025",
                     "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=10)).isoformat()},
                    {"enrollment_id": "enr-003", "user_name": "Carol Park",
                     "user": {"name": "Carol Park"}, "module_name": "Security Awareness 2025",
                     "status": "not_started",
                     "due_date": (NOW - timedelta(days=60)).isoformat()},
                    {"enrollment_id": "enr-004", "user_name": "Dave Thompson",
                     "user": {"name": "Dave Thompson"}, "module_name": "Security Awareness 2025",
                     "status": "completed",
                     "due_date": (NOW - timedelta(days=90)).isoformat(),
                     "completion_date": (NOW - timedelta(days=100)).isoformat()},
                    {"enrollment_id": "enr-005", "user_name": "Eve Nakamura",
                     "user": {"name": "Eve Nakamura"}, "module_name": "New Hire Security Onboarding",
                     "status": "in_progress",
                     "due_date": (NOW + timedelta(days=14)).isoformat()},
                    {"enrollment_id": "enr-006", "user_name": "Frank Torres",
                     "user": {"name": "Frank Torres"}, "module_name": "Security Awareness 2025",
                     "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=5)).isoformat()},
                    {"enrollment_id": "enr-007", "user_name": "Grace Kim",
                     "user": {"name": "Grace Kim"}, "module_name": "Security Awareness 2025",
                     "status": "not_started",
                     "due_date": (NOW - timedelta(days=15)).isoformat()},
                    {"enrollment_id": "enr-008", "user_name": "Hassan Ali",
                     "user": {"name": "Hassan Ali"}, "module_name": "Security Awareness 2025",
                     "status": "completed",
                     "due_date": (NOW + timedelta(days=30)).isoformat(),
                     "completion_date": (NOW - timedelta(days=20)).isoformat()},
                ],
            },
        ))

        # Phishing results — Carol and Grace clicked
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_phishing_results",
            raw_data={
                "response": [
                    {
                        "pst_id": "pst-001", "name": "Q1 Phishing Simulation",
                        "recipients": [
                            {"email": "alice.chen@acme.com", "user": {"name": "Alice Chen"},
                             "clicked_link": False, "reported": True, "opened_email": True},
                            {"email": "bob.martinez@acme.com", "user": {"name": "Bob Martinez"},
                             "clicked_link": False, "reported": True, "opened_email": False},
                            {"email": "carol.park@acme.com", "user": {"name": "Carol Park"},
                             "clicked_link": True, "reported": False, "opened_email": True},
                            {"email": "frank.torres@acme.com", "user": {"name": "Frank Torres"},
                             "clicked_link": False, "reported": True, "opened_email": True},
                            {"email": "grace.kim@acme.com", "user": {"name": "Grace Kim"},
                             "clicked_link": True, "reported": False, "opened_email": True},
                            {"email": "hassan.ali@acme.com", "user": {"name": "Hassan Ali"},
                             "clicked_link": False, "reported": False, "opened_email": True},
                        ],
                    },
                ],
            },
        ))

        # Training campaign (org-level)
        result.events.append(RawEventData(
            source="knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
            event_type="kb4_training_campaigns",
            raw_data={
                "response": [
                    {
                        "campaign_id": "camp-001", "name": "Security Awareness 2025",
                        "status": "in_progress",
                        "completion_percentage": 50,
                        "start_date": (NOW - timedelta(days=60)).isoformat(),
                        "end_date": (NOW + timedelta(days=30)).isoformat(),
                    },
                    {
                        "campaign_id": "camp-002", "name": "New Hire Security Onboarding",
                        "status": "in_progress",
                        "completion_percentage": 0,
                        "start_date": (NOW - timedelta(days=14)).isoformat(),
                        "end_date": (NOW + timedelta(days=14)).isoformat(),
                    },
                ],
            },
        ))

        result.complete()
        return result
```

- [ ] **Step 3: Register connector and normalizer in main()**

```python
connectors.register("knowbe4", DemoKnowBe4Connector)
connectors.create(ConnectorConfig(
    name="demo-knowbe4", source_type=SourceType.TRAINING, provider="knowbe4",
))
normalizers.register(KnowBe4Normalizer())
```

- [ ] **Step 4: Run and verify**

```bash
python scripts/demo_seed.py
warlock findings | grep -i training | head -5
warlock findings | grep -i phishing | head -5
```

---

### Task 3: Add DemoSecurityScorecardConnector (Vendor risk data)

**Files:**
- Modify: `scripts/demo_seed.py`

Adds 5 vendor companies with risk factors and issues flowing through `SecurityScorecardNormalizer`.

- [ ] **Step 1: Add import**

```python
from warlock.normalizers.securityscorecard import SecurityScorecardNormalizer
```

- [ ] **Step 2: Add DemoSecurityScorecardConnector class**

```python
class DemoSecurityScorecardConnector(BaseConnector):
    """Simulates SecurityScorecard vendor risk data — 5 vendors."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="securityscorecard",
            source_type=SourceType.GRC,
            provider="securityscorecard",
        )

        # Company scores
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC,
            provider="securityscorecard",
            event_type="ssc_companies",
            raw_data={
                "response": [
                    {"domain": "stripe.com", "name": "Stripe", "score": 92,
                     "grade": "A", "industry": "Financial Services", "size": "large",
                     "last_score_change": 2},
                    {"domain": "datadoghq.com", "name": "Datadog", "score": 88,
                     "grade": "A", "industry": "Technology", "size": "large",
                     "last_score_change": -1},
                    {"domain": "acmestaffing.example.com", "name": "Acme Staffing Co",
                     "score": 58, "grade": "D", "industry": "Professional Services",
                     "size": "small", "last_score_change": -5},
                    {"domain": "cloudbackuppro.example.com", "name": "CloudBackup Pro",
                     "score": 45, "grade": "F", "industry": "Technology", "size": "small",
                     "last_score_change": -12},
                    {"domain": "quickdocs.example.com", "name": "QuickDocs LLC",
                     "score": 72, "grade": "C", "industry": "Technology", "size": "medium",
                     "last_score_change": 3},
                ],
            },
        ))

        # Risk factors per vendor
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC,
            provider="securityscorecard",
            event_type="ssc_factors",
            raw_data={
                "response": [
                    {"domain": "stripe.com", "factors": [
                        {"name": "Network Security", "grade": "A", "score": 95, "issue_count": 0},
                        {"name": "Patching Cadence", "grade": "A", "score": 90, "issue_count": 1},
                        {"name": "Application Security", "grade": "B", "score": 82, "issue_count": 2},
                        {"name": "DNS Health", "grade": "A", "score": 97, "issue_count": 0},
                    ]},
                    {"domain": "datadoghq.com", "factors": [
                        {"name": "Network Security", "grade": "A", "score": 91, "issue_count": 1},
                        {"name": "Patching Cadence", "grade": "B", "score": 85, "issue_count": 3},
                        {"name": "Application Security", "grade": "A", "score": 90, "issue_count": 1},
                        {"name": "Endpoint Security", "grade": "B", "score": 80, "issue_count": 2},
                    ]},
                    {"domain": "acmestaffing.example.com", "factors": [
                        {"name": "Network Security", "grade": "D", "score": 40, "issue_count": 8},
                        {"name": "Patching Cadence", "grade": "F", "score": 25, "issue_count": 15},
                        {"name": "Application Security", "grade": "C", "score": 60, "issue_count": 5},
                        {"name": "DNS Health", "grade": "D", "score": 45, "issue_count": 4},
                    ]},
                    {"domain": "cloudbackuppro.example.com", "factors": [
                        {"name": "Network Security", "grade": "F", "score": 20, "issue_count": 12},
                        {"name": "Patching Cadence", "grade": "F", "score": 15, "issue_count": 20},
                        {"name": "Application Security", "grade": "D", "score": 35, "issue_count": 9},
                        {"name": "Endpoint Security", "grade": "F", "score": 18, "issue_count": 14},
                    ]},
                    {"domain": "quickdocs.example.com", "factors": [
                        {"name": "Network Security", "grade": "C", "score": 68, "issue_count": 4},
                        {"name": "Patching Cadence", "grade": "B", "score": 78, "issue_count": 3},
                        {"name": "Application Security", "grade": "C", "score": 65, "issue_count": 5},
                        {"name": "DNS Health", "grade": "B", "score": 80, "issue_count": 1},
                    ]},
                ],
            },
        ))

        # Issues for problematic vendors
        result.events.append(RawEventData(
            source="securityscorecard", source_type=SourceType.GRC,
            provider="securityscorecard",
            event_type="ssc_issues",
            raw_data={
                "response": [
                    {"_domain": "acmestaffing.example.com", "type": "tlscert_expired",
                     "severity": "high", "count": 2,
                     "first_seen_time": (NOW - timedelta(days=90)).isoformat(),
                     "last_seen_time": (NOW - timedelta(days=1)).isoformat()},
                    {"_domain": "acmestaffing.example.com", "type": "open_port_25",
                     "severity": "medium", "count": 1,
                     "first_seen_time": (NOW - timedelta(days=180)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "tlscert_no_revocation",
                     "severity": "critical", "count": 3,
                     "first_seen_time": (NOW - timedelta(days=60)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "cve_detected",
                     "severity": "critical", "count": 5,
                     "first_seen_time": (NOW - timedelta(days=120)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "cloudbackuppro.example.com", "type": "spf_record_missing",
                     "severity": "high", "count": 1,
                     "first_seen_time": (NOW - timedelta(days=200)).isoformat(),
                     "last_seen_time": NOW.isoformat()},
                    {"_domain": "quickdocs.example.com", "type": "hsts_missing",
                     "severity": "medium", "count": 2,
                     "first_seen_time": (NOW - timedelta(days=45)).isoformat(),
                     "last_seen_time": (NOW - timedelta(days=5)).isoformat()},
                ],
            },
        ))

        result.complete()
        return result
```

- [ ] **Step 3: Register connector and normalizer in main()**

```python
connectors.register("securityscorecard", DemoSecurityScorecardConnector)
connectors.create(ConnectorConfig(
    name="demo-securityscorecard", source_type=SourceType.GRC, provider="securityscorecard",
))
normalizers.register(SecurityScorecardNormalizer())
```

- [ ] **Step 4: Run and verify**

```bash
python scripts/demo_seed.py
warlock vendors
```

Expected: 5 vendors with risk scores. CloudBackup Pro and Acme Staffing should show as high-risk.

---

### Task 4: Add DemoConfluenceConnector (Policy documents)

**Files:**
- Modify: `scripts/demo_seed.py`

Adds 7 policy documents as Confluence pages flowing through `ConfluenceNormalizer`, producing `grc_document` findings that `policy-coverage` consumes.

- [ ] **Step 1: Add import**

```python
from warlock.normalizers.confluence import ConfluenceNormalizer
```

- [ ] **Step 2: Add DemoConfluenceConnector class**

```python
class DemoConfluenceConnector(BaseConnector):
    """Simulates Confluence GRC document library — 7 policies."""

    def validate(self):
        return []

    def health_check(self):
        return True

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.name,
            source="confluence",
            source_type=SourceType.GRC,
            provider="confluence",
        )

        result.events.append(RawEventData(
            source="confluence", source_type=SourceType.GRC, provider="confluence",
            event_type="confluence_pages",
            raw_data={
                "space_key": "SEC",
                "pages": [
                    {
                        "id": "100001", "title": "Access Control Policy",
                        "status": "current", "authorId": "usr-grace-kim",
                        "version": {"createdAt": (NOW - timedelta(days=45)).isoformat()},
                    },
                    {
                        "id": "100002", "title": "Incident Response Plan",
                        "status": "current", "authorId": "usr-eve-nakamura",
                        "version": {"createdAt": (NOW - timedelta(days=30)).isoformat()},
                    },
                    {
                        "id": "100003", "title": "Change Management Policy",
                        "status": "current", "authorId": "usr-frank-torres",
                        "version": {"createdAt": (NOW - timedelta(days=90)).isoformat()},
                    },
                    {
                        "id": "100004", "title": "Data Classification Standard",
                        "status": "current", "authorId": "usr-grace-kim",
                        "version": {"createdAt": (NOW - timedelta(days=120)).isoformat()},
                    },
                    {
                        "id": "100005", "title": "Business Continuity Plan",
                        "status": "current", "authorId": "usr-hassan-ali",
                        "version": {"createdAt": (NOW - timedelta(days=200)).isoformat()},
                    },
                    {
                        "id": "100006", "title": "Encryption and Key Management Policy",
                        "status": "current", "authorId": "usr-eve-nakamura",
                        "version": {"createdAt": (NOW - timedelta(days=60)).isoformat()},
                    },
                    {
                        "id": "100007", "title": "Acceptable Use Policy",
                        "status": "current", "authorId": "usr-grace-kim",
                        "version": {"createdAt": (NOW - timedelta(days=150)).isoformat()},
                    },
                ],
            },
        ))

        result.complete()
        return result
```

- [ ] **Step 3: Register connector and normalizer in main()**

```python
connectors.register("confluence", DemoConfluenceConnector)
connectors.create(ConnectorConfig(
    name="demo-confluence", source_type=SourceType.GRC, provider="confluence",
))
normalizers.register(ConfluenceNormalizer())
```

- [ ] **Step 4: Run and verify**

```bash
python scripts/demo_seed.py
warlock policy-coverage -f iso_27001
```

Expected: Non-zero policy coverage (7 policies mapped to controls).

---

### Task 5: Add data silo findings to DemoAWSConnector

**Files:**
- Modify: `scripts/demo_seed.py`

Extends the existing AWS connector with storage resource findings that `data-silos-discover` consumes. Also adds a GitHub and SharePoint event via new mini-connectors.

- [ ] **Step 1: Add new RawEventData events to DemoAWSConnector.collect()**

After the existing S3 buckets event, add these additional events to the AWS connector:

```python
        # RDS instances for data silo discovery
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="rds_instances",
            raw_data={
                "service": "rds", "method": "describe_db_instances",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"DBInstances": [
                    {
                        "DBInstanceIdentifier": "prod-customers",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:912345678012:db/prod-customers",
                        "Engine": "postgres",
                        "StorageEncrypted": True,
                        "AutoMinorVersionUpgrade": True,
                        "BackupRetentionPeriod": 30,
                    },
                ]},
            },
        ))

        # Redshift clusters
        result.events.append(RawEventData(
            source="aws", source_type=SourceType.CLOUD, provider="aws",
            event_type="redshift_clusters",
            raw_data={
                "service": "redshift", "method": "describe_clusters",
                "region": "us-east-1", "account_id": "912345678012",
                "response": {"Clusters": [
                    {
                        "ClusterIdentifier": "analytics-warehouse",
                        "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
                        "Encrypted": True,
                        "AutomatedSnapshotRetentionPeriod": 0,
                    },
                ]},
            },
        ))
```

- [ ] **Step 2: Verify the AWS normalizer handles RDS and Redshift events**

Check if the AWS normalizer produces findings with `resource_type` matching `rds_instance` or `redshift_cluster`. If not, the generic normalizer will handle them. Either way, `data-silos-discover` needs the Finding `resource_type` to match its `STORAGE_RESOURCE_TYPES` mapping.

Run:
```bash
python scripts/demo_seed.py
warlock data-silos-discover
warlock data-silos
```

If data silos are empty, we'll need to seed DataSilo records directly in Task 8.

---

### Task 6: Add post-pipeline seeding — System Profiles

**Files:**
- Modify: `scripts/demo_seed.py`

After the pipeline runs, seed 5 system profiles using `SystemProfileManager` or direct model creation.

- [ ] **Step 1: Add imports at top of file**

```python
from warlock.db.models import SystemProfile, LegalHold, Issue
```

- [ ] **Step 2: Add seed_systems() function before main()**

```python
def seed_systems(session):
    """Create 5 system profiles representing Acme Corp's authorization boundary."""
    systems = [
        SystemProfile(
            name="Acme Production Platform",
            acronym="APP",
            description="Primary SaaS platform serving customer workloads. Hosts APIs, web app, and background workers on AWS.",
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="high",
            overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27001"],
            connector_scope=["aws", "crowdstrike", "okta"],
            cloud_accounts=[{"provider": "aws", "account_id": "912345678012", "regions": ["us-east-1", "us-west-2"]}],
            network_boundaries=[{"cidr": "10.0.0.0/16", "description": "Production VPC"}],
            system_owner="Frank Torres",
            system_owner_email="frank.torres@acme.com",
            isso="Eve Nakamura",
            isso_email="eve.nakamura@acme.com",
            authorizing_official="Hassan Ali",
            ao_email="hassan.ali@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=180),
            authorization_expiry=NOW + timedelta(days=185),
            deployment_model="cloud",
            service_model="IaaS",
        ),
        SystemProfile(
            name="Customer Data Warehouse",
            acronym="CDW",
            description="Analytics and reporting platform. Ingests customer telemetry into Redshift for BI dashboards.",
            confidentiality_impact="high",
            integrity_impact="high",
            availability_impact="moderate",
            overall_impact="high",
            frameworks=["nist_800_53", "soc2", "iso_27701"],
            connector_scope=["aws"],
            cloud_accounts=[{"provider": "aws", "account_id": "912345678012", "regions": ["us-east-1"]}],
            system_owner="Carol Park",
            system_owner_email="carol.park@acme.com",
            authorization_status="in_process",
            deployment_model="cloud",
            service_model="IaaS",
        ),
        SystemProfile(
            name="Corporate IT",
            acronym="CIT",
            description="Internal IT services: identity, email, endpoint management, and collaboration tools.",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="moderate",
            overall_impact="moderate",
            frameworks=["iso_27001", "soc2"],
            connector_scope=["okta", "crowdstrike"],
            system_owner="Bob Martinez",
            system_owner_email="bob.martinez@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=365),
            authorization_expiry=NOW + timedelta(days=1),
            deployment_model="hybrid",
            service_model="SaaS",
        ),
        SystemProfile(
            name="AI/ML Analytics Platform",
            acronym="AIML",
            description="Machine learning model training and inference. Processes anonymized customer data for product insights.",
            confidentiality_impact="moderate",
            integrity_impact="moderate",
            availability_impact="low",
            overall_impact="moderate",
            frameworks=["iso_42001", "nist_800_53"],
            connector_scope=["aws"],
            system_owner="Alice Chen",
            system_owner_email="alice.chen@acme.com",
            authorization_status="not_authorized",
            deployment_model="cloud",
            service_model="PaaS",
        ),
        SystemProfile(
            name="Development and Staging",
            acronym="DEV",
            description="Non-production environments for development, testing, and staging. No real customer data.",
            confidentiality_impact="low",
            integrity_impact="low",
            availability_impact="low",
            overall_impact="low",
            frameworks=["soc2"],
            connector_scope=["aws", "crowdstrike"],
            system_owner="Frank Torres",
            system_owner_email="frank.torres@acme.com",
            authorization_status="authorized",
            authorization_date=NOW - timedelta(days=90),
            authorization_expiry=NOW + timedelta(days=275),
            deployment_model="cloud",
            service_model="IaaS",
        ),
    ]

    for system in systems:
        session.add(system)
    session.commit()
    return len(systems)
```

- [ ] **Step 3: Call seed_systems() from main() after pipeline step**

After `[4/4] Done!` section and before the results printout, add a new section:

```python
    # 5. Post-pipeline seeding
    print("\n[5/8] Seeding system profiles...")
    with get_session() as session:
        n = seed_systems(session)
        print(f"       Created {n} system profiles")
```

- [ ] **Step 4: Run and verify**

```bash
python scripts/demo_seed.py
warlock systems
```

Expected: 5 system profiles with mixed authorization statuses.

---

### Task 7: Add post-pipeline seeding — Personnel sync, Issues, Questionnaires

**Files:**
- Modify: `scripts/demo_seed.py`

Calls existing workflow managers to populate personnel, issues, and questionnaires from the pipeline data.

- [ ] **Step 1: Add imports**

```python
from warlock.workflows.personnel import PersonnelManager
from warlock.workflows.issues import IssueManager
from warlock.workflows.questionnaires import QuestionnaireManager
from warlock.workflows.data_silos import DataSiloManager
```

- [ ] **Step 2: Add seed_personnel() function**

```python
def seed_personnel(session):
    """Sync personnel from HR (Workday) + IdP (Okta) + training (KnowBe4) findings."""
    manager = PersonnelManager()
    hr = manager.sync_from_hr(session)
    idp = manager.sync_from_idp(session)
    training = manager.sync_from_training(session)
    return {
        "hr": hr,
        "idp": idp,
        "training": training,
        "total": session.query(Personnel).count(),
    }
```

Add `Personnel` to the existing `from warlock.db.models import ...` line.

- [ ] **Step 3: Add seed_questionnaires() function**

```python
def seed_questionnaires(session):
    """Seed templates + create 2 vendor questionnaire instances with responses."""
    manager = QuestionnaireManager()
    templates = manager.seed_default_templates(session)

    sig_template = next((t for t in templates if "sig" in t.name.lower()), None)
    ddq_template = next((t for t in templates if "ddq" in t.name.lower()), None)

    created = []

    if sig_template:
        q = manager.create_questionnaire(
            session, template_id=sig_template.id,
            vendor_name="Stripe",
            vendor_email="security@stripe.com",
            due_days=30, created_by="eve.nakamura@acme.com",
        )
        # Answer most SIG Lite questions positively for Stripe
        responses = {}
        for question in sig_template.questions[:18]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "yes", "notes": "Verified via SOC 2 Type II report"}
            elif question.get("response_type") == "rating":
                responses[qid] = {"answer": "4", "notes": "Strong controls in place"}
            else:
                responses[qid] = {"answer": "Implemented and documented", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        manager.score_responses(session, q.id)
        created.append(f"Stripe (SIG Lite, completed)")

    if ddq_template:
        q = manager.create_questionnaire(
            session, template_id=ddq_template.id,
            vendor_name="CloudBackup Pro",
            vendor_email="compliance@cloudbackuppro.example.com",
            due_days=30, created_by="eve.nakamura@acme.com",
        )
        # Partially answer DDQ for CloudBackup Pro
        responses = {}
        for question in ddq_template.questions[:4]:
            qid = question["id"]
            if question.get("response_type") == "yes_no":
                responses[qid] = {"answer": "no", "notes": "In progress"}
            else:
                responses[qid] = {"answer": "Under review", "notes": ""}
        manager.submit_bulk_responses(session, q.id, responses)
        created.append(f"CloudBackup Pro (DDQ, in_progress)")

    return {"templates": len(templates), "questionnaires": created}
```

- [ ] **Step 4: Add seed_issues() function**

```python
def seed_issues(session):
    """Auto-create issues from non-compliant results + add 3 manual issues."""
    manager = IssueManager()
    auto = manager.auto_create_from_results(session)

    # Manual issues
    manual_issues = [
        Issue(
            title="Vendor risk acceptance needed: CloudBackup Pro",
            description="CloudBackup Pro scored 45/100 on SecurityScorecard. Evaluate alternatives or accept risk with compensating controls.",
            framework="soc2",
            control_id="CC9.1",
            status="open",
            priority="high",
            assigned_to="eve.nakamura@acme.com",
            due_date=NOW + timedelta(days=14),
            source="manual",
            tags=["vendor-risk", "third-party"],
            created_by="hassan.ali@acme.com",
        ),
        Issue(
            title="Overdue access review for Product department",
            description="Product department has not completed quarterly access review. Last review was 120+ days ago.",
            framework="iso_27001",
            control_id="A.5.18",
            status="assigned",
            priority="medium",
            assigned_to="hassan.ali@acme.com",
            assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=7),
            due_date=NOW + timedelta(days=7),
            source="manual",
            tags=["access-review", "overdue"],
            created_by="eve.nakamura@acme.com",
        ),
        Issue(
            title="Policy gap: No Audit Logging Policy documented",
            description="Policy coverage check shows AU-family controls have no mapped policy document. Need to draft and publish.",
            framework="nist_800_53",
            control_id="AU-1",
            status="in_progress",
            priority="medium",
            assigned_to="grace.kim@acme.com",
            assigned_by="eve.nakamura@acme.com",
            assigned_at=NOW - timedelta(days=14),
            due_date=NOW + timedelta(days=21),
            remediation_plan="Draft AU policy in Confluence, route through legal review, publish to SEC space.",
            source="manual",
            tags=["policy-gap", "documentation"],
            created_by="eve.nakamura@acme.com",
        ),
    ]
    for issue in manual_issues:
        session.add(issue)
    session.commit()

    return {"auto_created": len(auto), "manual": len(manual_issues)}
```

- [ ] **Step 5: Add seed_data_silos() function**

```python
def seed_data_silos(session):
    """Discover data silos from storage findings, then supplement with direct records."""
    manager = DataSiloManager()
    result = manager.discover_from_findings(session)

    # If discovery didn't find enough, add directly
    from warlock.db.models import DataSilo

    direct_silos = [
        DataSilo(
            name="acme-prod-data",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-prod-data",
            data_classification="confidential",
            contains_pii=True,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=365,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"],
        ),
        DataSilo(
            name="acme-public-assets",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-public-assets",
            data_classification="public",
            contains_pii=False,
            encrypted_at_rest=False,
            encrypted_in_transit=True,
            access_logging_enabled=False,
            backup_enabled=False,
            owner="Bob Martinez",
            team="DevOps",
            applicable_frameworks=[],
        ),
        DataSilo(
            name="acme-logs",
            silo_type="s3_bucket",
            provider="aws",
            location="arn:aws:s3:::acme-logs",
            data_classification="internal",
            contains_pii=False,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=1095,
            owner="Bob Martinez",
            team="DevOps",
            applicable_frameworks=["nist_800_53"],
        ),
        DataSilo(
            name="prod-customers",
            silo_type="rds_database",
            provider="aws",
            location="arn:aws:rds:us-east-1:912345678012:db/prod-customers",
            data_classification="restricted",
            contains_pii=True,
            contains_pci=True,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            retention_days=30,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["pci_dss", "soc2", "iso_27001"],
        ),
        DataSilo(
            name="analytics-warehouse",
            silo_type="redshift",
            provider="aws",
            location="arn:aws:redshift:us-east-1:912345678012:namespace/analytics-warehouse",
            data_classification="confidential",
            contains_pii=True,
            contains_phi=True,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=False,
            backup_enabled=False,
            owner="Carol Park",
            team="Finance",
            applicable_frameworks=["hipaa", "soc2"],
        ),
        DataSilo(
            name="eng-wiki",
            silo_type="sharepoint_site",
            provider="sharepoint",
            location="https://acme.sharepoint.com/sites/engineering",
            data_classification="internal",
            contains_pii=False,
            encrypted_at_rest=False,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["iso_27001"],
        ),
        DataSilo(
            name="acme-app",
            silo_type="github_repo",
            provider="github",
            location="https://github.com/acme-corp/acme-app",
            data_classification="confidential",
            contains_credentials=True,
            encrypted_at_rest=True,
            encrypted_in_transit=True,
            access_logging_enabled=True,
            backup_enabled=True,
            owner="Frank Torres",
            team="Engineering",
            applicable_frameworks=["soc2", "iso_27001"],
            scan_findings=[
                {"field_name": ".env.production", "data_type": "credential", "confidence": 0.95},
                {"field_name": "config/secrets.yml", "data_type": "credential", "confidence": 0.88},
            ],
            sensitive_field_count=2,
            scan_status="completed",
            last_scan_date=NOW - timedelta(days=7),
        ),
    ]

    # Only add silos that don't already exist (from discover)
    existing_names = {s.name for s in session.query(DataSilo.name).all()}
    added = 0
    for silo in direct_silos:
        if silo.name not in existing_names:
            session.add(silo)
            added += 1
    session.commit()

    return {"discovered": result.get("created", 0), "direct": added}
```

- [ ] **Step 6: Add seed_legal_holds() function**

```python
def seed_legal_holds(session):
    """Create 2 legal holds — one active (indefinite), one expired."""
    holds = [
        LegalHold(
            reason="FTC investigation — preserve all authentication and access logs",
            start_date=NOW - timedelta(days=60),
            end_date=None,  # Indefinite
            created_by="grace.kim@acme.com",
            is_active=True,
        ),
        LegalHold(
            reason="Q3 2025 SOC 2 audit evidence preservation",
            start_date=NOW - timedelta(days=120),
            end_date=NOW - timedelta(days=30),
            created_by="eve.nakamura@acme.com",
            is_active=False,
        ),
    ]
    for hold in holds:
        session.add(hold)
    session.commit()
    return len(holds)
```

- [ ] **Step 7: Wire all post-pipeline seeding into main()**

Replace the current `[4/4] Done!` section with an expanded set of steps:

```python
    print("[4/9] Done with pipeline!\n")

    print("[5/9] Seeding system profiles...")
    with get_session() as session:
        n = seed_systems(session)
        print(f"       Created {n} system profiles")

    print("[6/9] Syncing personnel from HR + IdP + training...")
    with get_session() as session:
        p = seed_personnel(session)
        print(f"       Personnel: {p['total']} records synced")

    print("[7/9] Seeding questionnaire templates and instances...")
    with get_session() as session:
        q = seed_questionnaires(session)
        print(f"       Templates: {q['templates']}, Questionnaires: {len(q['questionnaires'])}")

    print("[8/9] Seeding data silos, legal holds, and issues...")
    with get_session() as session:
        ds = seed_data_silos(session)
        print(f"       Data silos: {ds['discovered']} discovered + {ds['direct']} direct")
        lh = seed_legal_holds(session)
        print(f"       Legal holds: {lh}")
        issues = seed_issues(session)
        print(f"       Issues: {issues['auto_created']} auto + {issues['manual']} manual")

    print("[9/9] Seed complete!\n")
```

Update the step numbering in the earlier pipeline steps to match (1/9, 2/9, 3/9).

- [ ] **Step 8: Update the "Try these commands" section at the end**

```python
    print("=" * 60)
    print("  Try these commands:")
    print("=" * 60)
    print("  warlock results                    # control results")
    print("  warlock results --status non_compliant")
    print("  warlock coverage                   # compliance summary")
    print("  warlock findings                   # all findings")
    print("  warlock sources                    # registered sources")
    print("  warlock systems                    # system profiles")
    print("  warlock personnel                  # HR/IdP/training records")
    print("  warlock vendors                    # vendor risk scores")
    print("  warlock questionnaires             # vendor questionnaires")
    print("  warlock data-silos                 # storage inventory")
    print("  warlock retention                  # retention & legal holds")
    print("  warlock issues                     # compliance issues")
    print("  warlock policy-coverage -f iso_27001  # policy gaps")
    print("  warlock risk -f nist_800_53        # FAIR risk analysis")
    print("  warlock oscal                      # export OSCAL JSON")
    print("=" * 60)
```

---

### Task 8: Integration test — run full seed and verify all commands

**Files:**
- None (validation only)

- [ ] **Step 1: Delete existing database and run fresh seed**

```bash
cd /Users/jsn/Coding/GitHub/warlock/warlock
rm -f warlock.db
source .venv/bin/activate
python scripts/demo_seed.py
```

Expected: All 9 steps complete without errors.

- [ ] **Step 2: Verify every command returns non-empty output**

```bash
warlock results | head -5
warlock results --status non_compliant | head -5
warlock coverage | head -10
warlock findings | head -5
warlock sources
warlock systems
warlock personnel
warlock vendors
warlock questionnaires
warlock data-silos
warlock retention
warlock issues | head -10
warlock policy-coverage -f iso_27001
warlock risk -f nist_800_53
warlock oscal | head -20
```

Each command should return data, not empty tables or "No data" messages.

- [ ] **Step 3: Fix any command that returns empty output**

If any command returns no data, trace the data path:
1. Check findings exist for the expected `resource_type`
2. Check the workflow manager processes those findings correctly
3. Adjust connector data or add direct seeding as needed

- [ ] **Step 4: Commit**

```bash
git add scripts/demo_seed.py
git commit -m "feat: fully populate demo seed with all warlock features

Add mock connectors for Workday (HR), KnowBe4 (training),
SecurityScorecard (vendor risk), and Confluence (policy docs).
Post-pipeline seeding for system profiles, personnel sync,
questionnaires, data silos, legal holds, and issues.

Every warlock CLI command now returns rich demo data."
```
