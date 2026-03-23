#!/usr/bin/env python3
"""Rich, realistic data generation for the Warlock demo seed.

Generates data that looks like a real mid-size SaaS company (Acme Corp):
500 employees, multi-cloud (AWS/Azure/GCP), SOC 2 + HIPAA + ISO 27001
certified, using dozens of SaaS tools.

All functions take a ``count`` parameter and use a fixed random seed (42)
for reproducibility.  Returns lists of dicts ready for ``raw_data`` in
``RawEventData``.

Usage::

    from scripts.demo_data import generate_users, generate_vulnerabilities
    users = generate_users(100)
    vulns = generate_vulnerabilities(500)
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Fixed seed for reproducibility
# ---------------------------------------------------------------------------

_RNG = random.Random(42)

# ---------------------------------------------------------------------------
# Company profile constants
# ---------------------------------------------------------------------------

COMPANY = "Acme Corp"
DOMAINS = ["acme.com", "acme.io", "acme-internal.net"]
DEPARTMENTS = [
    "Engineering",
    "Security",
    "IT",
    "Finance",
    "Legal",
    "HR",
    "Sales",
    "Marketing",
    "Product",
    "Support",
]
TEAMS = [
    "Platform",
    "Frontend",
    "Backend",
    "DevOps",
    "SRE",
    "Data",
    "ML",
    "Mobile",
    "QA",
    "Infra",
]
CLOUD_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

# ---------------------------------------------------------------------------
# Name pools (realistic first/last names)
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "Alice",
    "Bob",
    "Carlos",
    "Diana",
    "Elena",
    "Faisal",
    "Grace",
    "Hassan",
    "Ingrid",
    "James",
    "Karen",
    "Liam",
    "Mei",
    "Noah",
    "Olivia",
    "Priya",
    "Quinn",
    "Raj",
    "Sofia",
    "Tomas",
    "Uma",
    "Victor",
    "Wendy",
    "Xavier",
    "Yuki",
    "Zara",
    "Aaron",
    "Beth",
    "Chen",
    "David",
    "Emily",
    "Frank",
    "Gita",
    "Henry",
    "Isla",
    "Juan",
    "Kate",
    "Leo",
    "Maria",
    "Nadia",
    "Oscar",
    "Paula",
    "Ravi",
    "Sarah",
    "Tyler",
    "Vera",
    "Will",
    "Xena",
    "Yolanda",
    "Zach",
    "Aisha",
    "Brian",
    "Carmen",
    "Derek",
    "Eva",
    "Felix",
    "Hannah",
    "Ian",
    "Julia",
    "Kevin",
    "Luna",
    "Mike",
    "Nina",
    "Owen",
    "Petra",
    "Ryan",
    "Sana",
    "Tariq",
    "Ursula",
    "Vikram",
    "Zoe",
]

LAST_NAMES = [
    "Chen",
    "Martinez",
    "Johnson",
    "Patel",
    "Williams",
    "Kim",
    "O'Brien",
    "Garcia",
    "Nakamura",
    "Singh",
    "Anderson",
    "Kowalski",
    "Ali",
    "Thompson",
    "Rodriguez",
    "Lee",
    "Johansson",
    "Gupta",
    "Mueller",
    "Santos",
    "Hernandez",
    "Yamamoto",
    "Brown",
    "Ivanova",
    "Costa",
    "Park",
    "Wilson",
    "Khan",
    "Larsson",
    "Okafor",
    "Taylor",
    "Zhao",
    "Davis",
    "Schmidt",
    "Clark",
    "Reyes",
    "Mitchell",
    "Turner",
    "Wright",
    "Lopez",
    "Hill",
    "Green",
    "Adams",
    "Baker",
    "Nelson",
    "Carter",
    "Phillips",
    "Evans",
    "Torres",
    "Collins",
]

# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_TITLES = {
    "Engineering": [
        "Software Engineer",
        "Senior Software Engineer",
        "Staff Engineer",
        "Principal Engineer",
        "Engineering Manager",
    ],
    "Security": [
        "Security Engineer",
        "Senior Security Engineer",
        "Security Analyst",
        "Security Architect",
        "CISO",
    ],
    "IT": [
        "IT Administrator",
        "Systems Engineer",
        "IT Manager",
        "Help Desk Analyst",
        "Network Engineer",
    ],
    "Finance": [
        "Financial Analyst",
        "Controller",
        "CFO",
        "Accounts Payable Specialist",
        "FP&A Manager",
    ],
    "Legal": [
        "General Counsel",
        "Corporate Attorney",
        "Paralegal",
        "Privacy Counsel",
        "Compliance Officer",
    ],
    "HR": [
        "HR Manager",
        "Recruiter",
        "HR Business Partner",
        "People Operations Lead",
        "Benefits Coordinator",
    ],
    "Sales": [
        "Account Executive",
        "Sales Manager",
        "SDR",
        "VP Sales",
        "Solutions Engineer",
    ],
    "Marketing": [
        "Marketing Manager",
        "Content Strategist",
        "Growth Lead",
        "Product Marketing Manager",
        "Brand Designer",
    ],
    "Product": [
        "Product Manager",
        "Senior Product Manager",
        "VP Product",
        "UX Designer",
        "Product Analyst",
    ],
    "Support": [
        "Support Engineer",
        "Support Manager",
        "Customer Success Manager",
        "Technical Account Manager",
        "Support Lead",
    ],
}

_LOCATIONS = [
    ("San Francisco", "US"),
    ("New York", "US"),
    ("Austin", "US"),
    ("Seattle", "US"),
    ("Denver", "US"),
    ("Chicago", "US"),
    ("London", "GB"),
    ("Berlin", "DE"),
    ("Dublin", "IE"),
    ("Toronto", "CA"),
    ("Bangalore", "IN"),
    ("Singapore", "SG"),
    ("Sydney", "AU"),
    ("Tokyo", "JP"),
    ("Sao Paulo", "BR"),
]

_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15",
    "okta-sdk-python/2.9.0 python/3.12.3",
]

_IAM_GROUPS = [
    ("engineering", "Engineering team members", "security"),
    ("security-team", "Security team members", "security"),
    ("it-admins", "IT administrators", "security"),
    ("developers", "All developers", "security"),
    ("finance", "Finance department", "security"),
    ("hr-team", "Human resources", "security"),
    ("executives", "C-suite and VPs", "security"),
    ("aws-admins", "AWS account administrators", "security"),
    ("gcp-admins", "GCP project administrators", "security"),
    ("azure-admins", "Azure subscription administrators", "security"),
    ("read-only", "Read-only access", "security"),
    ("on-call", "On-call rotation members", "security"),
    ("contractors", "External contractors", "security"),
    ("pci-zone", "PCI DSS scoped personnel", "security"),
    ("hipaa-users", "HIPAA data access", "security"),
    ("all-employees", "All Acme Corp employees", "distribution"),
    ("eng-announce", "Engineering announcements", "distribution"),
    ("security-alerts", "Security alert notifications", "distribution"),
    ("leadership", "Leadership team", "distribution"),
    ("office-sf", "San Francisco office", "distribution"),
]

_DEVICE_MODELS = {
    "macOS": ["MacBook Pro 16-inch", "MacBook Air M3", "Mac Mini M2", "iMac 24-inch"],
    "Windows": ["ThinkPad X1 Carbon Gen 11", "Dell XPS 15", "Surface Pro 9", "HP EliteBook 860"],
    "Linux": ["ThinkPad T14s", "Dell Precision 5570", "System76 Lemur Pro"],
    "iOS": ["iPhone 15 Pro", "iPhone 15", "iPad Pro 12.9"],
    "Android": ["Pixel 8 Pro", "Samsung Galaxy S24", "Samsung Galaxy Tab S9"],
}

_OS_VERSIONS = {
    "macOS": ["14.4.1", "14.3.1", "14.2", "13.6.4", "12.7.3"],
    "Windows": ["10.0.22631", "10.0.22621", "10.0.19045", "10.0.17763"],
    "Linux": ["Ubuntu 24.04", "Ubuntu 22.04", "Fedora 40", "Debian 12"],
    "iOS": ["17.4.1", "17.3.1", "16.7.5"],
    "Android": ["14", "13", "12"],
}

_INSTANCE_TYPES = {
    "aws": [
        "t3.micro",
        "t3.medium",
        "t3.large",
        "m6i.xlarge",
        "m6i.2xlarge",
        "c6i.xlarge",
        "r6i.xlarge",
        "r6i.2xlarge",
        "m7g.medium",
        "c7g.large",
    ],
    "azure": [
        "Standard_B2s",
        "Standard_D2s_v5",
        "Standard_D4s_v5",
        "Standard_E2s_v5",
        "Standard_F4s_v2",
    ],
    "gcp": [
        "e2-micro",
        "e2-medium",
        "e2-standard-2",
        "e2-standard-4",
        "n2-standard-2",
        "n2-standard-4",
        "c2-standard-4",
    ],
}

_AZURE_REGIONS = ["eastus", "westus2", "westeurope", "southeastasia"]
_GCP_REGIONS = ["us-central1", "us-east1", "europe-west1", "asia-southeast1"]

_VPC_IDS = [
    "vpc-0a1b2c3d4e5f6a7b8",
    "vpc-1b2c3d4e5f6a7b8c9",
    "vpc-2c3d4e5f6a7b8c9d0",
    "vpc-3d4e5f6a7b8c9d0e1",
]

_VULN_TITLES = [
    ("Remote Code Execution in OpenSSL", "critical", 9.8, "openssl", "3.1.3", "3.1.4"),
    (
        "SQL Injection in PostgreSQL JDBC Driver",
        "critical",
        9.1,
        "postgresql-jdbc",
        "42.6.0",
        "42.6.1",
    ),
    ("Prototype Pollution in lodash", "high", 7.5, "lodash", "4.17.20", "4.17.21"),
    ("Denial of Service in Express.js", "high", 7.1, "express", "4.18.1", "4.18.2"),
    ("Cross-Site Scripting in React DOM", "high", 6.8, "react-dom", "18.2.0", "18.3.1"),
    ("Path Traversal in Spring Framework", "high", 7.4, "spring-core", "6.1.3", "6.1.4"),
    ("Insecure Deserialization in Jackson", "high", 7.2, "jackson-databind", "2.15.1", "2.15.3"),
    ("Buffer Overflow in zlib", "medium", 6.5, "zlib", "1.2.13", "1.3.1"),
    ("Information Disclosure in nginx", "medium", 5.3, "nginx", "1.24.0", "1.25.4"),
    ("Improper Input Validation in Django", "medium", 5.8, "django", "4.2.7", "4.2.9"),
    ("XML External Entity in lxml", "medium", 5.5, "lxml", "4.9.3", "5.1.0"),
    ("Regular Expression DoS in ua-parser-js", "medium", 5.3, "ua-parser-js", "1.0.35", "1.0.37"),
    ("Weak Cipher Suite in cryptography", "medium", 4.7, "cryptography", "41.0.4", "42.0.0"),
    ("Open Redirect in urllib3", "low", 3.7, "urllib3", "2.0.6", "2.1.0"),
    ("Missing HTTP Security Headers", "low", 3.1, "helmet", "7.0.0", "7.1.0"),
    ("Verbose Error Messages in FastAPI", "low", 2.5, "fastapi", "0.104.0", "0.109.0"),
    ("Cookie Without Secure Flag", "low", 2.8, "flask", "3.0.0", "3.0.1"),
    ("Cleartext Transmission of Sensitive Data", "medium", 5.9, "requests", "2.31.0", "2.32.0"),
    ("Server-Side Request Forgery in httpx", "high", 7.7, "httpx", "0.25.0", "0.27.0"),
    ("Privilege Escalation in sudo", "critical", 8.8, "sudo", "1.9.14", "1.9.15p5"),
]

_SAST_RULES = [
    ("sql-injection-raw-query", "SQL Injection via raw query", "critical", "sql_injection"),
    ("hardcoded-aws-key", "Hardcoded AWS Access Key", "critical", "hardcoded_secret"),
    ("hardcoded-private-key", "Hardcoded RSA Private Key", "critical", "hardcoded_secret"),
    ("hardcoded-jwt-secret", "Hardcoded JWT Secret", "high", "hardcoded_secret"),
    ("xss-unescaped-output", "Unescaped user input in template", "high", "xss"),
    ("xss-inner-html-assignment", "Unsafe innerHTML assignment", "high", "xss"),
    ("path-traversal-user-input", "Path traversal via user input", "high", "path_traversal"),
    ("insecure-random", "Use of Math.random() for security", "medium", "insecure_random"),
    ("missing-csrf-token", "Missing CSRF token on form", "medium", "csrf"),
    ("open-redirect", "Open redirect via user-controlled URL", "medium", "open_redirect"),
    ("weak-hash-md5", "Use of MD5 for hashing", "medium", "weak_crypto"),
    ("weak-hash-sha1", "Use of SHA-1 for signatures", "medium", "weak_crypto"),
    ("insecure-tls-version", "TLS 1.0/1.1 still enabled", "medium", "insecure_tls"),
    ("debug-mode-enabled", "Debug mode enabled in production", "low", "misconfiguration"),
    ("verbose-error-messages", "Stack traces exposed to users", "low", "info_disclosure"),
    ("unused-import", "Unused import statement", "low", "code_quality"),
]

_MITRE_TECHNIQUES = [
    ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    ("T1078", "Valid Accounts", "Persistence"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Persistence"),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
    ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted", "Exfiltration"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    ("T1098", "Account Manipulation", "Persistence"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1005", "Data from Local System", "Collection"),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    ("T1055", "Process Injection", "Defense Evasion"),
]

_VENDOR_NAMES = [
    ("Stripe", "payment_processing"),
    ("Datadog", "observability"),
    ("Snowflake", "data_warehouse"),
    ("Salesforce", "crm"),
    ("Zendesk", "support"),
    ("Twilio", "communications"),
    ("SendGrid", "email"),
    ("PagerDuty", "incident_management"),
    ("LaunchDarkly", "feature_flags"),
    ("Segment", "analytics"),
    ("Auth0", "identity"),
    ("MongoDB Atlas", "database"),
    ("Cloudflare", "cdn_security"),
    ("GitHub", "source_control"),
    ("Slack", "collaboration"),
    ("Notion", "documentation"),
    ("Figma", "design"),
    ("Linear", "project_management"),
    ("Vercel", "hosting"),
    ("AWS", "cloud_infrastructure"),
    ("GCP", "cloud_infrastructure"),
    ("Azure", "cloud_infrastructure"),
    ("DocuSign", "document_signing"),
    ("Greenhouse", "recruiting"),
    ("BambooHR", "hris"),
    ("Netsuite", "erp"),
    ("Expensify", "expense_management"),
    ("Brex", "corporate_card"),
    ("Vanta", "compliance"),
    ("Drata", "compliance"),
    ("CrowdStrike", "endpoint_security"),
    ("SentinelOne", "endpoint_security"),
    ("Snyk", "application_security"),
    ("Wiz", "cloud_security"),
    ("Zscaler", "network_security"),
    ("Proofpoint", "email_security"),
    ("KnowBe4", "security_training"),
    ("1Password", "password_management"),
    ("HashiCorp Vault", "secrets_management"),
    ("Terraform Cloud", "infrastructure_as_code"),
]

_POLICY_TITLES = [
    ("Information Security Policy", "security"),
    ("Acceptable Use Policy", "security"),
    ("Data Classification Policy", "security"),
    ("Access Control Policy", "security"),
    ("Incident Response Plan", "incident_response"),
    ("Business Continuity Plan", "business_continuity"),
    ("Disaster Recovery Plan", "business_continuity"),
    ("Privacy Policy", "privacy"),
    ("Data Retention Policy", "privacy"),
    ("Data Processing Agreement Template", "privacy"),
    ("Change Management Policy", "operations"),
    ("Vulnerability Management Policy", "security"),
    ("Encryption Policy", "security"),
    ("Remote Work Policy", "acceptable_use"),
    ("Third-Party Risk Management Policy", "vendor_management"),
    ("Asset Management Policy", "operations"),
    ("Network Security Policy", "security"),
    ("Logging and Monitoring Policy", "security"),
    ("Physical Security Policy", "physical_security"),
    ("Code of Conduct", "hr"),
    ("Whistleblower Policy", "hr"),
    ("Anti-Bribery and Corruption Policy", "legal"),
    ("Software Development Lifecycle Policy", "security"),
    ("Backup and Recovery Policy", "operations"),
    ("Mobile Device Management Policy", "security"),
]

_TRAINING_COURSES = [
    ("Security Awareness Fundamentals 2026", "security_awareness"),
    ("Phishing Identification and Reporting", "phishing"),
    ("HIPAA Privacy and Security", "compliance"),
    ("PCI DSS Cardholder Data Handling", "compliance"),
    ("GDPR Data Protection Basics", "privacy"),
    ("Secure Coding Practices", "security_awareness"),
    ("Social Engineering Defense", "phishing"),
    ("Incident Response Procedures", "security_awareness"),
    ("Password Hygiene and MFA", "security_awareness"),
    ("Data Classification and Handling", "compliance"),
]

_SUSPICIOUS_DOMAINS = [
    "malware-c2-server.xyz",
    "phish-acme-login.com",
    "data-exfil-drop.net",
    "cryptominer-pool.ru",
    "evil-redirect.info",
]

_REPOS = [
    "acme/api-gateway",
    "acme/web-app",
    "acme/mobile-ios",
    "acme/mobile-android",
    "acme/billing-service",
    "acme/auth-service",
    "acme/data-pipeline",
    "acme/ml-platform",
    "acme/infrastructure",
    "acme/docs",
    "acme/notification-service",
    "acme/search-service",
    "acme/admin-dashboard",
    "acme/sdk-python",
    "acme/sdk-node",
]

_LANGUAGES = ["python", "typescript", "go", "java", "rust", "javascript", "kotlin", "swift"]

_BASE_IMAGES = [
    "python:3.12-slim",
    "node:20-alpine",
    "golang:1.22-bookworm",
    "eclipse-temurin:21-jre-alpine",
    "rust:1.77-slim",
    "nginx:1.25-alpine",
    "redis:7-alpine",
    "postgres:16-alpine",
    "ubuntu:24.04",
]

_CONTAINER_REPOS = [
    "acme/api-gateway",
    "acme/web-frontend",
    "acme/billing-service",
    "acme/auth-service",
    "acme/data-pipeline",
    "acme/ml-worker",
    "acme/notification-service",
    "acme/search-service",
    "acme/admin-dashboard",
    "acme/cron-scheduler",
]

_IAC_RESOURCE_TYPES = [
    "aws_s3_bucket",
    "aws_security_group",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_rds_instance",
    "aws_lambda_function",
    "aws_cloudwatch_log_group",
    "azurerm_storage_account",
    "azurerm_network_security_group",
    "azurerm_key_vault",
    "google_compute_instance",
    "google_storage_bucket",
    "google_project_iam_binding",
]

_IAC_RULES = [
    (
        "s3-bucket-public-access",
        "S3 bucket allows public access",
        "critical",
        "aws_s3_bucket",
        "Ensure S3 buckets are not publicly accessible",
    ),
    (
        "sg-unrestricted-ingress",
        "Security group allows unrestricted ingress",
        "high",
        "aws_security_group",
        "Restrict ingress to specific CIDR ranges",
    ),
    (
        "iam-admin-policy",
        "IAM policy with full admin access",
        "high",
        "aws_iam_policy",
        "Follow least privilege principle",
    ),
    (
        "rds-unencrypted",
        "RDS instance without encryption",
        "high",
        "aws_rds_instance",
        "Enable encryption at rest for RDS",
    ),
    (
        "rds-public-access",
        "RDS instance publicly accessible",
        "critical",
        "aws_rds_instance",
        "Disable public access for RDS instances",
    ),
    (
        "lambda-no-vpc",
        "Lambda function not in VPC",
        "medium",
        "aws_lambda_function",
        "Place Lambda functions in VPC",
    ),
    (
        "cloudwatch-no-retention",
        "CloudWatch log group without retention",
        "medium",
        "aws_cloudwatch_log_group",
        "Set retention period for log groups",
    ),
    (
        "storage-no-https",
        "Azure storage allows HTTP",
        "high",
        "azurerm_storage_account",
        "Enforce HTTPS-only access",
    ),
    (
        "nsg-any-inbound",
        "NSG allows any inbound traffic",
        "high",
        "azurerm_network_security_group",
        "Restrict NSG inbound rules",
    ),
    (
        "keyvault-no-purge",
        "Key Vault without purge protection",
        "medium",
        "azurerm_key_vault",
        "Enable purge protection for Key Vault",
    ),
    (
        "gce-default-sa",
        "GCE instance uses default service account",
        "medium",
        "google_compute_instance",
        "Use dedicated service account",
    ),
    (
        "gcs-uniform-access",
        "GCS bucket without uniform access",
        "medium",
        "google_storage_bucket",
        "Enable uniform bucket-level access",
    ),
    (
        "iam-binding-all-users",
        "IAM binding grants access to allUsers",
        "critical",
        "google_project_iam_binding",
        "Remove allUsers from IAM bindings",
    ),
]

_CERTIFICATIONS = [
    "SOC 2 Type II",
    "ISO 27001",
    "ISO 27701",
    "HIPAA BAA",
    "PCI DSS Level 1",
    "FedRAMP Moderate",
    "GDPR Compliant",
    "CSA STAR Level 2",
    "SOC 1 Type II",
]

_INCIDENT_TYPES = [
    ("malware", "Malware Detected on Engineering Workstation"),
    ("phishing", "Executive Targeted Phishing Campaign"),
    ("phishing", "Credential Harvesting via Fake Login Page"),
    ("data_breach", "Unauthorized Access to Customer PII Database"),
    ("unauthorized_access", "Suspicious Login from Unusual Geography"),
    ("unauthorized_access", "Former Employee Account Still Active"),
    ("unauthorized_access", "Brute Force Attack on VPN Gateway"),
    ("dos", "DDoS Attack on Public API"),
    ("malware", "Ransomware Attempt Blocked by EDR"),
    ("data_breach", "S3 Bucket Temporarily Exposed to Public"),
    ("unauthorized_access", "Privilege Escalation Attempt Detected"),
    ("phishing", "Business Email Compromise Attempt"),
    ("malware", "Cryptominer Detected in Container Workload"),
    ("unauthorized_access", "API Key Leaked in Public Repository"),
    ("dos", "Application Layer DoS on Payment Endpoint"),
]

_NOW = datetime.now(timezone.utc)


# ===================================================================
# Utility functions
# ===================================================================


def random_ip() -> str:
    """Return a random plausible IPv4 address."""
    first = _RNG.choice([10, 172, 192, 34, 52, 54, 104, 203])
    if first == 10:
        return f"10.{_RNG.randint(0, 255)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"
    if first == 172:
        return f"172.{_RNG.randint(16, 31)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"
    if first == 192:
        return f"192.168.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"
    return f"{first}.{_RNG.randint(0, 255)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"


def random_public_ip() -> str:
    """Return a random public IPv4 address."""
    first = _RNG.choice([34, 52, 54, 104, 203, 13, 20, 35, 44, 99])
    return f"{first}.{_RNG.randint(0, 255)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"


def random_private_ip() -> str:
    """Return a random RFC 1918 IPv4 address."""
    return f"10.{_RNG.randint(0, 255)}.{_RNG.randint(0, 255)}.{_RNG.randint(1, 254)}"


def random_timestamp(days_back: int = 90) -> str:
    """Return a random ISO-format UTC timestamp within the last ``days_back`` days."""
    delta = timedelta(
        seconds=_RNG.randint(0, days_back * 86400),
    )
    ts = _NOW - delta
    return ts.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def random_timestamp_dt(days_back: int = 90) -> datetime:
    """Return a random timezone-aware datetime within the last ``days_back`` days."""
    delta = timedelta(seconds=_RNG.randint(0, days_back * 86400))
    return _NOW - delta


def random_name() -> tuple[str, str]:
    """Return a random (first_name, last_name) pair."""
    return _RNG.choice(FIRST_NAMES), _RNG.choice(LAST_NAMES)


def random_email(first: str, last: str) -> str:
    """Return a plausible email for the given name at the primary domain."""
    clean_last = last.lower().replace("'", "")
    return f"{first.lower()}.{clean_last}@{DOMAINS[0]}"


def random_id(prefix: str = "") -> str:
    """Return a UUID-based ID with optional prefix."""
    uid = uuid.UUID(int=_RNG.getrandbits(128), version=4)
    if prefix:
        return f"{prefix}-{uid.hex[:12]}"
    return uid.hex[:16]


def random_hostname() -> str:
    """Return a realistic internal hostname."""
    env = _RNG.choice(["prod", "staging", "dev"])
    svc = _RNG.choice(["web", "api", "worker", "db", "cache", "queue", "proxy", "bastion"])
    num = _RNG.randint(1, 20)
    region = _RNG.choice(["use1", "usw2", "euw1", "apse1"])
    return f"{env}-{svc}-{num:02d}.{region}.acme-internal.net"


def random_cve() -> str:
    """Return a realistic CVE ID."""
    year = _RNG.choice([2024, 2024, 2024, 2025, 2025, 2023])
    num = _RNG.randint(1000, 52000)
    return f"CVE-{year}-{num}"


def random_serial() -> str:
    """Return a device-like serial number."""
    return "".join(_RNG.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=12))


# ===================================================================
# Identity & Access
# ===================================================================


def generate_users(count: int = 100) -> list[dict]:
    """Generate IAM user records (Okta / JumpCloud / Auth0 / Entra ID style).

    ~15% without MFA, ~5% suspended, ~3% deprovisioned.
    """
    users = []
    used_emails: set[str] = set()
    for _ in range(count):
        first, last = random_name()
        email = random_email(first, last)
        # Ensure unique emails
        while email in used_emails:
            first, last = random_name()
            email = random_email(first, last)
        used_emails.add(email)

        dept = _RNG.choice(DEPARTMENTS)
        roll = _RNG.random()
        if roll < 0.03:
            status = "deprovisioned"
        elif roll < 0.08:
            status = "suspended"
        else:
            status = "active"

        has_mfa = _RNG.random() > 0.15
        mfa_type = _RNG.choice(["push", "totp", "webauthn"]) if has_mfa else None

        groups = _RNG.sample(
            [g[0] for g in _IAM_GROUPS],
            k=_RNG.randint(1, 4),
        )
        if dept.lower() in [g[0] for g in _IAM_GROUPS]:
            groups.append(dept.lower())

        users.append(
            {
                "user_id": random_id("usr"),
                "username": f"{first.lower()}.{last.lower().replace(chr(39), '')}",
                "email": email,
                "first_name": first,
                "last_name": last,
                "status": status,
                "is_enrolled_mfa": has_mfa,
                "mfa_type": mfa_type,
                "department": dept,
                "role": _RNG.choice(_TITLES.get(dept, ["Employee"])),
                "last_login": random_timestamp(30) if status == "active" else random_timestamp(180),
                "created_at": random_timestamp(365),
                "groups": groups,
            }
        )
    return users


def generate_groups(count: int = 20) -> list[dict]:
    """Generate IAM groups."""
    groups = []
    for i in range(min(count, len(_IAM_GROUPS))):
        name, desc, gtype = _IAM_GROUPS[i]
        groups.append(
            {
                "group_id": random_id("grp"),
                "name": name,
                "description": desc,
                "member_count": _RNG.randint(3, 80),
                "type": gtype,
            }
        )
    # Fill remaining with generated groups if count > predefined
    for i in range(len(_IAM_GROUPS), count):
        groups.append(
            {
                "group_id": random_id("grp"),
                "name": f"custom-group-{i}",
                "description": f"Custom group {i}",
                "member_count": _RNG.randint(2, 20),
                "type": _RNG.choice(["security", "distribution"]),
            }
        )
    return groups


def generate_auth_logs(count: int = 500) -> list[dict]:
    """Generate authentication event logs over 90 days.

    ~10% failures, ~1% fraud.
    """
    logs = []
    for _ in range(count):
        first, last = random_name()
        email = random_email(first, last)
        username = f"{first.lower()}.{last.lower().replace(chr(39), '')}"
        location = _RNG.choice(_LOCATIONS)

        roll = _RNG.random()
        if roll < 0.01:
            result = "fraud"
            reason = _RNG.choice(
                [
                    "Impossible travel detected",
                    "Known malicious IP",
                    "Credential stuffing pattern",
                ]
            )
        elif roll < 0.11:
            result = "failure"
            reason = _RNG.choice(
                [
                    "Invalid password",
                    "Account locked",
                    "MFA challenge failed",
                    "Expired session token",
                    "IP not in allowlist",
                ]
            )
        else:
            result = "success"
            reason = None

        logs.append(
            {
                "event_id": random_id("evt"),
                "timestamp": random_timestamp(90),
                "username": username,
                "email": email,
                "result": result,
                "reason": reason,
                "ip_address": random_public_ip() if result == "fraud" else random_ip(),
                "user_agent": _RNG.choice(_USER_AGENTS),
                "location": {"city": location[0], "country": location[1]},
                "factor": _RNG.choice(["push", "totp", "sms", "password", "webauthn"]),
            }
        )
    return logs


# ===================================================================
# Endpoints & Devices
# ===================================================================


def generate_devices(count: int = 200) -> list[dict]:
    """Generate managed device inventory.

    ~8% unencrypted, ~5% no firewall, ~3% outdated OS.
    """
    devices = []
    for i in range(count):
        platform = _RNG.choice(
            ["macOS", "macOS", "macOS", "Windows", "Windows", "Linux", "iOS", "Android"]
        )
        model = _RNG.choice(_DEVICE_MODELS[platform])
        os_version = _RNG.choice(_OS_VERSIONS[platform])

        is_encrypted = _RNG.random() > 0.08
        firewall_enabled = _RNG.random() > 0.05
        screen_lock = _RNG.random() > 0.02
        # Outdated OS: use the last version in the list
        if _RNG.random() < 0.03:
            os_version = _OS_VERSIONS[platform][-1]

        is_compliant = is_encrypted and firewall_enabled and screen_lock

        first, last = random_name()
        devices.append(
            {
                "device_id": random_id("dev"),
                "device_name": f"{first.lower()}-{platform.lower()}-{i:03d}",
                "serial_number": random_serial(),
                "platform": platform,
                "os_version": os_version,
                "is_encrypted": is_encrypted,
                "firewall_enabled": firewall_enabled,
                "screen_lock": screen_lock,
                "is_compliant": is_compliant,
                "last_seen": random_timestamp(7),
                "user_email": random_email(first, last),
                "model": model,
            }
        )
    return devices


def generate_endpoints_edr(count: int = 150) -> list[dict]:
    """Generate EDR agent inventory.

    ~5% offline, ~3% in detect-only mode.
    """
    endpoints = []
    for _ in range(count):
        platform = _RNG.choice(["macOS", "macOS", "Windows", "Windows", "Windows", "Linux"])
        os_version = _RNG.choice(_OS_VERSIONS[platform])

        roll = _RNG.random()
        if roll < 0.02:
            status = "degraded"
        elif roll < 0.07:
            status = "offline"
        else:
            status = "online"

        prevention_mode = "detect" if _RNG.random() < 0.03 else "prevent"

        endpoints.append(
            {
                "agent_id": random_id("agt"),
                "hostname": random_hostname(),
                "platform": platform,
                "os_version": os_version,
                "agent_version": f"7.{_RNG.randint(12, 18)}.{_RNG.randint(0, 9)}.{_RNG.randint(1000, 9999)}",
                "last_seen": random_timestamp(3) if status == "online" else random_timestamp(30),
                "status": status,
                "policy_name": _RNG.choice(
                    ["Standard Protection", "High Security", "Server Workload", "Developer"]
                ),
                "prevention_mode": prevention_mode,
                "sensor_version": f"6.{_RNG.randint(50, 58)}.{_RNG.randint(0, 9)}",
                "group_name": _RNG.choice(
                    ["Production Servers", "Workstations", "Engineering", "Executives"]
                ),
            }
        )
    return endpoints


# ===================================================================
# Cloud Infrastructure
# ===================================================================


def generate_cloud_instances(count: int = 300) -> list[dict]:
    """Generate cloud compute instances.

    ~10% with public IPs, ~5% unencrypted volumes, ~8% stopped.
    """
    instances = []
    for i in range(count):
        cloud = _RNG.choice(["aws", "aws", "aws", "azure", "azure", "gcp"])

        if cloud == "aws":
            region = _RNG.choice(CLOUD_REGIONS)
            instance_type = _RNG.choice(_INSTANCE_TYPES["aws"])
            instance_id = f"i-{_RNG.randbytes(8).hex()[:17]}"
        elif cloud == "azure":
            region = _RNG.choice(_AZURE_REGIONS)
            instance_type = _RNG.choice(_INSTANCE_TYPES["azure"])
            instance_id = (
                f"/subscriptions/{random_id()}/resourceGroups/rg-prod"
                f"/providers/Microsoft.Compute/virtualMachines/vm-{i:03d}"
            )
        else:
            region = _RNG.choice(_GCP_REGIONS)
            instance_type = _RNG.choice(_INSTANCE_TYPES["gcp"])
            instance_id = f"projects/acme-prod/zones/{region}-a/instances/gce-{i:03d}"

        state = "stopped" if _RNG.random() < 0.08 else "running"
        has_public_ip = _RNG.random() < 0.10
        encrypted = _RNG.random() > 0.05

        env_tag = _RNG.choice(["production", "production", "staging", "development"])
        svc_tag = _RNG.choice(
            ["api", "web", "worker", "scheduler", "ml", "database", "cache", "proxy"]
        )

        instances.append(
            {
                "instance_id": instance_id,
                "name": f"{env_tag}-{svc_tag}-{i:03d}",
                "cloud": cloud,
                "region": region,
                "instance_type": instance_type,
                "state": state,
                "public_ip": random_public_ip() if has_public_ip else None,
                "private_ip": random_private_ip(),
                "vpc_id": _RNG.choice(_VPC_IDS),
                "security_groups": [
                    f"sg-{_RNG.randbytes(4).hex()}" for _ in range(_RNG.randint(1, 3))
                ],
                "tags": {
                    "Environment": env_tag,
                    "Service": svc_tag,
                    "Team": _RNG.choice(TEAMS),
                    "ManagedBy": _RNG.choice(["terraform", "terraform", "manual"]),
                },
                "launched_at": random_timestamp(180),
                "encrypted_volumes": encrypted,
            }
        )
    return instances


def generate_iam_policies(count: int = 50) -> list[dict]:
    """Generate cloud IAM policies.

    ~10% with admin access, ~15% unused >90 days.
    """
    policy_names = [
        "ReadOnlyAccess",
        "PowerUserAccess",
        "AdministratorAccess",
        "S3FullAccess",
        "EC2FullAccess",
        "LambdaExecutionRole",
        "DatabaseAdmin",
        "BillingViewAccess",
        "SecurityAudit",
        "CloudWatchReadOnly",
        "SecretsManagerReadWrite",
        "ECSTaskExecution",
        "CodeDeployRole",
        "CICDPipelineRole",
        "DataScienceNotebook",
        "KMSKeyAdmin",
        "VPCFlowLogWriter",
        "GuardDutyReader",
        "SSOPermissionSet-Dev",
        "SSOPermissionSet-Admin",
        "SSOPermissionSet-ReadOnly",
        "SSOPermissionSet-Security",
        "CrossAccountAudit",
        "BackupOperator",
        "NetworkAdmin",
    ]
    policies = []
    for i in range(count):
        name = policy_names[i % len(policy_names)] if i < len(policy_names) else f"CustomPolicy-{i}"
        cloud = _RNG.choice(["aws", "aws", "azure", "gcp"])
        has_admin = _RNG.random() < 0.10
        unused = _RNG.random() < 0.15

        permissions = (
            ["*"]
            if has_admin
            else _RNG.sample(
                [
                    "s3:GetObject",
                    "s3:PutObject",
                    "ec2:DescribeInstances",
                    "iam:ListUsers",
                    "logs:GetLogEvents",
                    "lambda:InvokeFunction",
                    "secretsmanager:GetSecretValue",
                    "kms:Decrypt",
                    "rds:DescribeDBInstances",
                    "dynamodb:Query",
                    "sqs:SendMessage",
                    "sns:Publish",
                ],
                k=_RNG.randint(2, 6),
            )
        )

        policies.append(
            {
                "policy_id": random_id("pol"),
                "name": name,
                "cloud": cloud,
                "type": _RNG.choice(["managed", "managed", "custom", "inline"]),
                "attached_to": [random_id("role") for _ in range(_RNG.randint(0, 5))],
                "permissions": permissions,
                "has_admin_access": has_admin,
                "last_used": random_timestamp(180) if unused else random_timestamp(14),
                "created_at": random_timestamp(365),
            }
        )
    return policies


def generate_security_groups(count: int = 100) -> list[dict]:
    """Generate network security groups.

    ~5% with 0.0.0.0/0 on non-standard ports.
    """
    sgs = []
    for i in range(count):
        cloud = _RNG.choice(["aws", "aws", "azure", "gcp"])
        is_overly_permissive = _RNG.random() < 0.05

        inbound_rules = []
        # Standard HTTPS rule
        inbound_rules.append(
            {
                "port": 443,
                "protocol": "tcp",
                "source": _RNG.choice(["0.0.0.0/0", "10.0.0.0/8"]),
            }
        )
        # HTTP rule
        if _RNG.random() < 0.6:
            inbound_rules.append(
                {
                    "port": 80,
                    "protocol": "tcp",
                    "source": _RNG.choice(["0.0.0.0/0", "10.0.0.0/8"]),
                }
            )
        # Dangerous rule
        if is_overly_permissive:
            bad_port = _RNG.choice([22, 3389, 5432, 3306, 6379, 27017])
            inbound_rules.append(
                {
                    "port": bad_port,
                    "protocol": "tcp",
                    "source": "0.0.0.0/0",
                }
            )

        outbound_rules = [{"port": 0, "protocol": "all", "destination": "0.0.0.0/0"}]

        sgs.append(
            {
                "sg_id": f"sg-{_RNG.randbytes(6).hex()[:12]}",
                "name": f"sg-{_RNG.choice(['web', 'api', 'db', 'cache', 'internal', 'bastion', 'vpn', 'monitoring'])}-{i:03d}",
                "cloud": cloud,
                "vpc_id": _RNG.choice(_VPC_IDS),
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules,
            }
        )
    return sgs


def generate_storage_buckets(count: int = 80) -> list[dict]:
    """Generate cloud storage buckets.

    ~3% public, ~8% no encryption, ~15% no versioning.
    """
    purposes = [
        "logs",
        "backups",
        "data-lake",
        "static-assets",
        "uploads",
        "ml-models",
        "terraform-state",
        "artifacts",
        "reports",
        "exports",
    ]
    buckets = []
    for i in range(count):
        cloud = _RNG.choice(["aws", "aws", "azure", "gcp"])
        purpose = _RNG.choice(purposes)
        env = _RNG.choice(["prod", "staging", "dev"])

        is_public = _RNG.random() < 0.03
        if cloud == "aws":
            enc = (
                _RNG.choice(["sse-s3", "sse-s3", "sse-kms", "cmk"])
                if _RNG.random() > 0.08
                else "none"
            )
        elif cloud == "azure":
            enc = _RNG.choice(["sse-managed", "sse-cmk"]) if _RNG.random() > 0.08 else "none"
        else:
            enc = _RNG.choice(["google-managed", "cmek"]) if _RNG.random() > 0.08 else "none"

        versioning = _RNG.random() > 0.15
        logging = _RNG.random() > 0.20

        region = (
            _RNG.choice(CLOUD_REGIONS)
            if cloud == "aws"
            else (_RNG.choice(_AZURE_REGIONS) if cloud == "azure" else _RNG.choice(_GCP_REGIONS))
        )

        buckets.append(
            {
                "bucket_id": random_id("bkt"),
                "name": f"acme-{env}-{purpose}-{i:03d}",
                "cloud": cloud,
                "region": region,
                "is_public": is_public,
                "encryption": enc,
                "versioning": versioning,
                "logging": logging,
                "object_count": _RNG.randint(10, 500000),
                "size_gb": round(_RNG.uniform(0.01, 2000.0), 2),
                "created_at": random_timestamp(365),
            }
        )
    return buckets


# ===================================================================
# Vulnerabilities & Code Security
# ===================================================================


def generate_vulnerabilities(count: int = 500) -> list[dict]:
    """Generate vulnerability scanner findings.

    Distribution: 5% critical, 15% high, 40% medium, 40% low. 60% open.
    """
    vulns = []
    for _ in range(count):
        roll = _RNG.random()
        if roll < 0.05:
            sev_filter = "critical"
        elif roll < 0.20:
            sev_filter = "high"
        elif roll < 0.60:
            sev_filter = "medium"
        else:
            sev_filter = "low"

        # Pick a matching template or generate
        matching = [v for v in _VULN_TITLES if v[1] == sev_filter]
        if matching:
            title, severity, cvss, pkg, installed, fixed = _RNG.choice(matching)
        else:
            title = f"Vulnerability in component-{_RNG.randint(1, 999)}"
            severity = sev_filter
            cvss = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5}[sev_filter]
            pkg = f"lib-{_RNG.randint(1, 50)}"
            installed = f"{_RNG.randint(1, 5)}.{_RNG.randint(0, 20)}.{_RNG.randint(0, 10)}"
            fixed = f"{_RNG.randint(1, 5)}.{_RNG.randint(0, 20)}.{_RNG.randint(0, 10)}"

        # Add slight variation to CVSS
        cvss = round(min(10.0, max(0.0, cvss + _RNG.uniform(-0.3, 0.3))), 1)

        status_roll = _RNG.random()
        if status_roll < 0.60:
            status = "open"
        elif status_roll < 0.90:
            status = "fixed"
        else:
            status = "accepted"

        resource = random_hostname()
        first_seen = random_timestamp_dt(90)
        last_seen = first_seen + timedelta(days=_RNG.randint(0, 30))

        vulns.append(
            {
                "vuln_id": random_id("vuln"),
                "cve_id": random_cve(),
                "title": title,
                "description": f"{title}. Affects {pkg} versions prior to {fixed}.",
                "severity": severity,
                "cvss_score": cvss,
                "affected_resource": resource,
                "resource_type": _RNG.choice(["server", "container", "workstation", "serverless"]),
                "first_seen": first_seen.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "last_seen": last_seen.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "status": status,
                "fix_available": _RNG.random() > 0.15,
                "package_name": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
            }
        )
    return vulns


def generate_code_findings(count: int = 200) -> list[dict]:
    """Generate SAST / secret scanning findings.

    ~10% critical (secrets), ~20% high.
    """
    findings = []
    for _ in range(count):
        rule_id, title, severity, category = _RNG.choice(_SAST_RULES)
        repo = _RNG.choice(_REPOS)
        lang = _RNG.choice(_LANGUAGES)
        ext = {
            "python": ".py",
            "typescript": ".ts",
            "go": ".go",
            "java": ".java",
            "rust": ".rs",
            "javascript": ".js",
            "kotlin": ".kt",
            "swift": ".swift",
        }[lang]

        path_parts = _RNG.choice(["src", "lib", "app", "pkg", "internal", "services"])
        filename = _RNG.choice(
            [
                "auth",
                "api",
                "handler",
                "service",
                "util",
                "controller",
                "middleware",
                "db",
                "config",
                "routes",
            ]
        )

        status_roll = _RNG.random()
        if status_roll < 0.55:
            status = "open"
        elif status_roll < 0.85:
            status = "fixed"
        else:
            status = "ignored"

        first, last = random_name()
        findings.append(
            {
                "finding_id": random_id("sast"),
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "file_path": f"{path_parts}/{filename}{ext}",
                "line_number": _RNG.randint(1, 500),
                "snippet": f"// Finding: {title} on line {_RNG.randint(1, 500)}",
                "language": lang,
                "category": category,
                "status": status,
                "repository": repo,
                "branch": _RNG.choice(["main", "main", "develop", f"feature/{random_id()[:8]}"]),
                "author": random_email(first, last),
                "detected_at": random_timestamp(60),
            }
        )
    return findings


def generate_container_images(count: int = 100) -> list[dict]:
    """Generate container image scan results.

    ~15% with critical vulns.
    """
    images = []
    for _ in range(count):
        repo = _RNG.choice(_CONTAINER_REPOS)
        tag = _RNG.choice(
            [
                "latest",
                "v1.0.0",
                "v1.1.0",
                "v1.2.3",
                "v2.0.0-rc1",
                f"sha-{_RNG.randbytes(3).hex()}",
                "stable",
                "canary",
            ]
        )
        base = _RNG.choice(_BASE_IMAGES)

        has_critical = _RNG.random() < 0.15
        critical = _RNG.randint(1, 5) if has_critical else 0
        high = _RNG.randint(0, 12)
        medium = _RNG.randint(0, 25)
        low = _RNG.randint(0, 40)

        images.append(
            {
                "image_id": f"sha256:{_RNG.randbytes(16).hex()}",
                "repository": repo,
                "tag": tag,
                "digest": f"sha256:{_RNG.randbytes(32).hex()}",
                "os": _RNG.choice(["linux", "linux", "linux"]),
                "architecture": _RNG.choice(["amd64", "amd64", "arm64"]),
                "total_vulns": critical + high + medium + low,
                "critical_vulns": critical,
                "high_vulns": high,
                "medium_vulns": medium,
                "low_vulns": low,
                "base_image": base,
                "last_scanned": random_timestamp(7),
                "size_mb": _RNG.randint(30, 900),
                "created_at": random_timestamp(60),
            }
        )
    return images


# ===================================================================
# HR & People
# ===================================================================


def generate_employees(count: int = 500) -> list[dict]:
    """Generate HR employee records.

    ~5% terminated, ~3% on leave, ~10% contractors.
    """
    employees = []
    used_emails: set[str] = set()
    managers: list[str] = []

    for i in range(count):
        first, last = random_name()
        email = random_email(first, last)
        while email in used_emails:
            first, last = random_name()
            email = random_email(first, last)
        used_emails.add(email)

        dept = _RNG.choice(DEPARTMENTS)
        location = _RNG.choice(_LOCATIONS)
        is_contractor = _RNG.random() < 0.10

        roll = _RNG.random()
        if roll < 0.05:
            status = "terminated"
        elif roll < 0.08:
            status = "leave"
        else:
            status = "active"

        start_date = random_timestamp_dt(730)  # up to 2 years ago
        termination_date = None
        if status == "terminated":
            termination_date = (start_date + timedelta(days=_RNG.randint(60, 600))).strftime(
                "%Y-%m-%d"
            )

        title = _RNG.choice(_TITLES.get(dept, ["Employee"]))
        # First 20 people can be managers
        if i < 20:
            managers.append(email)
        manager_email = _RNG.choice(managers) if managers and i > 0 else None

        employees.append(
            {
                "employee_id": f"EMP-{i + 1:04d}",
                "first_name": first,
                "last_name": last,
                "email": email,
                "department": dept,
                "title": title,
                "manager_email": manager_email,
                "start_date": start_date.strftime("%Y-%m-%d"),
                "termination_date": termination_date,
                "status": status,
                "location": {"city": location[0], "country": location[1]},
                "is_contractor": is_contractor,
            }
        )
    return employees


def generate_training_records(count: int = 500) -> list[dict]:
    """Generate security training records.

    ~15% overdue, ~5% failed.
    """
    records = []
    for _ in range(count):
        first, last = random_name()
        email = random_email(first, last)
        course, category = _RNG.choice(_TRAINING_COURSES)

        roll = _RNG.random()
        if roll < 0.15:
            status = "overdue"
        elif roll < 0.20:
            status = "in_progress"
        else:
            status = "completed"

        assigned = random_timestamp_dt(90)
        passing_score = 80

        if status == "completed":
            completed_at = (assigned + timedelta(days=_RNG.randint(1, 14))).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            score = _RNG.randint(60, 100)
        elif status == "in_progress":
            completed_at = None
            score = None
        else:
            completed_at = None
            score = None

        records.append(
            {
                "record_id": random_id("trn"),
                "employee_email": email,
                "course_name": course,
                "category": category,
                "status": status,
                "assigned_at": assigned.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "completed_at": completed_at,
                "score": score,
                "passing_score": passing_score,
            }
        )
    return records


# ===================================================================
# Incidents & Alerts
# ===================================================================


def generate_security_alerts(count: int = 300) -> list[dict]:
    """Generate SIEM / EDR alerts.

    ~5% critical, ~15% high, ~40% resolved.
    """
    alerts = []
    for _ in range(count):
        technique_id, technique_name, tactic = _RNG.choice(_MITRE_TECHNIQUES)

        roll = _RNG.random()
        if roll < 0.05:
            severity = "critical"
        elif roll < 0.20:
            severity = "high"
        elif roll < 0.55:
            severity = "medium"
        elif roll < 0.85:
            severity = "low"
        else:
            severity = "info"

        status_roll = _RNG.random()
        if status_roll < 0.25:
            status = "new"
        elif status_roll < 0.45:
            status = "investigating"
        elif status_roll < 0.85:
            status = "resolved"
        else:
            status = "false_positive"

        source = _RNG.choice(["crowdstrike", "sentinel", "splunk", "guardduty", "datadog"])
        detected = random_timestamp_dt(60)
        resolved_at = None
        if status in ("resolved", "false_positive"):
            resolved_at = (detected + timedelta(hours=_RNG.randint(1, 72))).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )

        alerts.append(
            {
                "alert_id": random_id("alt"),
                "title": f"{technique_name} - {_RNG.choice(['Suspicious', 'Detected', 'Attempted', 'Blocked'])} Activity",
                "severity": severity,
                "source": source,
                "status": status,
                "technique": technique_id,
                "tactic": tactic,
                "description": f"Detection of {technique_name.lower()} activity on host.",
                "affected_host": random_hostname(),
                "detected_at": detected.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "resolved_at": resolved_at,
            }
        )
    return alerts


def generate_incidents(count: int = 30) -> list[dict]:
    """Generate security incidents. Mix of open and closed over 90 days."""
    incidents = []
    for i in range(count):
        inc_type, title = _RNG.choice(_INCIDENT_TYPES)

        severity = _RNG.choice(["critical", "high", "high", "medium", "medium", "low"])
        status_roll = _RNG.random()
        if status_roll < 0.10:
            status = "open"
        elif status_roll < 0.25:
            status = "investigating"
        elif status_roll < 0.35:
            status = "contained"
        elif status_roll < 0.75:
            status = "resolved"
        else:
            status = "closed"

        reported = random_timestamp_dt(90)
        contained_at = None
        resolved_at = None
        if status in ("contained", "resolved", "closed"):
            contained_at = (reported + timedelta(hours=_RNG.randint(1, 24))).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
        if status in ("resolved", "closed"):
            resolved_at = (reported + timedelta(hours=_RNG.randint(24, 168))).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )

        first, last = random_name()
        affected_count = _RNG.randint(1, 5)

        root_causes = [
            "Unpatched vulnerability exploited",
            "Employee clicked phishing link",
            "Misconfigured S3 bucket ACL",
            "Weak password on service account",
            "Missing MFA on VPN",
            "Insider threat - disgruntled employee",
            "Third-party vendor compromise",
            "Expired SSL certificate allowed MITM",
        ]

        incidents.append(
            {
                "incident_id": f"INC-{_NOW.year}-{i + 1:04d}",
                "title": title,
                "severity": severity,
                "status": status,
                "type": inc_type,
                "reported_at": reported.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "contained_at": contained_at,
                "resolved_at": resolved_at,
                "assignee_email": random_email(first, last),
                "affected_systems": [random_hostname() for _ in range(affected_count)],
                "root_cause": _RNG.choice(root_causes)
                if status in ("resolved", "closed")
                else None,
                "lessons_learned": (
                    f"Post-incident review completed. Action items tracked in INC-{_NOW.year}-{i + 1:04d}-PIR."
                    if status == "closed"
                    else None
                ),
            }
        )
    return incidents


# ===================================================================
# Compliance & GRC
# ===================================================================


def generate_vendor_assessments(count: int = 40) -> list[dict]:
    """Generate vendor risk assessments.

    ~20% below acceptable threshold.
    """
    assessments = []
    vendors_used: set[str] = set()
    for i in range(count):
        idx = i % len(_VENDOR_NAMES)
        vendor_name, category = _VENDOR_NAMES[idx]
        if vendor_name in vendors_used:
            vendor_name = f"{vendor_name} ({_RNG.choice(['EMEA', 'APAC', 'US'])} Instance)"
        vendors_used.add(vendor_name)

        risk_score = _RNG.randint(20, 100)

        # Letter rating from score
        if risk_score >= 90:
            rating = "A"
        elif risk_score >= 80:
            rating = "B"
        elif risk_score >= 70:
            rating = "C"
        elif risk_score >= 60:
            rating = "D"
        else:
            rating = "F"

        num_certs = _RNG.randint(0, 5)
        certs = _RNG.sample(_CERTIFICATIONS, k=min(num_certs, len(_CERTIFICATIONS)))

        contract_end = (_NOW + timedelta(days=_RNG.randint(-30, 365))).strftime("%Y-%m-%d")

        assessments.append(
            {
                "vendor_id": random_id("vnd"),
                "vendor_name": vendor_name,
                "category": category,
                "rating": rating,
                "risk_score": risk_score,
                "last_assessed": random_timestamp(180),
                "certifications": certs,
                "data_access_level": _RNG.choice(["none", "limited", "limited", "full"]),
                "contract_end": contract_end,
                "sla_compliance": _RNG.random() > 0.12,
            }
        )
    return assessments


def generate_policy_documents(count: int = 25) -> list[dict]:
    """Generate internal policy documents.

    ~20% overdue for review.
    """
    policies = []
    for i in range(min(count, len(_POLICY_TITLES))):
        title, category = _POLICY_TITLES[i]
        first, last = random_name()
        owner = random_email(first, last)

        approved = random_timestamp_dt(400)
        review_due = approved + timedelta(days=365)
        is_overdue = review_due < _NOW
        last_reviewed = (approved + timedelta(days=_RNG.randint(0, 350))).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )

        status_roll = _RNG.random()
        if status_roll < 0.08:
            status = "draft"
        elif status_roll < 0.12:
            status = "retired"
        else:
            status = "active"

        version = f"{_RNG.randint(1, 5)}.{_RNG.randint(0, 9)}"

        policies.append(
            {
                "policy_id": f"POL-{i + 1:03d}",
                "title": title,
                "category": category,
                "version": version,
                "status": status,
                "owner_email": owner,
                "approved_at": approved.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "review_due": review_due.strftime("%Y-%m-%d"),
                "last_reviewed": last_reviewed,
                "is_overdue": is_overdue,
            }
        )
    return policies


# ===================================================================
# Network & Email
# ===================================================================


def generate_dns_queries(count: int = 200) -> list[dict]:
    """Generate DNS / web gateway logs.

    ~5% blocked, ~2% suspicious.
    """
    safe_domains = [
        "google.com",
        "github.com",
        "slack.com",
        "aws.amazon.com",
        "login.microsoftonline.com",
        "api.stripe.com",
        "cdn.jsdelivr.net",
        "registry.npmjs.org",
        "pypi.org",
        "fonts.googleapis.com",
        "sentry.io",
        "datadog-agent.com",
        "okta.com",
        "zoom.us",
        "notion.so",
        "figma.com",
        "linear.app",
        "vercel.app",
    ]
    queries = []
    for _ in range(count):
        roll = _RNG.random()
        if roll < 0.02:
            domain = _RNG.choice(_SUSPICIOUS_DOMAINS)
            category = "suspicious"
            action = "block"
            threat = _RNG.choice(["malware", "phishing", "c2"])
        elif roll < 0.07:
            domain = f"{''.join(_RNG.choices('abcdefghijklmnop', k=8))}.{''.join(_RNG.choices('xyz', k=3))}"
            category = "blocked"
            action = "block"
            threat = _RNG.choice(["malware", "phishing", None])
        else:
            domain = _RNG.choice(safe_domains)
            category = "allowed"
            action = "allow"
            threat = None

        first, last = random_name()
        queries.append(
            {
                "query_id": random_id("dns"),
                "domain": domain,
                "category": category,
                "source_ip": random_private_ip(),
                "user_email": random_email(first, last),
                "timestamp": random_timestamp(30),
                "action": action,
                "threat_type": threat,
            }
        )
    return queries


def generate_email_events(count: int = 300) -> list[dict]:
    """Generate email security events.

    ~10% quarantined/blocked, ~3% phishing.
    """
    external_domains = [
        "gmail.com",
        "outlook.com",
        "partner-co.com",
        "vendor-inc.com",
        "newsletter.example.com",
        "noreply@github.com",
        "support@stripe.com",
    ]
    subjects_normal = [
        "Q4 Planning Meeting",
        "Invoice #INV-2026-4391",
        "Re: Project Update",
        "Weekly Standup Notes",
        "Action Required: Review PR #342",
        "Your order has shipped",
        "New comment on JIRA-1234",
        "Security Advisory: Update Required",
        "Monthly Report - January",
        "Welcome to the team!",
        "PTO Request Approved",
    ]
    subjects_phishing = [
        "Urgent: Verify your account immediately",
        "Your password expires in 24 hours",
        "CEO: Wire transfer needed ASAP",
        "Shared document: Q4 Financials.xlsx",
        "IT: System maintenance - click to confirm",
        "Action Required: Unusual sign-in activity",
    ]

    events = []
    for _ in range(count):
        direction = _RNG.choice(["inbound", "inbound", "inbound", "outbound"])
        first, last = random_name()
        internal_email = random_email(first, last)

        roll = _RNG.random()
        if roll < 0.03:
            # Phishing
            from_addr = (
                f"{''.join(_RNG.choices('abcdefgh', k=6))}"
                f"@{_RNG.choice(['secure-acme.com', 'acme-support.net', 'acme-verify.org'])}"
            )
            to_addr = internal_email
            subject = _RNG.choice(subjects_phishing)
            status = _RNG.choice(["quarantined", "blocked", "delivered"])
            threat = "phishing"
            direction = "inbound"
        elif roll < 0.10:
            # Spam / malware
            from_addr = (
                f"offer@{_RNG.choice(['deals-now.biz', 'promo-blast.info', 'free-stuff.click'])}"
            )
            to_addr = internal_email
            subject = _RNG.choice(
                ["CONGRATULATIONS YOU WON", "Limited time offer!!!", "Free gift card"]
            )
            status = _RNG.choice(["quarantined", "blocked"])
            threat = _RNG.choice(["spam", "malware"])
            direction = "inbound"
        else:
            if direction == "inbound":
                efirst, elast = random_name()
                from_addr = f"{efirst.lower()}@{_RNG.choice(external_domains)}"
                to_addr = internal_email
            else:
                from_addr = internal_email
                efirst, elast = random_name()
                to_addr = f"{efirst.lower()}@{_RNG.choice(external_domains)}"
            subject = _RNG.choice(subjects_normal)
            status = "delivered"
            threat = None

        has_attachment = _RNG.random() < 0.30
        attachment_types = []
        if has_attachment:
            attachment_types = _RNG.sample(
                [".pdf", ".docx", ".xlsx", ".zip", ".png", ".csv"],
                k=_RNG.randint(1, 3),
            )

        events.append(
            {
                "message_id": f"<{random_id()}@{DOMAINS[0]}>",
                "from_address": from_addr,
                "to_address": to_addr,
                "subject": subject,
                "direction": direction,
                "status": status,
                "threat_type": threat,
                "has_attachment": has_attachment,
                "attachment_types": attachment_types,
                "timestamp": random_timestamp(30),
            }
        )
    return events


# ===================================================================
# Infrastructure as Code
# ===================================================================


def generate_terraform_workspaces(count: int = 30) -> list[dict]:
    """Generate Terraform Cloud workspace records.

    ~15% with drift, ~10% auto-apply enabled.
    """
    ws_names = [
        "acme-prod-us-east",
        "acme-prod-eu-west",
        "acme-staging-us-east",
        "acme-dev-us-east",
        "acme-prod-networking",
        "acme-prod-database",
        "acme-prod-kubernetes",
        "acme-prod-monitoring",
        "acme-staging-kubernetes",
        "acme-prod-iam",
        "acme-prod-security",
        "acme-prod-dns",
        "acme-prod-cdn",
        "acme-staging-database",
        "acme-dev-kubernetes",
        "acme-prod-secrets",
        "acme-prod-logging",
        "acme-prod-backup",
        "acme-prod-ml-infra",
        "acme-staging-ml-infra",
        "acme-prod-api-gateway",
        "acme-prod-lambda",
        "acme-staging-lambda",
        "acme-prod-data-lake",
        "acme-dev-sandbox",
        "acme-prod-compliance",
        "acme-prod-waf",
        "acme-staging-waf",
        "acme-prod-container-registry",
        "acme-prod-service-mesh",
    ]
    workspaces = []
    for i in range(count):
        name = ws_names[i] if i < len(ws_names) else f"acme-ws-{i}"
        has_drift = _RNG.random() < 0.15
        auto_apply = _RNG.random() < 0.10

        workspaces.append(
            {
                "workspace_id": random_id("ws"),
                "name": name,
                "organization": "acme-corp",
                "vcs_repo": "acme/infrastructure",
                "current_run_status": (
                    _RNG.choice(["applied", "applied", "planned", "errored"])
                    if not has_drift
                    else "planned"
                ),
                "has_drift": has_drift,
                "last_applied": random_timestamp(30),
                "auto_apply": auto_apply,
                "terraform_version": _RNG.choice(["1.7.4", "1.7.5", "1.8.0", "1.8.2", "1.9.0"]),
                "resource_count": _RNG.randint(5, 200),
                "sentinel_policy_count": _RNG.randint(0, 15),
            }
        )
    return workspaces


def generate_iac_misconfigs(count: int = 100) -> list[dict]:
    """Generate IaC scan results (Checkov / tfsec / Trivy style).

    ~10% critical, ~25% high.
    """
    findings = []
    for _ in range(count):
        rule = _RNG.choice(_IAC_RULES)
        rule_id, title, severity, resource_type, remediation = rule

        # Occasionally override severity for distribution
        roll = _RNG.random()
        if roll < 0.10:
            severity = "critical"
        elif roll < 0.35:
            severity = "high"
        elif roll < 0.70:
            severity = "medium"
        else:
            severity = "low"

        module = _RNG.choice(
            [
                "modules/networking",
                "modules/compute",
                "modules/database",
                "modules/iam",
                "modules/storage",
                "modules/monitoring",
                "environments/prod",
                "environments/staging",
            ]
        )

        findings.append(
            {
                "finding_id": random_id("iac"),
                "rule_id": rule_id,
                "severity": severity,
                "resource_type": resource_type,
                "resource_name": f"{resource_type.split('_')[-1]}-{random_id()[:6]}",
                "file_path": f"{module}/main.tf",
                "line_number": _RNG.randint(1, 300),
                "description": title,
                "remediation": remediation,
            }
        )
    return findings


# ===================================================================
# Convenience: generate everything
# ===================================================================


def generate_all() -> dict[str, list[dict]]:
    """Generate the full dataset (~3,500 items). Returns a dict keyed by category."""
    return {
        "users": generate_users(100),
        "groups": generate_groups(20),
        "auth_logs": generate_auth_logs(500),
        "devices": generate_devices(200),
        "endpoints_edr": generate_endpoints_edr(150),
        "cloud_instances": generate_cloud_instances(300),
        "iam_policies": generate_iam_policies(50),
        "security_groups": generate_security_groups(100),
        "storage_buckets": generate_storage_buckets(80),
        "vulnerabilities": generate_vulnerabilities(500),
        "code_findings": generate_code_findings(200),
        "container_images": generate_container_images(100),
        "employees": generate_employees(500),
        "training_records": generate_training_records(500),
        "security_alerts": generate_security_alerts(300),
        "incidents": generate_incidents(30),
        "vendor_assessments": generate_vendor_assessments(40),
        "policy_documents": generate_policy_documents(25),
        "dns_queries": generate_dns_queries(200),
        "email_events": generate_email_events(300),
        "terraform_workspaces": generate_terraform_workspaces(30),
        "iac_misconfigs": generate_iac_misconfigs(100),
    }


if __name__ == "__main__":
    data = generate_all()
    total = sum(len(v) for v in data.values())
    print(f"Generated {total:,} items across {len(data)} categories:")
    for category, items in data.items():
        print(f"  {category:25s} {len(items):>5,}")
