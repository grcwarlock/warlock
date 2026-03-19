import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  Shield, BarChart3, Zap, FileCheck, Database, Globe, Eye,
  ArrowRight, ArrowLeft, CheckCircle, Lock,
  Layers, TrendingUp, AlertTriangle, ClipboardCheck, Search,
  Send, LineChart, RefreshCw, Settings, Users, FileText,
  Activity, Target, Gauge, Bell, ShieldCheck, Workflow,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Feature data                                                       */
/* ------------------------------------------------------------------ */

interface FeatureData {
  slug: string;
  icon: LucideIcon;
  color: string;
  glow: string;
  badge: string;
  title: string;
  headline: string;
  subheadline: string;
  heroDescription: string;
  capabilities: { icon: LucideIcon; title: string; description: string }[];
  benefits: string[];
  frameworks: string[];
  ctaLabel: string;
  ctaLink: string;
}

const FEATURE_DATA: Record<string, FeatureData> = {
  'compliance-monitoring': {
    slug: 'compliance-monitoring',
    icon: BarChart3,
    color: 'from-blue-500 to-cyan-400',
    glow: 'rgba(59,130,246,0.25)',
    badge: '655 controls',
    title: 'Real-Time Compliance Monitoring',
    headline: 'See every control. Fix what fails. Stay audit-ready 24/7.',
    subheadline: 'Continuous compliance monitoring across 5 frameworks and 655 controls — no spreadsheets, no screenshots, no surprises.',
    heroDescription: 'Warlock monitors every control in your environment continuously. When a control drifts out of compliance, you know immediately — not when an auditor tells you three months later. Every control is color-coded green, yellow, or red, and every failing control comes with exact remediation steps, linked evidence, and one-click ticket creation.',
    capabilities: [
      { icon: Gauge, title: 'Unified Control Dashboard', description: 'See all 655 controls across NIST 800-53, SOC 2, ISO 27001, HIPAA, and CMMC L2 on a single screen. Filter by framework, status, or owner. No tab-switching, no spreadsheet merging.' },
      { icon: Bell, title: 'Instant Drift Detection', description: 'When a control changes status — a firewall rule is modified, an MFA policy is disabled, an encryption setting changes — Warlock detects it and alerts your team within minutes, not months.' },
      { icon: Target, title: 'Remediation Guidance', description: 'Every failing control includes step-by-step remediation instructions, the specific assets affected, who owns the fix, and a direct link to create a Jira or ServiceNow ticket.' },
      { icon: TrendingUp, title: 'Compliance Trend Analysis', description: 'Track your compliance posture over time. See which control families are improving, which are degrading, and where to invest your engineering effort for maximum audit readiness.' },
      { icon: Layers, title: 'Multi-Framework Mapping', description: 'A single control fix can satisfy requirements across multiple frameworks simultaneously. Warlock shows you exactly which frameworks benefit from every remediation action.' },
      { icon: Activity, title: 'Continuous Evidence Collection', description: 'Evidence is collected automatically from your connected tools. No more quarterly evidence-gathering sprints. When audit day arrives, your evidence is already current and organized.' },
    ],
    benefits: [
      'Reduce audit preparation time from weeks to hours',
      'Catch compliance drift the moment it happens, not months later',
      'Eliminate manual evidence screenshots and spreadsheet tracking',
      'Prioritize remediation by risk impact, not alphabetical order',
      'Show auditors real-time compliance data instead of stale snapshots',
      'Track compliance trends across quarters to prove continuous improvement',
    ],
    frameworks: ['NIST 800-53', 'SOC 2', 'ISO 27001', 'HIPAA', 'CMMC L2'],
    ctaLabel: 'Launch Demo Dashboard',
    ctaLink: '/login',
  },

  'integrations': {
    slug: 'integrations',
    icon: Zap,
    color: 'from-violet-500 to-purple-400',
    glow: 'rgba(139,92,246,0.25)',
    badge: '38 tools',
    title: '38 Native Integrations',
    headline: 'Connect your tools. Compliance maps itself.',
    subheadline: 'Wire up AWS, CrowdStrike, Okta, Splunk, and 34 more tools with an API key. Findings flow in and map to control families automatically.',
    heroDescription: 'Warlock integrates natively with the security and infrastructure tools your team already uses. When you connect a tool, its findings are automatically mapped to the correct control families across every framework you track. No CSV exports, no screenshots, no manual uploads. A CrowdStrike finding maps to SI-3. A missing MFA configuration in Okta maps to IA-2. Everything flows in real time.',
    capabilities: [
      { icon: Settings, title: 'One-Click Setup', description: 'Add an API key and you\'re connected. No agents to install, no custom scripts to maintain, no middleware to configure. Most integrations are producing mapped findings within 60 seconds.' },
      { icon: RefreshCw, title: 'Continuous Sync', description: 'Integrations pull data continuously — not once a quarter, not once a week. When a finding is created or resolved in your security tool, Warlock reflects the change immediately.' },
      { icon: Layers, title: 'Automatic Control Mapping', description: 'Every finding from every tool is automatically mapped to the NIST 800-53, SOC 2, ISO 27001, HIPAA, and CMMC L2 controls it affects. No manual tagging or categorization required.' },
      { icon: ShieldCheck, title: 'Cloud Security Posture', description: 'Native integrations with AWS Security Hub, Azure Security Center, and GCP Security Command Center pull cloud misconfigurations directly into your compliance view.' },
      { icon: Search, title: 'Vulnerability Management', description: 'Connect Tenable, Qualys, Rapid7, or Wiz and see vulnerability findings mapped to the controls they violate. Prioritize patches by compliance impact, not just CVSS score.' },
      { icon: Users, title: 'Identity & Access', description: 'Okta, Azure AD, and JumpCloud integrations monitor access controls, MFA enforcement, and privilege escalation — mapping every finding to AC and IA control families.' },
    ],
    benefits: [
      'Eliminate manual evidence collection from 38 different tool consoles',
      'Map findings to controls automatically — no GRC analyst required',
      'Get compliance-relevant data flowing in under 60 seconds per tool',
      'See cross-tool coverage gaps you didn\'t know existed',
      'Reduce false positives by correlating findings across tools',
      'Scale your GRC program without scaling your GRC team',
    ],
    frameworks: ['AWS', 'Azure', 'GCP', 'CrowdStrike', 'Okta', 'Splunk', 'Tenable', 'Jira', 'ServiceNow', 'Wiz', 'Qualys', 'Rapid7'],
    ctaLabel: 'Browse All Integrations',
    ctaLink: '/login',
  },

  'poam-audit-exports': {
    slug: 'poam-audit-exports',
    icon: FileCheck,
    color: 'from-emerald-500 to-teal-400',
    glow: 'rgba(16,185,129,0.25)',
    badge: 'Audit-ready',
    title: 'Automated POAM & Audit Exports',
    headline: 'Every failing control becomes a plan. Every plan becomes an export.',
    subheadline: 'Automatically generate Plan of Action & Milestones entries with risk ratings, timelines, and owners. Export complete audit packages in one click.',
    heroDescription: 'When a control fails, Warlock doesn\'t just flag it — it creates a structured Plan of Action & Milestones (POA&M) entry automatically. Each entry includes the risk rating, a remediation timeline, the assigned owner, and linked evidence. When audit day arrives, export a complete, framework-formatted audit package — NIST, SOC 2, or HIPAA — in a single click. No more last-minute scrambles.',
    capabilities: [
      { icon: ClipboardCheck, title: 'Auto-Generated POA&M Entries', description: 'Every failing control automatically creates a POA&M entry with severity, risk rating, remediation steps, timeline, and owner. No manual data entry, no copy-pasting from spreadsheets.' },
      { icon: FileText, title: 'One-Click Audit Packages', description: 'Export a complete audit evidence package formatted for NIST 800-53, SOC 2, ISO 27001, HIPAA, or CMMC L2. Includes control narratives, evidence artifacts, and assessment results.' },
      { icon: Target, title: 'Risk-Prioritized Remediation', description: 'POA&M entries are ranked by risk impact, not alphabetical order. Your team fixes the highest-risk gaps first, and auditors see a risk-aware remediation strategy.' },
      { icon: Workflow, title: 'Milestone Tracking', description: 'Set remediation milestones with due dates and track progress over time. See which POA&M items are on track, which are overdue, and which need escalation.' },
      { icon: LineChart, title: 'Trend Reporting', description: 'Track POA&M counts over time to demonstrate continuous improvement. Show auditors that your open findings are trending down, not accumulating.' },
      { icon: Send, title: 'Auditor-Ready Formatting', description: 'Exports are formatted exactly how auditors expect to receive them — proper column headers, risk categorization, evidence references, and framework-specific terminology.' },
    ],
    benefits: [
      'Eliminate the audit-prep scramble — evidence is always current and organized',
      'Generate POA&M entries automatically when controls fail',
      'Export complete audit packages in the format your auditor expects',
      'Track remediation progress with milestones and due dates',
      'Demonstrate continuous improvement with trend data',
      'Reduce audit preparation from weeks of manual work to a single click',
    ],
    frameworks: ['NIST 800-53', 'SOC 2', 'ISO 27001', 'HIPAA', 'CMMC L2'],
    ctaLabel: 'See POAM Tracker',
    ctaLink: '/login',
  },

  'data-silo-scanning': {
    slug: 'data-silo-scanning',
    icon: Database,
    color: 'from-amber-500 to-orange-400',
    glow: 'rgba(245,158,11,0.25)',
    badge: 'PII & PHI detection',
    title: 'Data Silo Scanning',
    headline: 'Find sensitive data before your auditor does.',
    subheadline: 'Automatically surface PII, PHI, API secrets, and sensitive data across S3 buckets, GitHub repos, SharePoint, and databases.',
    heroDescription: 'Sensitive data doesn\'t stay where you put it. It spreads across S3 buckets, GitHub repositories, SharePoint sites, Confluence pages, and database tables. Warlock scans your data silos continuously, surfaces PII, PHI, API secrets, and other sensitive data, and maps every finding directly to the compliance control it violates. You know exactly what to fix and why it matters.',
    capabilities: [
      { icon: Search, title: 'Multi-Source Scanning', description: 'Scan S3 buckets, GitHub repositories, SharePoint sites, Confluence spaces, databases, and file shares from a single console. No separate tools for each data source.' },
      { icon: AlertTriangle, title: 'Sensitive Data Classification', description: 'Automatically classify discovered data as PII (names, SSNs, emails), PHI (medical records, insurance IDs), financial data (credit cards, bank accounts), or secrets (API keys, tokens, passwords).' },
      { icon: Layers, title: 'Control Mapping', description: 'Every data finding is mapped to the specific compliance control it violates — SC-28 for data at rest, SC-8 for data in transit, MP-6 for media sanitization. You see the compliance impact immediately.' },
      { icon: Target, title: 'Risk Scoring', description: 'Findings are scored by sensitivity, exposure, and volume. A public S3 bucket with 10,000 SSNs ranks higher than an internal repo with a test API key. Prioritize what matters.' },
      { icon: RefreshCw, title: 'Continuous Monitoring', description: 'Scans run continuously, not quarterly. When someone uploads a spreadsheet of customer data to the wrong SharePoint folder, you know within hours, not during the next audit cycle.' },
      { icon: FileText, title: 'Remediation Reports', description: 'Generate detailed remediation reports showing exactly where sensitive data lives, who has access, what controls are violated, and the specific steps needed to remediate each finding.' },
    ],
    benefits: [
      'Discover sensitive data you didn\'t know existed in your environment',
      'Map every data finding to the specific compliance control it violates',
      'Prioritize remediation by sensitivity, exposure, and volume',
      'Demonstrate data governance to auditors with continuous scan evidence',
      'Catch data sprawl early — before it becomes an audit finding',
      'Reduce your data breach surface area systematically',
    ],
    frameworks: ['NIST 800-53 SC-28', 'HIPAA §164.312', 'SOC 2 CC6.1', 'ISO 27001 A.8', 'GDPR Art. 32', 'CCPA §1798.150'],
    ctaLabel: 'Run a Silo Scan',
    ctaLink: '/login',
  },

  'trust-hub': {
    slug: 'trust-hub',
    icon: Globe,
    color: 'from-pink-500 to-rose-400',
    glow: 'rgba(236,72,153,0.25)',
    badge: 'Public · No login',
    title: 'Customer Trust Hub',
    headline: 'Send a link, not a PDF.',
    subheadline: 'Publish a live, public-facing security portal in minutes. Show real-time compliance status, certifications, and audit summaries — no NDA required.',
    heroDescription: 'Every enterprise sales cycle includes the question: "Do you have a SOC 2?" Instead of emailing a 200-page PDF, send prospects a link to your Trust Hub — a live, public-facing security portal that shows real-time compliance scores, certification status, and audit summaries. No NDA required, no back-and-forth with your security team, no stale documents. Your compliance posture is always current and always accessible.',
    capabilities: [
      { icon: Globe, title: 'Public Security Portal', description: 'Publish a branded, public-facing page that shows your compliance status, certifications, and security posture. No login required for visitors — reduce friction in your sales cycle.' },
      { icon: TrendingUp, title: 'Real-Time Compliance Scores', description: 'Show live pass rates across frameworks. When you remediate a finding, your Trust Hub updates automatically. Prospects always see your current posture, not last quarter\'s snapshot.' },
      { icon: ShieldCheck, title: 'Certification Display', description: 'Showcase your SOC 2, ISO 27001, HIPAA, and other certifications with verification dates and scope descriptions. Make it easy for prospects to verify your compliance status.' },
      { icon: FileText, title: 'Document Sharing', description: 'Share audit summaries, security whitepapers, and compliance documentation directly from your Trust Hub. Control which documents are public and which require an NDA request.' },
      { icon: Lock, title: 'NDA-Gated Content', description: 'Some documents require an NDA. Your Trust Hub includes a request flow where prospects can request access to sensitive documents, routed to your team for approval.' },
      { icon: Send, title: 'Sales Enablement', description: 'Give your sales team a single link to answer every security questionnaire. When a prospect asks about your security posture, the answer is always the same: "Here\'s our Trust Hub."' },
    ],
    benefits: [
      'Answer "Do you have a SOC 2?" with a link instead of a 200-page PDF',
      'Reduce security questionnaire response time from days to seconds',
      'Show prospects real-time compliance data, not stale snapshots',
      'Accelerate enterprise sales cycles by removing security review bottlenecks',
      'Maintain a single source of truth for your security posture',
      'Build customer trust proactively, before they ask',
    ],
    frameworks: ['SOC 2', 'ISO 27001', 'HIPAA', 'NIST 800-53', 'CMMC L2'],
    ctaLabel: 'View Live Trust Portal',
    ctaLink: '/trust',
  },

  'vendor-risk-management': {
    slug: 'vendor-risk-management',
    icon: Eye,
    color: 'from-sky-500 to-indigo-400',
    glow: 'rgba(14,165,233,0.25)',
    badge: 'Supply chain',
    title: 'Third-Party Risk Management',
    headline: 'Know your vendor risk before your auditor does.',
    subheadline: 'Score every vendor against your compliance requirements. Send automated questionnaires, track responses, flag gaps, and monitor posture over time.',
    heroDescription: 'Your compliance posture is only as strong as your weakest vendor. Warlock lets you score every vendor in your supply chain against your own compliance requirements. Send automated security questionnaires, track response status, flag gaps, and monitor posture changes over time. When an auditor asks about your third-party risk management program, show them a live dashboard — not a folder of expired questionnaire PDFs.',
    capabilities: [
      { icon: ClipboardCheck, title: 'Automated Questionnaires', description: 'Send standardized security questionnaires to vendors with automated reminders. Track response rates, flag overdue responses, and compare vendor answers against your requirements.' },
      { icon: Gauge, title: 'Risk Scoring', description: 'Score vendors on a consistent scale based on their questionnaire responses, certification status, breach history, and data access level. See your riskiest vendors at a glance.' },
      { icon: TrendingUp, title: 'Posture Monitoring', description: 'Track vendor security posture over time. Get alerted when a vendor\'s score drops, when certifications expire, or when a vendor appears in a breach notification.' },
      { icon: Layers, title: 'Tiered Risk Classification', description: 'Classify vendors by data access level and business criticality. Apply proportional assessment requirements — your cloud hosting provider gets a deeper review than your office snack vendor.' },
      { icon: AlertTriangle, title: 'Fourth-Party Visibility', description: 'Understand your fourth-party risk by mapping vendor dependencies. If your payment processor relies on a sub-processor with weak security, you need to know before your auditor finds out.' },
      { icon: LineChart, title: 'Portfolio Analytics', description: 'See aggregate risk metrics across your entire vendor portfolio. Track how many vendors meet your requirements, how many have gaps, and how your overall third-party risk is trending.' },
    ],
    benefits: [
      'Replace spreadsheet-based vendor tracking with a live risk dashboard',
      'Send and track security questionnaires without email back-and-forth',
      'Score vendors consistently using standardized risk criteria',
      'Monitor vendor posture changes and certification expirations automatically',
      'Demonstrate a mature third-party risk program to auditors',
      'Identify fourth-party risk before it becomes your problem',
    ],
    frameworks: ['SOC 2 CC9.2', 'NIST 800-53 SA-9', 'ISO 27001 A.15', 'HIPAA §164.308(b)', 'CMMC L2 3.12'],
    ctaLabel: 'View Vendor Risk',
    ctaLink: '/login',
  },

  'nist-800-53': {
    slug: 'nist-800-53',
    icon: Shield,
    color: 'from-blue-500 to-indigo-500',
    glow: 'rgba(59,130,246,0.25)',
    badge: '324 controls',
    title: 'NIST 800-53 Rev 5 Compliance',
    headline: 'Automate all 20 control families. Ship your ATO package in days, not months.',
    subheadline: '324 controls across 20 control families — continuously assessed, automatically evidenced, and always audit-ready.',
    heroDescription: 'NIST 800-53 Rev 5 is the gold standard for federal information security, but managing 324 controls across 20 control families manually is a full-time job for an entire team. Warlock maps every control family — Access Control (AC), Awareness and Training (AT), Audit and Accountability (AU), Assessment Authorization and Monitoring (CA), Configuration Management (CM), Contingency Planning (CP), Identification and Authentication (IA), Incident Response (IR), Maintenance (MA), Media Protection (MP), Physical and Environmental Protection (PE), Planning (PL), Program Management (PM), Personnel Security (PS), Personally Identifiable Information Processing and Transparency (PT), Risk Assessment (RA), System and Services Acquisition (SA), System and Communications Protection (SC), System and Information Integrity (SI), and Supply Chain Risk Management (SR) — to your actual infrastructure through native integrations. Evidence is collected continuously, control assessments run automatically, and your ATO package is always current.',
    capabilities: [
      { icon: Layers, title: 'All 20 Control Families Mapped', description: 'Every control from AC through SR is mapped to your environment. See which controls are satisfied by your existing tools, which have gaps, and which need manual attestation — all on one dashboard.' },
      { icon: Activity, title: 'Continuous Assessment', description: 'Controls are assessed in real time as findings flow in from your connected tools. A CrowdStrike alert maps to SI-3, a missing MFA configuration maps to IA-2, and an unencrypted S3 bucket maps to SC-28 — automatically.' },
      { icon: FileText, title: 'ATO-Ready Packages', description: 'Export a complete Authorization to Operate package with System Security Plan (SSP), control narratives, evidence artifacts, and POA&M entries. Formatted for federal reviewers and ready to submit.' },
      { icon: Target, title: 'Control Enhancement Tracking', description: 'Track not just base controls but control enhancements. Know whether you satisfy AC-2(1) through AC-2(13) individually, with specific evidence mapped to each enhancement level.' },
      { icon: RefreshCw, title: 'Automated Evidence Collection', description: 'Evidence is pulled from your connected tools continuously. No more quarterly evidence-gathering sprints where your team screenshots 300 console pages. When the auditor arrives, your evidence is already current.' },
      { icon: TrendingUp, title: 'FISMA Scoring & Trends', description: 'Track your overall NIST 800-53 compliance score over time. See which control families are improving, which are degrading, and generate FISMA-ready metrics for your ISSO and AO.' },
    ],
    benefits: [
      'Reduce ATO timeline from 18 months to weeks with pre-built control mappings',
      'Continuously assess all 324 controls instead of point-in-time snapshots',
      'Automatically map tool findings to the correct control families',
      'Generate SSP, POA&M, and evidence packages with a single click',
      'Track control enhancements individually, not just base controls',
      'Demonstrate continuous monitoring to satisfy CA-7 requirements',
    ],
    frameworks: ['NIST 800-53 Rev 5', 'FISMA', 'FedRAMP', 'NIST CSF', 'NIST 800-171'],
    ctaLabel: 'See It In Action',
    ctaLink: '/login',
  },

  'soc-2': {
    slug: 'soc-2',
    icon: ShieldCheck,
    color: 'from-violet-500 to-purple-500',
    glow: 'rgba(139,92,246,0.25)',
    badge: '5 TSC mapped',
    title: 'SOC 2 Type II Compliance',
    headline: 'Continuous SOC 2 compliance — not just a point-in-time report.',
    subheadline: 'All 5 Trust Services Criteria mapped with automated evidence collection, continuous monitoring, and auditor-ready exports.',
    heroDescription: 'SOC 2 Type II is the compliance standard your enterprise customers demand, but maintaining continuous compliance across all five Trust Services Criteria — Security (CC), Availability (A), Processing Integrity (PI), Confidentiality (C), and Privacy (P) — requires constant vigilance. Warlock maps every criterion to your actual infrastructure, collects evidence automatically from your connected tools, and keeps your compliance posture current every day of the audit period. When your auditor arrives, you hand them a complete evidence package instead of scrambling for screenshots.',
    capabilities: [
      { icon: ShieldCheck, title: 'All 5 Trust Services Criteria', description: 'Security (CC1-CC9), Availability (A1), Processing Integrity (PI1), Confidentiality (C1), and Privacy (P1) — every criterion is mapped to specific controls in your environment with evidence collected automatically.' },
      { icon: Activity, title: 'Continuous Monitoring Period', description: 'SOC 2 Type II requires evidence over a monitoring period, not a single point in time. Warlock collects evidence continuously, so every day of your audit window is covered without manual effort.' },
      { icon: FileText, title: 'Auditor-Ready Evidence Packages', description: 'Export a complete evidence package organized by Trust Services Criteria. Includes control narratives, evidence artifacts with timestamps, and exception tracking — formatted exactly how your auditor expects.' },
      { icon: ClipboardCheck, title: 'Control Narratives', description: 'Pre-built control narratives describe how each criterion is satisfied in your environment. Customize them to match your specific implementation, and link each narrative to the evidence that supports it.' },
      { icon: AlertTriangle, title: 'Exception Tracking', description: 'When a control fails during the monitoring period, Warlock documents the exception, the remediation action, and the timeline — so your auditor sees a managed exception, not a surprise gap.' },
      { icon: Send, title: 'Bridge Letter Generation', description: 'Generate SOC 2 bridge letters to cover the gap between your last audit report and the current date. Show customers that your compliance posture has been maintained since your last Type II report.' },
    ],
    benefits: [
      'Maintain continuous compliance across all 5 Trust Services Criteria',
      'Collect evidence automatically throughout the entire audit period',
      'Export auditor-ready packages organized by TSC criteria',
      'Track and document exceptions with remediation timelines',
      'Generate bridge letters to cover gaps between audit reports',
      'Close enterprise deals faster with always-current SOC 2 evidence',
    ],
    frameworks: ['SOC 2 Type II', 'SOC 2 Type I', 'SOC 1', 'AICPA TSC 2017'],
    ctaLabel: 'Start Free Demo',
    ctaLink: '/login',
  },

  'iso-27001': {
    slug: 'iso-27001',
    icon: Shield,
    color: 'from-emerald-500 to-green-500',
    glow: 'rgba(16,185,129,0.25)',
    badge: 'Annex A mapped',
    title: 'ISO 27001:2022 Certification',
    headline: 'From gap analysis to certification — automated.',
    subheadline: 'ISO 27001:2022 Annex A controls mapped, Statement of Applicability generated, and continuous ISMS monitoring built in.',
    heroDescription: 'ISO 27001:2022 certification demonstrates to global customers and partners that your Information Security Management System (ISMS) meets the international gold standard. Warlock maps every Annex A control to your actual infrastructure, generates your Statement of Applicability (SoA) automatically, and monitors your ISMS continuously. Whether you are pursuing initial certification or maintaining an existing one, the platform handles the heavy lifting — control mapping, evidence collection, gap identification, and audit preparation — so your team can focus on building security, not documenting it.',
    capabilities: [
      { icon: Layers, title: 'Annex A Control Mapping', description: 'All 93 Annex A controls from ISO 27001:2022 are mapped across the four themes — Organizational (37 controls), People (8 controls), Physical (14 controls), and Technological (34 controls). See your coverage at a glance.' },
      { icon: FileText, title: 'Statement of Applicability (SoA)', description: 'Automatically generate your Statement of Applicability showing which Annex A controls are applicable, how each is implemented, and the justification for any exclusions. Keep it current as your environment changes.' },
      { icon: Search, title: 'Gap Analysis', description: 'Run a comprehensive gap analysis against ISO 27001:2022 requirements. See exactly which controls are satisfied, which have partial coverage, and which need implementation — prioritized by risk.' },
      { icon: RefreshCw, title: 'Continuous ISMS Monitoring', description: 'Your ISMS does not stop between audits, and neither does Warlock. Monitor control effectiveness continuously and detect when changes in your environment create new gaps.' },
      { icon: Target, title: 'Risk Treatment Tracking', description: 'Document risk treatment decisions — accept, mitigate, transfer, or avoid — and link them to specific Annex A controls. Track treatment plan progress and demonstrate risk-based decision-making to auditors.' },
      { icon: TrendingUp, title: 'Surveillance Audit Readiness', description: 'ISO 27001 requires annual surveillance audits. Warlock keeps your evidence current year-round, so surveillance audit preparation is a matter of clicking export, not a multi-week scramble.' },
    ],
    benefits: [
      'Map all 93 Annex A controls to your environment automatically',
      'Generate and maintain your Statement of Applicability in real time',
      'Identify gaps before your certification auditor does',
      'Monitor ISMS effectiveness continuously between audits',
      'Reduce surveillance audit preparation from weeks to hours',
      'Demonstrate continuous improvement to satisfy Clause 10 requirements',
    ],
    frameworks: ['ISO 27001:2022', 'ISO 27002:2022', 'ISO 27017', 'ISO 27018', 'ISO 27701'],
    ctaLabel: 'See It In Action',
    ctaLink: '/login',
  },

  'hipaa': {
    slug: 'hipaa',
    icon: Shield,
    color: 'from-rose-500 to-pink-500',
    glow: 'rgba(244,63,94,0.25)',
    badge: 'Security Rule',
    title: 'HIPAA Security Rule Compliance',
    headline: 'Protect PHI. Manage BAAs. Automate breach response.',
    subheadline: 'HIPAA Security Rule administrative, physical, and technical safeguards mapped with PHI tracking, BAA management, and breach notification workflows.',
    heroDescription: 'HIPAA compliance is not optional when you handle Protected Health Information (PHI), and the penalties for non-compliance can reach millions of dollars per violation category. Warlock maps every Security Rule requirement — administrative safeguards (164.308), physical safeguards (164.310), and technical safeguards (164.312) — to your actual infrastructure. Track where PHI lives across your environment, manage Business Associate Agreements (BAAs) with every vendor that touches patient data, and maintain documented breach notification workflows that satisfy the Breach Notification Rule (164.400-414). When OCR comes knocking, your compliance documentation is already organized and current.',
    capabilities: [
      { icon: ShieldCheck, title: 'Security Rule Safeguards', description: 'All three categories of safeguards — administrative (164.308), physical (164.310), and technical (164.312) — are mapped to your infrastructure with evidence collected automatically from your connected security tools.' },
      { icon: Database, title: 'PHI Data Mapping', description: 'Know exactly where Protected Health Information lives in your environment. Warlock scans your data silos to identify PHI across databases, file stores, cloud storage, and SaaS applications — and maps findings to the controls they violate.' },
      { icon: ClipboardCheck, title: 'BAA Management', description: 'Track every Business Associate Agreement in one place. Monitor expiration dates, coverage scope, and compliance status for every vendor that accesses, processes, or stores PHI on your behalf.' },
      { icon: Bell, title: 'Breach Notification Workflows', description: 'Maintain documented breach notification procedures that satisfy the Breach Notification Rule. When an incident occurs, follow pre-built workflows for individual notification (60-day rule), HHS reporting, and media notification for breaches affecting 500+ individuals.' },
      { icon: AlertTriangle, title: 'Risk Analysis (164.308(a)(1))', description: 'Conduct and document the required Security Rule risk analysis. Identify threats, vulnerabilities, and the likelihood and impact of potential PHI breaches — with continuous updates as your environment changes.' },
      { icon: Users, title: 'Workforce Training Tracking', description: 'Track security awareness training completion for all workforce members who handle PHI. Document training dates, topics covered, and attestations to satisfy the training requirements under 164.308(a)(5).' },
    ],
    benefits: [
      'Map all Security Rule safeguards to your actual infrastructure',
      'Track PHI across every data silo in your environment automatically',
      'Manage BAAs with centralized tracking and expiration alerts',
      'Maintain documented breach notification workflows ready for any incident',
      'Conduct continuous risk analysis instead of annual point-in-time assessments',
      'Demonstrate compliance to OCR with organized, current documentation',
    ],
    frameworks: ['HIPAA Security Rule', 'HIPAA Privacy Rule', 'HITECH Act', 'HITRUST CSF', 'NIST 800-66'],
    ctaLabel: 'Start Free Demo',
    ctaLink: '/login',
  },

  'cmmc-l2': {
    slug: 'cmmc-l2',
    icon: Shield,
    color: 'from-amber-500 to-yellow-500',
    glow: 'rgba(245,158,11,0.25)',
    badge: '110 practices',
    title: 'CMMC Level 2 Certification',
    headline: 'Win DoD contracts. Prove CUI protection. Pass your C3PAO assessment.',
    subheadline: '110 practices mapped to NIST 800-171, SPRS scoring calculated, and assessment-ready evidence packages generated automatically.',
    heroDescription: 'Cybersecurity Maturity Model Certification (CMMC) Level 2 is required for any defense contractor handling Controlled Unclassified Information (CUI). With 110 practices aligned to NIST SP 800-171 across 14 domains, achieving certification through a CMMC Third-Party Assessment Organization (C3PAO) demands rigorous documentation, continuous monitoring, and complete evidence packages. Warlock maps all 110 practices to your infrastructure, calculates your Supplier Performance Risk System (SPRS) score in real time, identifies gaps before your assessor does, and generates the evidence packages your C3PAO needs. Stop losing DoD contracts because of compliance gaps — get assessment-ready and stay that way.',
    capabilities: [
      { icon: Layers, title: '110 Practices Across 14 Domains', description: 'Every CMMC Level 2 practice is mapped across all 14 domains — Access Control, Awareness & Training, Audit & Accountability, Configuration Management, Identification & Authentication, Incident Response, Maintenance, Media Protection, Personnel Security, Physical Protection, Risk Assessment, Security Assessment, System & Communications Protection, and System & Information Integrity.' },
      { icon: Gauge, title: 'Real-Time SPRS Scoring', description: 'Your Supplier Performance Risk System (SPRS) score is calculated continuously based on your current compliance posture. See your score change in real time as you remediate findings, and know exactly which practices are dragging your score down.' },
      { icon: Target, title: 'CUI Boundary Mapping', description: 'Define and document your CUI boundary — the systems, networks, and data stores that process, store, or transmit Controlled Unclassified Information. Warlock tracks CUI flow and flags when data moves outside the boundary.' },
      { icon: FileText, title: 'System Security Plan (SSP)', description: 'Generate and maintain your System Security Plan with practice-level narratives describing how each of the 110 practices is implemented in your environment. Linked evidence keeps the SSP current automatically.' },
      { icon: ClipboardCheck, title: 'POA&M for Assessment', description: 'Not every practice will be fully implemented on day one. Warlock generates a POA&M that documents your remediation plan for each gap, with timelines and milestones that satisfy C3PAO expectations.' },
      { icon: TrendingUp, title: 'Assessment Readiness Dashboard', description: 'See a single dashboard showing your readiness for C3PAO assessment. Green practices are fully evidenced, yellow practices have partial evidence, and red practices need attention — with clear remediation guidance for each.' },
    ],
    benefits: [
      'Map all 110 CMMC Level 2 practices to your infrastructure automatically',
      'Calculate your SPRS score in real time and track it over time',
      'Identify assessment gaps before your C3PAO does',
      'Generate SSP and POA&M documents with linked evidence',
      'Define and monitor your CUI boundary with continuous scanning',
      'Win DoD contracts by demonstrating certified CUI protection',
    ],
    frameworks: ['CMMC Level 2', 'NIST SP 800-171', 'DFARS 252.204-7012', 'NIST SP 800-172', 'ITAR'],
    ctaLabel: 'See It In Action',
    ctaLink: '/login',
  },
};

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function FeaturePage() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const feature = slug ? FEATURE_DATA[slug] : undefined;

  if (!feature) {
    return (
      <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-heading)] flex flex-col items-center justify-center gap-4">
        <h1 className="text-2xl font-bold">Feature not found</h1>
        <Link to="/" className="text-blue-400 hover:text-blue-300 flex items-center gap-1">
          <ArrowLeft className="w-4 h-4" /> Back to home
        </Link>
      </div>
    );
  }

  const Icon = feature.icon;
  const allSlugs = Object.keys(FEATURE_DATA);
  const currentIndex = allSlugs.indexOf(feature.slug);
  const prevFeature = currentIndex > 0 ? FEATURE_DATA[allSlugs[currentIndex - 1]] : null;
  const nextFeature = currentIndex < allSlugs.length - 1 ? FEATURE_DATA[allSlugs[currentIndex + 1]] : null;

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-heading)] overflow-x-hidden">
      {/* Background blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none" aria-hidden="true">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] bg-blue-600/8 rounded-full blur-[120px]" />
        <div className="absolute top-1/3 -right-40 w-[500px] h-[500px] bg-violet-600/8 rounded-full blur-[100px]" />
      </div>

      {/* Nav */}
      <nav className="relative z-20 flex items-center justify-between px-5 md:px-16 py-4 border-b border-[var(--border-subtle)] sticky top-0 bg-[var(--bg-base)]/80 backdrop-blur-[12px]" style={{ WebkitBackdropFilter: 'blur(12px)' }}>
        <Link to="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center shadow-lg shadow-blue-500/30 flex-shrink-0">
            <Shield className="w-4 h-4 text-[var(--text-heading)]" />
          </div>
          <span className="text-base font-bold tracking-tight">
            GRC <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent" style={{ WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Warlock</span>
          </span>
        </Link>

        <div className="flex items-center gap-2.5">
          <Link to="/" className="hidden sm:flex items-center gap-1 text-sm text-slate-300 hover:text-[var(--text-heading)] transition-colors px-4 py-2 rounded-lg hover:bg-[var(--bg-interactive)]">
            <ArrowLeft className="w-3.5 h-3.5" /> Back
          </Link>
          <Link to="/login" className="text-sm font-semibold px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 transition-all shadow-lg shadow-blue-500/20 flex items-center gap-1.5 whitespace-nowrap">
            View Demo <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative z-10 px-5 pt-16 pb-20 md:pt-24 md:pb-28 max-w-4xl mx-auto">
        <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-[var(--text-heading)] transition-colors mb-8">
          <ArrowLeft className="w-3.5 h-3.5" /> All features
        </Link>

        <div className="flex items-start gap-4 mb-6">
          <div className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${feature.color} flex items-center justify-center shadow-lg flex-shrink-0`}>
            <Icon className="w-7 h-7 text-[var(--text-heading)]" />
          </div>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400">{feature.badge}</span>
            </div>
            <h1 className="text-3xl md:text-4xl lg:text-5xl font-extrabold tracking-tight leading-tight">{feature.title}</h1>
          </div>
        </div>

        <h2 className="text-xl md:text-2xl font-bold text-slate-200 mb-4 leading-snug max-w-3xl">{feature.headline}</h2>
        <p className="text-slate-400 text-lg leading-relaxed max-w-3xl">{feature.heroDescription}</p>
      </section>

      {/* Capabilities grid */}
      <section className="relative z-10 px-5 pb-20 max-w-6xl mx-auto">
        <div className="text-center mb-12">
          <h3 className="text-2xl md:text-3xl font-extrabold text-[var(--text-heading)] mb-2">Key Capabilities</h3>
          <p className="text-slate-500 text-base">{feature.subheadline}</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {feature.capabilities.map((cap) => {
            const CapIcon = cap.icon;
            return (
              <div key={cap.title} className="group bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-2xl p-6 hover:bg-[var(--bg-interactive-hover)] hover:border-[var(--border-color-hover)] transition-all">
                <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${feature.color} flex items-center justify-center mb-4 opacity-80`}>
                  <CapIcon className="w-5 h-5 text-[var(--text-heading)]" />
                </div>
                <h4 className="font-bold text-[var(--text-heading)] text-base mb-2">{cap.title}</h4>
                <p className="text-slate-400 text-sm leading-relaxed">{cap.description}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* Benefits */}
      <section className="relative z-10 px-5 pb-20 bg-[var(--bg-subtle)] border-y border-[var(--border-subtle)]">
        <div className="max-w-4xl mx-auto py-16">
          <h3 className="text-2xl md:text-3xl font-extrabold text-[var(--text-heading)] mb-10 text-center">Why It Matters</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {feature.benefits.map((benefit) => (
              <div key={benefit} className="flex items-start gap-3 p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-subtle)]">
                <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                <span className="text-slate-300 text-sm leading-relaxed">{benefit}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Framework / tool badges */}
      <section className="relative z-10 px-5 py-16 max-w-4xl mx-auto text-center">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-6">
          {feature.slug === 'integrations' ? 'Supported Tools' : 'Applicable Frameworks & Controls'}
        </p>
        <div className="flex flex-wrap justify-center gap-3">
          {feature.frameworks.map((fw) => (
            <span key={fw} className="px-4 py-2 rounded-xl border border-[var(--border-color)] bg-[var(--bg-subtle)] text-sm font-semibold text-slate-300">
              {fw}
            </span>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative z-10 px-5 pb-20 max-w-4xl mx-auto">
        <div className="relative bg-gradient-to-br from-blue-600/15 to-violet-600/10 border border-blue-500/20 rounded-3xl p-8 md:p-12 overflow-hidden text-center">
          <div className="absolute inset-0 opacity-30 pointer-events-none">
            <div className="absolute -top-20 -right-20 w-64 h-64 bg-violet-600/20 rounded-full blur-3xl" />
            <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-blue-600/20 rounded-full blur-3xl" />
          </div>
          <div className="relative">
            <h2 className="text-2xl md:text-3xl font-extrabold text-[var(--text-heading)] mb-3">See it in action</h2>
            <p className="text-slate-400 text-base max-w-xl mx-auto mb-6">
              Explore {feature.title.toLowerCase()} in the live demo environment. No signup required — use the demo credentials to get started immediately.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-4">
              <Link to={feature.ctaLink} className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 font-bold text-base shadow-xl shadow-blue-500/25 transition-all hover:scale-[1.02]">
                {feature.ctaLabel} <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
            <div className="flex items-center justify-center gap-2 text-xs text-slate-500">
              <Lock className="w-3.5 h-3.5" />
              Request demo access from your account team
            </div>
          </div>
        </div>
      </section>

      {/* Prev / Next navigation */}
      <section className="relative z-10 px-5 pb-20 max-w-4xl mx-auto">
        <div className="flex flex-col sm:flex-row gap-4">
          {prevFeature && (
            <button
              onClick={() => navigate(`/features/${prevFeature.slug}`)}
              className="flex-1 flex items-center gap-3 p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] hover:border-[var(--border-color-hover)] transition-all text-left"
            >
              <ArrowLeft className="w-4 h-4 text-slate-500 flex-shrink-0" />
              <div>
                <div className="text-xs text-slate-500 mb-0.5">Previous</div>
                <div className="text-sm font-semibold text-slate-300">{prevFeature.title}</div>
              </div>
            </button>
          )}
          {nextFeature && (
            <button
              onClick={() => navigate(`/features/${nextFeature.slug}`)}
              className="flex-1 flex items-center justify-end gap-3 p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] hover:border-[var(--border-color-hover)] transition-all text-right"
            >
              <div>
                <div className="text-xs text-slate-500 mb-0.5">Next</div>
                <div className="text-sm font-semibold text-slate-300">{nextFeature.title}</div>
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
            </button>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-[var(--border-subtle)] px-5 py-8">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-5">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-[var(--text-heading)]" />
            </div>
            <span className="font-bold text-sm">
              GRC <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent" style={{ WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Warlock</span>
            </span>
          </Link>
          <div className="flex flex-wrap gap-5 text-xs text-slate-500">
            <Link to="/" className="hover:text-slate-300 transition-colors">Home</Link>
            <Link to="/trust" className="hover:text-slate-300 transition-colors">Trust Hub</Link>
            <Link to="/login" className="hover:text-slate-300 transition-colors">Sign In</Link>
          </div>
          <p className="text-xs text-slate-600">&copy; 2026 Warlock. The full-stack Compliance engineering platform.</p>
        </div>
      </footer>
    </div>
  );
}
