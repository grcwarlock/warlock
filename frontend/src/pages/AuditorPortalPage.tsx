import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, CheckCircle, AlertTriangle, XCircle, Download, Search,
  ChevronDown, ChevronRight, Eye, FileText, Clock, Activity,
  Package, Filter, X, Loader2, RefreshCw,
  ArrowLeft, FileCheck, Layers,
  Calendar, User, AlertCircle, Archive, LogOut, Code
} from 'lucide-react';
import api from '../lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FrameworkSummary {
  id: string;
  name: string;
  version: string;
  abbreviation: string;
  color: string;
  totalControls: number;
  evidenceCompleteness: number;
  status: 'Ready for Audit' | 'In Progress' | 'Needs Attention';
  controlFamilies: number;
  lastUpdated: string;
}

interface ControlFamily {
  id: string;
  name: string;
  controls: ControlSummary[];
}

interface ControlSummary {
  controlId: string;
  name: string;
  evidenceStatus: 'met' | 'partial' | 'not_met';
  artifactsCount: number;
  lastReviewed: string;
}

interface ControlDetail {
  controlId: string;
  name: string;
  description: string;
  implementation: string;
  testingProcedure: string;
  reviewer: string;
  reviewDate: string;
  status: string;
  statusNotes: string;
  artifacts: Artifact[];
}

interface Artifact {
  name: string;
  type: 'Policy' | 'Config' | 'Log' | 'Report' | 'Certificate';
  collectionMethod: 'Automated' | 'Manual';
  collectedDate: string;
  description: string;
  contentPreview: string;
}

interface ActivityEvent {
  id: string;
  type: 'collection' | 'review' | 'status_change';
  message: string;
  framework: string;
  actor: string;
  timestamp: string;
}

interface PortalSummary {
  totalControls: number;
  evidenceArtifacts: number;
  frameworkCount: number;
  lastUpdated: string;
  frameworkScores: { name: string; abbreviation: string; score: number; color: string }[];
}

// ---------------------------------------------------------------------------
// Fallback demo data
// ---------------------------------------------------------------------------

const DEMO_FRAMEWORKS: FrameworkSummary[] = [
  { id: 'soc2', name: 'SOC 2 Type II', version: '2017', abbreviation: 'SOC2', color: '#3b82f6', totalControls: 64, evidenceCompleteness: 94, status: 'Ready for Audit', controlFamilies: 5, lastUpdated: '2026-03-15' },
  { id: 'iso_27001', name: 'ISO 27001:2022', version: '2022', abbreviation: 'ISO', color: '#8b5cf6', totalControls: 93, evidenceCompleteness: 91, status: 'Ready for Audit', controlFamilies: 14, lastUpdated: '2026-03-14' },
  { id: 'nist800_53', name: 'NIST 800-53 Rev 5', version: 'Rev 5', abbreviation: 'NIST', color: '#06b6d4', totalControls: 322, evidenceCompleteness: 87, status: 'In Progress', controlFamilies: 20, lastUpdated: '2026-03-16' },
  { id: 'hipaa', name: 'HIPAA Security Rule', version: '2013', abbreviation: 'HIPAA', color: '#10b981', totalControls: 54, evidenceCompleteness: 82, status: 'In Progress', controlFamilies: 5, lastUpdated: '2026-03-13' },
  { id: 'gdpr', name: 'GDPR', version: '2016/679', abbreviation: 'GDPR', color: '#f59e0b', totalControls: 41, evidenceCompleteness: 76, status: 'In Progress', controlFamilies: 6, lastUpdated: '2026-03-12' },
  { id: 'fedramp', name: 'FedRAMP Moderate', version: 'Rev 5', abbreviation: 'FED', color: '#ef4444', totalControls: 325, evidenceCompleteness: 68, status: 'Needs Attention', controlFamilies: 20, lastUpdated: '2026-03-10' },
  { id: 'cmmc', name: 'CMMC Level 2', version: '2.0', abbreviation: 'CMMC', color: '#f97316', totalControls: 110, evidenceCompleteness: 73, status: 'In Progress', controlFamilies: 14, lastUpdated: '2026-03-11' },
  { id: 'pci_dss', name: 'PCI DSS v4.0', version: '4.0', abbreviation: 'PCI', color: '#ec4899', totalControls: 64, evidenceCompleteness: 96, status: 'Ready for Audit', controlFamilies: 12, lastUpdated: '2026-03-16' },
  { id: 'iso42001', name: 'ISO 42001', version: '2023', abbreviation: 'AI', color: '#a855f7', totalControls: 38, evidenceCompleteness: 62, status: 'Needs Attention', controlFamilies: 8, lastUpdated: '2026-03-09' },
];

const DEMO_SUMMARY: PortalSummary = {
  totalControls: 1111,
  evidenceArtifacts: 3847,
  frameworkCount: 9,
  lastUpdated: '2026-03-16T14:32:00Z',
  frameworkScores: DEMO_FRAMEWORKS.map(f => ({ name: f.name, abbreviation: f.abbreviation, score: f.evidenceCompleteness, color: f.color })),
};

const DEMO_ACTIVITY: ActivityEvent[] = [
  { id: '1', type: 'collection', message: 'Automated evidence collected for AC-2 (Account Management)', framework: 'NIST 800-53', actor: 'System', timestamp: '2026-03-16T14:30:00Z' },
  { id: '2', type: 'review', message: 'CC6.1 evidence package reviewed and approved', framework: 'SOC 2', actor: 'Sarah Chen', timestamp: '2026-03-16T13:15:00Z' },
  { id: '3', type: 'status_change', message: 'PCI DSS Requirement 8 moved to Ready for Audit', framework: 'PCI DSS', actor: 'Mike Johnson', timestamp: '2026-03-16T11:45:00Z' },
  { id: '4', type: 'collection', message: 'AWS Config snapshots collected for infrastructure controls', framework: 'ISO 27001', actor: 'System', timestamp: '2026-03-16T10:00:00Z' },
  { id: '5', type: 'review', message: 'HIPAA Administrative Safeguards evidence reviewed', framework: 'HIPAA', actor: 'Dr. Emily Roberts', timestamp: '2026-03-15T16:30:00Z' },
  { id: '6', type: 'status_change', message: 'GDPR Article 32 controls flagged for re-assessment', framework: 'GDPR', actor: 'Thomas Mueller', timestamp: '2026-03-15T14:00:00Z' },
  { id: '7', type: 'collection', message: 'Vulnerability scan reports uploaded for SC-5', framework: 'FedRAMP', actor: 'System', timestamp: '2026-03-15T09:00:00Z' },
  { id: '8', type: 'review', message: 'CMMC Level 2 Access Control family fully reviewed', framework: 'CMMC', actor: 'James Wilson', timestamp: '2026-03-14T15:20:00Z' },
];

function getDemoControlFamilies(frameworkId: string): ControlFamily[] {
  const familyMap: Record<string, ControlFamily[]> = {
    soc2: [
      { id: 'CC1', name: 'CC1 - Control Environment', controls: [
        { controlId: 'CC1.1', name: 'COSO Principle 1: Integrity and Ethical Values', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-10' },
        { controlId: 'CC1.2', name: 'COSO Principle 2: Board Independence', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-10' },
        { controlId: 'CC1.3', name: 'COSO Principle 3: Management Structure', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-09' },
        { controlId: 'CC1.4', name: 'COSO Principle 4: Competence Commitment', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-08' },
        { controlId: 'CC1.5', name: 'COSO Principle 5: Accountability', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-10' },
      ]},
      { id: 'CC2', name: 'CC2 - Communication and Information', controls: [
        { controlId: 'CC2.1', name: 'COSO Principle 13: Quality Information', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-12' },
        { controlId: 'CC2.2', name: 'COSO Principle 14: Internal Communication', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-11' },
        { controlId: 'CC2.3', name: 'COSO Principle 15: External Communication', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-11' },
      ]},
      { id: 'CC3', name: 'CC3 - Risk Assessment', controls: [
        { controlId: 'CC3.1', name: 'COSO Principle 6: Risk Objectives', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-14' },
        { controlId: 'CC3.2', name: 'COSO Principle 7: Risk Identification', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-14' },
        { controlId: 'CC3.3', name: 'COSO Principle 8: Fraud Risk', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-13' },
        { controlId: 'CC3.4', name: 'COSO Principle 9: Change Identification', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-07' },
      ]},
      { id: 'CC6', name: 'CC6 - Logical and Physical Access', controls: [
        { controlId: 'CC6.1', name: 'Logical Access Security', evidenceStatus: 'met', artifactsCount: 8, lastReviewed: '2026-03-15' },
        { controlId: 'CC6.2', name: 'System Credentials Management', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-15' },
        { controlId: 'CC6.3', name: 'Access Authorization', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-14' },
        { controlId: 'CC6.6', name: 'Boundary Protection', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-15' },
        { controlId: 'CC6.7', name: 'Data Transmission Protection', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-12' },
        { controlId: 'CC6.8', name: 'Malicious Software Prevention', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-14' },
      ]},
      { id: 'CC7', name: 'CC7 - System Operations', controls: [
        { controlId: 'CC7.1', name: 'Infrastructure Monitoring', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-16' },
        { controlId: 'CC7.2', name: 'Anomaly Detection', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-16' },
        { controlId: 'CC7.3', name: 'Security Incident Evaluation', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-15' },
        { controlId: 'CC7.4', name: 'Incident Response', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-15' },
      ]},
    ],
    iso_27001: [
      { id: 'A5', name: 'A.5 - Organizational Controls', controls: [
        { controlId: 'A.5.1', name: 'Policies for Information Security', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-14' },
        { controlId: 'A.5.2', name: 'Information Security Roles', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-13' },
        { controlId: 'A.5.3', name: 'Segregation of Duties', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-13' },
        { controlId: 'A.5.4', name: 'Management Responsibilities', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-12' },
      ]},
      { id: 'A6', name: 'A.6 - People Controls', controls: [
        { controlId: 'A.6.1', name: 'Screening', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-11' },
        { controlId: 'A.6.2', name: 'Terms and Conditions of Employment', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-11' },
        { controlId: 'A.6.3', name: 'Information Security Awareness', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-10' },
      ]},
      { id: 'A7', name: 'A.7 - Physical Controls', controls: [
        { controlId: 'A.7.1', name: 'Physical Security Perimeters', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-12' },
        { controlId: 'A.7.2', name: 'Physical Entry', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-12' },
        { controlId: 'A.7.3', name: 'Securing Offices and Facilities', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-09' },
      ]},
      { id: 'A8', name: 'A.8 - Technological Controls', controls: [
        { controlId: 'A.8.1', name: 'User Endpoint Devices', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-14' },
        { controlId: 'A.8.2', name: 'Privileged Access Rights', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-14' },
        { controlId: 'A.8.3', name: 'Information Access Restriction', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-13' },
        { controlId: 'A.8.4', name: 'Access to Source Code', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-08' },
      ]},
    ],
    nist800_53: [
      { id: 'AC', name: 'AC - Access Control', controls: [
        { controlId: 'AC-1', name: 'Policy and Procedures', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-16' },
        { controlId: 'AC-2', name: 'Account Management', evidenceStatus: 'met', artifactsCount: 8, lastReviewed: '2026-03-16' },
        { controlId: 'AC-3', name: 'Access Enforcement', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-15' },
        { controlId: 'AC-4', name: 'Information Flow Enforcement', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-14' },
        { controlId: 'AC-5', name: 'Separation of Duties', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-14' },
        { controlId: 'AC-6', name: 'Least Privilege', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-15' },
      ]},
      { id: 'AU', name: 'AU - Audit and Accountability', controls: [
        { controlId: 'AU-1', name: 'Policy and Procedures', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-14' },
        { controlId: 'AU-2', name: 'Event Logging', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-15' },
        { controlId: 'AU-3', name: 'Content of Audit Records', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-14' },
        { controlId: 'AU-6', name: 'Audit Record Review', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-13' },
      ]},
      { id: 'SC', name: 'SC - System and Communications Protection', controls: [
        { controlId: 'SC-1', name: 'Policy and Procedures', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-13' },
        { controlId: 'SC-7', name: 'Boundary Protection', evidenceStatus: 'met', artifactsCount: 9, lastReviewed: '2026-03-16' },
        { controlId: 'SC-8', name: 'Transmission Confidentiality', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-15' },
        { controlId: 'SC-12', name: 'Cryptographic Key Management', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-08' },
        { controlId: 'SC-13', name: 'Cryptographic Protection', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-10' },
      ]},
    ],
    hipaa: [
      { id: 'AS', name: 'Administrative Safeguards', controls: [
        { controlId: '164.308(a)(1)', name: 'Security Management Process', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-13' },
        { controlId: '164.308(a)(2)', name: 'Assigned Security Responsibility', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-12' },
        { controlId: '164.308(a)(3)', name: 'Workforce Security', evidenceStatus: 'partial', artifactsCount: 4, lastReviewed: '2026-03-11' },
        { controlId: '164.308(a)(4)', name: 'Information Access Management', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-13' },
      ]},
      { id: 'PS', name: 'Physical Safeguards', controls: [
        { controlId: '164.310(a)', name: 'Facility Access Controls', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-10' },
        { controlId: '164.310(b)', name: 'Workstation Use', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-09' },
        { controlId: '164.310(c)', name: 'Workstation Security', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-10' },
        { controlId: '164.310(d)', name: 'Device and Media Controls', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-07' },
      ]},
      { id: 'TS', name: 'Technical Safeguards', controls: [
        { controlId: '164.312(a)', name: 'Access Control', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-13' },
        { controlId: '164.312(b)', name: 'Audit Controls', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-12' },
        { controlId: '164.312(c)', name: 'Integrity', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-11' },
        { controlId: '164.312(d)', name: 'Person or Entity Authentication', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-12' },
        { controlId: '164.312(e)', name: 'Transmission Security', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-10' },
      ]},
    ],
    gdpr: [
      { id: 'ART5', name: 'Article 5 - Data Processing Principles', controls: [
        { controlId: 'Art.5(1)(a)', name: 'Lawfulness, Fairness, Transparency', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-12' },
        { controlId: 'Art.5(1)(b)', name: 'Purpose Limitation', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-11' },
        { controlId: 'Art.5(1)(c)', name: 'Data Minimization', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-10' },
        { controlId: 'Art.5(1)(f)', name: 'Integrity and Confidentiality', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-12' },
      ]},
      { id: 'ART25', name: 'Article 25 - Data Protection by Design', controls: [
        { controlId: 'Art.25(1)', name: 'Data Protection by Design', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-09' },
        { controlId: 'Art.25(2)', name: 'Data Protection by Default', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-07' },
      ]},
      { id: 'ART32', name: 'Article 32 - Security of Processing', controls: [
        { controlId: 'Art.32(1)(a)', name: 'Pseudonymisation and Encryption', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-11' },
        { controlId: 'Art.32(1)(b)', name: 'Confidentiality and Integrity', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-11' },
        { controlId: 'Art.32(1)(c)', name: 'Availability and Resilience', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-10' },
        { controlId: 'Art.32(1)(d)', name: 'Testing and Evaluation', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-08' },
      ]},
    ],
    fedramp: [
      { id: 'AC', name: 'AC - Access Control', controls: [
        { controlId: 'AC-1', name: 'Access Control Policy', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-10' },
        { controlId: 'AC-2', name: 'Account Management', evidenceStatus: 'partial', artifactsCount: 4, lastReviewed: '2026-03-09' },
        { controlId: 'AC-3', name: 'Access Enforcement', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-08' },
        { controlId: 'AC-6', name: 'Least Privilege', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-05' },
      ]},
      { id: 'RA', name: 'RA - Risk Assessment', controls: [
        { controlId: 'RA-1', name: 'Risk Assessment Policy', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-08' },
        { controlId: 'RA-3', name: 'Risk Assessment', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-07' },
        { controlId: 'RA-5', name: 'Vulnerability Monitoring', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-10' },
      ]},
      { id: 'SI', name: 'SI - System and Information Integrity', controls: [
        { controlId: 'SI-1', name: 'System and Info Integrity Policy', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-09' },
        { controlId: 'SI-2', name: 'Flaw Remediation', evidenceStatus: 'not_met', artifactsCount: 2, lastReviewed: '2026-03-06' },
        { controlId: 'SI-4', name: 'System Monitoring', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-08' },
      ]},
    ],
    cmmc: [
      { id: 'CMMC-AC', name: 'AC - Access Control', controls: [
        { controlId: 'AC.L2-3.1.1', name: 'Authorized Access Control', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-11' },
        { controlId: 'AC.L2-3.1.2', name: 'Transaction and Function Control', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-11' },
        { controlId: 'AC.L2-3.1.3', name: 'CUI Flow Control', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-10' },
        { controlId: 'AC.L2-3.1.5', name: 'Least Privilege', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-11' },
      ]},
      { id: 'CMMC-IA', name: 'IA - Identification and Authentication', controls: [
        { controlId: 'IA.L2-3.5.1', name: 'Identification', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-10' },
        { controlId: 'IA.L2-3.5.2', name: 'Authentication', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-10' },
        { controlId: 'IA.L2-3.5.3', name: 'Multifactor Authentication', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-11' },
      ]},
    ],
    pci_dss: [
      { id: 'REQ1', name: 'Req 1 - Network Security Controls', controls: [
        { controlId: '1.2.1', name: 'Inbound Traffic Restriction', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-16' },
        { controlId: '1.2.5', name: 'Services and Ports Permitted', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-16' },
        { controlId: '1.3.1', name: 'Inbound Traffic to CDE', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-15' },
        { controlId: '1.4.1', name: 'NSC Between Trusted and Untrusted', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-15' },
      ]},
      { id: 'REQ3', name: 'Req 3 - Account Data Protection', controls: [
        { controlId: '3.3.1', name: 'SAD Not Stored After Authorization', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-15' },
        { controlId: '3.4.1', name: 'PAN Masked When Displayed', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-14' },
        { controlId: '3.5.1', name: 'PAN Rendered Unreadable', evidenceStatus: 'met', artifactsCount: 6, lastReviewed: '2026-03-15' },
      ]},
      { id: 'REQ8', name: 'Req 8 - User Identification and Authentication', controls: [
        { controlId: '8.2.1', name: 'Unique User IDs', evidenceStatus: 'met', artifactsCount: 5, lastReviewed: '2026-03-16' },
        { controlId: '8.3.1', name: 'Multi-Factor Authentication', evidenceStatus: 'met', artifactsCount: 7, lastReviewed: '2026-03-16' },
        { controlId: '8.3.6', name: 'Password Complexity', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-15' },
        { controlId: '8.6.1', name: 'System Account Management', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-12' },
      ]},
    ],
    iso42001: [
      { id: 'AI-4', name: '4 - Context of the Organization', controls: [
        { controlId: '4.1', name: 'Understanding the Organization', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-09' },
        { controlId: '4.2', name: 'Understanding Stakeholder Needs', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-07' },
        { controlId: '4.3', name: 'Determining AIMS Scope', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-05' },
      ]},
      { id: 'AI-6', name: '6 - Planning', controls: [
        { controlId: '6.1', name: 'AI Risk Assessment', evidenceStatus: 'partial', artifactsCount: 3, lastReviewed: '2026-03-08' },
        { controlId: '6.2', name: 'AI System Impact Assessment', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-05' },
        { controlId: '6.3', name: 'AI Objectives and Planning', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-06' },
      ]},
      { id: 'AI-8', name: '8 - Operation', controls: [
        { controlId: '8.1', name: 'Operational Planning and Control', evidenceStatus: 'met', artifactsCount: 4, lastReviewed: '2026-03-09' },
        { controlId: '8.2', name: 'AI Risk Assessment', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-07' },
        { controlId: '8.3', name: 'AI Risk Treatment', evidenceStatus: 'not_met', artifactsCount: 1, lastReviewed: '2026-03-04' },
        { controlId: '8.4', name: 'AI System Impact Assessment', evidenceStatus: 'not_met', artifactsCount: 0, lastReviewed: '2026-03-03' },
      ]},
    ],
  };
  return familyMap[frameworkId] || [
    { id: 'GEN', name: 'General Controls', controls: [
      { controlId: 'GEN-1', name: 'General Control 1', evidenceStatus: 'met', artifactsCount: 3, lastReviewed: '2026-03-10' },
      { controlId: 'GEN-2', name: 'General Control 2', evidenceStatus: 'partial', artifactsCount: 2, lastReviewed: '2026-03-08' },
    ]},
  ];
}

function getDemoControlDetail(controlId: string): ControlDetail {
  return {
    controlId,
    name: `Control ${controlId}`,
    description: `This control ensures that the organization implements appropriate security measures related to ${controlId}. It establishes requirements for policy documentation, implementation procedures, and ongoing monitoring to maintain compliance with applicable standards and regulations.`,
    implementation: `The organization has implemented this control through a combination of automated tooling and manual processes. Technical enforcement is provided via IAM policies, network segmentation rules, and continuous monitoring through our SIEM platform. Administrative controls include documented policies reviewed quarterly, security awareness training, and defined roles and responsibilities.`,
    testingProcedure: `1. Review policy documentation for completeness and currency\n2. Inspect technical configuration against baseline requirements\n3. Sample test: verify enforcement for 25 randomly selected users/resources\n4. Review monitoring alerts and incident response logs for the assessment period\n5. Interview control owner to confirm ongoing operation`,
    reviewer: 'Sarah Chen',
    reviewDate: '2026-03-14',
    status: 'Implemented',
    statusNotes: 'Control is fully implemented and operating effectively. All evidence artifacts have been verified and are current within the assessment period.',
    artifacts: [
      { name: 'Information Security Policy v4.2', type: 'Policy', collectionMethod: 'Manual', collectedDate: '2026-03-01', description: 'Corporate information security policy covering this control area', contentPreview: 'Section 4.3: The organization shall implement and maintain access control mechanisms that restrict system access to authorized users...' },
      { name: 'AWS IAM Configuration Export', type: 'Config', collectionMethod: 'Automated', collectedDate: '2026-03-15', description: 'Exported IAM roles, policies, and permission boundaries from production AWS accounts', contentPreview: '{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}}]}' },
      { name: 'CloudTrail Access Logs - March 2026', type: 'Log', collectionMethod: 'Automated', collectedDate: '2026-03-16', description: 'CloudTrail logs showing access events for the current assessment period', contentPreview: 'EventTime: 2026-03-16T10:23:45Z | EventName: ConsoleLogin | SourceIP: 10.0.1.45 | MFAUsed: Yes | Result: Success...' },
      { name: 'Q1 2026 Access Review Report', type: 'Report', collectionMethod: 'Manual', collectedDate: '2026-03-10', description: 'Quarterly access review documenting verification of all user accounts and permissions', contentPreview: 'Access Review Summary: 342 accounts reviewed, 12 terminated accounts removed, 8 excessive permissions corrected, 100% completion rate...' },
      { name: 'SOC 2 Type II Attestation (Current)', type: 'Certificate', collectionMethod: 'Manual', collectedDate: '2026-02-15', description: 'Current SOC 2 Type II attestation report from external auditor covering the relevant trust service criteria', contentPreview: 'Independent Service Auditor Report: In our opinion, the description of the system fairly presents the system that was designed and implemented...' },
    ],
  };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const ARTIFACT_TYPE_STYLES: Record<string, string> = {
  Policy: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  Config: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  Log: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  Report: 'bg-violet-500/10 text-violet-400 border-violet-500/20',
  Certificate: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
};

const ACTIVITY_TYPE_ICONS: Record<string, typeof Activity> = {
  collection: Package,
  review: FileCheck,
  status_change: RefreshCw,
};

function EvidenceStatusBadge({ status }: { status: string }) {
  if (status === 'met') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
        <CheckCircle className="w-3 h-3" /> Met
      </span>
    );
  }
  if (status === 'partial') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/20">
        <AlertTriangle className="w-3 h-3" /> Partial
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/20">
      <XCircle className="w-3 h-3" /> Not Met
    </span>
  );
}

function FrameworkStatusBadge({ status }: { status: string }) {
  if (status === 'Ready for Audit') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        <CheckCircle className="w-3.5 h-3.5" /> Ready for Audit
      </span>
    );
  }
  if (status === 'In Progress') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
        <Clock className="w-3.5 h-3.5" /> In Progress
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
      <AlertCircle className="w-3.5 h-3.5" /> Needs Attention
    </span>
  );
}

function completenessColor(pct: number): string {
  if (pct >= 90) return 'bg-emerald-500';
  if (pct >= 70) return 'bg-amber-500';
  return 'bg-red-500';
}

function completenessBorder(pct: number): string {
  if (pct >= 90) return 'border-emerald-500/30';
  if (pct >= 70) return 'border-amber-500/30';
  return 'border-red-500/30';
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function AuditorPortalPage() {
  const navigate = useNavigate();
  const [frameworks, setFrameworks] = useState<FrameworkSummary[]>([]);
  const [summary, setSummary] = useState<PortalSummary | null>(null);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<FrameworkSummary | null>(null);
  const [selectedControl, setSelectedControl] = useState<ControlDetail | null>(null);
  const [controlFamilies, setControlFamilies] = useState<ControlFamily[]>([]);
  const [expandedFamilies, setExpandedFamilies] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [controlLoading, setControlLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [downloadFilter, setDownloadFilter] = useState({ framework: 'all', status: 'all', format: 'zip' });
  const [oscalDocType, setOscalDocType] = useState('assessment-results');
  const [oscalFormat, setOscalFormat] = useState('json');
  const [oscalExporting, setOscalExporting] = useState(false);
  const isPublicRoute = typeof window !== 'undefined' && (window.location.pathname === '/auditor');

  // Auth check for public route
  useEffect(() => {
    if (isPublicRoute && !localStorage.getItem('grc_token')) {
      navigate('/auditor-login');
    }
  }, [isPublicRoute, navigate]);

  // Load initial data
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [sumRes, fwRes, actRes] = await Promise.all([
          api.get('/auditor/summary'),
          api.get('/auditor/frameworks'),
          api.get('/auditor/recent-activity'),
        ]);

        // Bug 1+2: Map API summary → PortalSummary
        const sumApi = sumRes.data;
        const mappedSummary: PortalSummary = {
          totalControls: sumApi.overall.total_controls,
          evidenceArtifacts: sumApi.overall.total_artifacts,
          frameworkCount: sumApi.overall.total_frameworks,
          lastUpdated: sumApi.generated_at,
          frameworkScores: (sumApi.frameworks || []).map((fw: any) => ({
            name: fw.framework_name,
            abbreviation: fw.framework_name.split(' ')[0],
            score: fw.compliance_pct,
            color: '#3b82f6',
          })),
        };

        // Bug 1+2: Unwrap + map API frameworks → FrameworkSummary[]
        const fwApi = fwRes.data.frameworks || [];
        const mappedFrameworks: FrameworkSummary[] = fwApi.map((fw: any) => {
          const pct = fw.stats?.compliance_pct ?? 0;
          let status: FrameworkSummary['status'] = 'Needs Attention';
          if (pct >= 90) status = 'Ready for Audit';
          else if (pct >= 70) status = 'In Progress';
          return {
            id: fw.id,
            name: fw.name,
            version: fw.version,
            abbreviation: fw.abbreviation || fw.name.split(' ')[0],
            color: fw.color || '#3b82f6',
            totalControls: fw.stats?.total_controls ?? 0,
            evidenceCompleteness: pct,
            status,
            controlFamilies: fw.stats?.families?.length ?? 0,
            lastUpdated: sumApi.generated_at,
          } as FrameworkSummary;
        });

        // Update frameworkScores with real abbreviation/color from frameworks
        mappedSummary.frameworkScores = mappedFrameworks.map(fw => ({
          name: fw.name,
          abbreviation: fw.abbreviation,
          score: fw.evidenceCompleteness,
          color: fw.color,
        }));

        // Bug 5: Unwrap + map activity { action, details } → ActivityEvent { type, message, id }
        const actApi = actRes.data.activities || [];
        const mappedActivity: ActivityEvent[] = actApi.map((a: any, i: number) => {
          const actionToType: Record<string, ActivityEvent['type']> = {
            evidence_collected: 'collection',
            evidence_reviewed: 'review',
            artifact_uploaded: 'collection',
            status_updated: 'status_change',
            control_assessed: 'review',
            package_generated: 'collection',
          };
          return {
            id: String(i + 1),
            type: actionToType[a.action] || 'collection',
            message: a.details || a.action,
            framework: a.framework || '',
            actor: a.actor || 'System',
            timestamp: a.timestamp,
          } as ActivityEvent;
        });

        setSummary(mappedSummary);
        setFrameworks(mappedFrameworks);
        setActivity(mappedActivity);
      } catch {
        setSummary(DEMO_SUMMARY);
        setFrameworks(DEMO_FRAMEWORKS);
        setActivity(DEMO_ACTIVITY);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Load framework details
  useEffect(() => {
    if (!selectedFramework) {
      setControlFamilies([]);
      setSelectedControl(null);
      return;
    }
    async function loadFrameworkDetail() {
      setDetailLoading(true);
      setSelectedControl(null);
      try {
        const res = await api.get(`/auditor/frameworks/${selectedFramework!.id}/controls`);
        // Bug 4: Group flat controls list into ControlFamily[]
        const flatControls: any[] = res.data.controls || [];
        const familyMap = new Map<string, ControlFamily>();
        for (const c of flatControls) {
          const famId = c.family || 'OTHER';
          if (!familyMap.has(famId)) {
            familyMap.set(famId, { id: famId, name: famId, controls: [] });
          }
          const statusMap: Record<string, ControlSummary['evidenceStatus']> = {
            satisfied: 'met',
            partially_satisfied: 'partial',
            gap: 'not_met',
          };
          familyMap.get(famId)!.controls.push({
            controlId: c.control_id,
            name: c.control_title,
            evidenceStatus: statusMap[c.status] || 'not_met',
            artifactsCount: c.artifact_count ?? 0,
            lastReviewed: c.collected_at ? c.collected_at.split('T')[0] : '',
          });
        }
        setControlFamilies(Array.from(familyMap.values()));
      } catch {
        setControlFamilies(getDemoControlFamilies(selectedFramework!.id));
      } finally {
        setDetailLoading(false);
      }
    }
    loadFrameworkDetail();
  }, [selectedFramework]);

  // Load control detail
  async function loadControlDetail(frameworkId: string, controlId: string) {
    setControlLoading(true);
    try {
      const res = await api.get(`/auditor/frameworks/${frameworkId}/controls/${controlId}`);
      const e = res.data.evidence || res.data;
      const typeMap: Record<string, string> = {
        policy: 'Policy', configuration: 'Config', log: 'Log', report: 'Report', certificate: 'Certificate',
        procedure: 'Policy', screenshot: 'Report',
      };
      const mapped: ControlDetail = {
        controlId: e.control_id,
        name: e.control_title,
        description: e.description,
        implementation: e.implementation_details || '',
        testingProcedure: e.testing_procedure || '',
        reviewer: e.reviewer || '',
        reviewDate: e.last_reviewed || '',
        status: e.status === 'satisfied' ? 'Implemented' : e.status === 'partially_satisfied' ? 'Partially Implemented' : 'Gap',
        statusNotes: `Evidence status: ${e.status}`,
        artifacts: (e.artifacts || []).map((a: any) => ({
          name: a.name,
          type: (typeMap[a.type] || 'Report') as Artifact['type'],
          collectionMethod: (e.collector === 'automated' ? 'Automated' : 'Manual') as Artifact['collectionMethod'],
          collectedDate: e.collected_at ? e.collected_at.split('T')[0] : '',
          description: a.content_summary || '',
          contentPreview: a.content_summary || '',
        })),
      };
      setSelectedControl(mapped);
    } catch {
      setSelectedControl(getDemoControlDetail(controlId));
    } finally {
      setControlLoading(false);
    }
  }

  // Download handler
  async function handleDownload(frameworkId: string, frameworkName: string) {
    try {
      const res = await api.get(`/auditor/frameworks/${frameworkId}/download`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${frameworkName.replace(/\s+/g, '_')}_evidence_package.zip`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      // Demo mode: show notification
      alert(`Download initiated for ${frameworkName} evidence package (demo mode - API not available)`);
    }
  }

  // OSCAL export handler
  async function handleOscalExport(frameworkId: string, frameworkName: string) {
    setOscalExporting(true);
    try {
      const res = await api.get(
        `/auditor/frameworks/${frameworkId}/oscal?document_type=${oscalDocType}&format=${oscalFormat}`,
        { responseType: 'blob' }
      );
      const ext = oscalFormat === 'xml' ? 'zip' : 'json';
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `oscal_${oscalDocType}_${frameworkName.replace(/\s+/g, '_')}.${ext}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      alert(`OSCAL export failed for ${frameworkName} (demo mode - API not available)`);
    } finally {
      setOscalExporting(false);
    }
  }

  // Toggle family expansion
  function toggleFamily(familyId: string) {
    setExpandedFamilies(prev => {
      const next = new Set(prev);
      if (next.has(familyId)) next.delete(familyId);
      else next.add(familyId);
      return next;
    });
  }

  // Filtered frameworks
  const filteredFrameworks = useMemo(() => {
    let filtered = frameworks;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(f =>
        f.name.toLowerCase().includes(q) ||
        f.abbreviation.toLowerCase().includes(q)
      );
    }
    if (statusFilter !== 'all') {
      filtered = filtered.filter(f => f.status === statusFilter);
    }
    return filtered;
  }, [frameworks, searchQuery, statusFilter]);

  // Filtered control families
  const filteredFamilies = useMemo(() => {
    if (!searchQuery && statusFilter === 'all') return controlFamilies;
    return controlFamilies.map(family => {
      const controls = family.controls.filter(c => {
        const matchesSearch = !searchQuery ||
          c.controlId.toLowerCase().includes(searchQuery.toLowerCase()) ||
          c.name.toLowerCase().includes(searchQuery.toLowerCase());
        const matchesStatus = statusFilter === 'all' || c.evidenceStatus === statusFilter;
        return matchesSearch && matchesStatus;
      });
      return { ...family, controls };
    }).filter(family => family.controls.length > 0);
  }, [controlFamilies, searchQuery, statusFilter]);

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
          <p className="text-sm text-slate-400">Loading auditor portal...</p>
        </div>
      </div>
    );
  }

  // ---- Framework Detail View ----
  if (selectedFramework) {
    return (
      <div className="space-y-5 page-enter text-[var(--text-heading)]">
        {/* Back nav + framework header */}
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
          <button
            onClick={() => { setSelectedFramework(null); setSelectedControl(null); setSearchQuery(''); setStatusFilter('all'); }}
            className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-[var(--text-heading)] transition-colors mb-4"
          >
            <ArrowLeft className="w-4 h-4" /> Back to All Frameworks
          </button>
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center text-lg font-extrabold text-[var(--text-heading)] shrink-0"
                style={{ backgroundColor: selectedFramework.color + '22', border: `1px solid ${selectedFramework.color}44` }}
              >
                {selectedFramework.abbreviation}
              </div>
              <div>
                <h2 className="text-xl font-bold text-[var(--text-heading)]">{selectedFramework.name}</h2>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-xs text-slate-400">Version {selectedFramework.version}</span>
                  <span className="text-xs text-slate-500">|</span>
                  <span className="text-xs text-slate-400">{selectedFramework.totalControls} Controls</span>
                  <span className="text-xs text-slate-500">|</span>
                  <FrameworkStatusBadge status={selectedFramework.status} />
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleDownload(selectedFramework.id, selectedFramework.name)}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20"
              >
                <Download className="w-4 h-4" /> Download Evidence Package
              </button>
            </div>
          </div>
          {/* Completeness bar */}
          <div className="mt-4">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-slate-400">Evidence Completeness</span>
              <span className="text-xs font-bold text-[var(--text-heading)]">{selectedFramework.evidenceCompleteness}%</span>
            </div>
            <div className="h-2.5 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${completenessColor(selectedFramework.evidenceCompleteness)}`}
                style={{ width: `${selectedFramework.evidenceCompleteness}%` }}
              />
            </div>
          </div>
        </div>

        {/* OSCAL Export Section */}
        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-emerald-400" />
              <span className="text-sm font-bold text-[var(--text-heading)]">Export OSCAL</span>
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">OSCAL 1.1.2</span>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={oscalDocType}
                onChange={e => setOscalDocType(e.target.value)}
                className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50"
              >
                <option value="assessment-results">Assessment Results</option>
                <option value="poam">Plan of Action &amp; Milestones</option>
                <option value="ssp">System Security Plan</option>
              </select>
              <select
                value={oscalFormat}
                onChange={e => setOscalFormat(e.target.value)}
                className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50"
              >
                <option value="json">JSON</option>
                <option value="xml">XML</option>
              </select>
              <button
                onClick={() => handleOscalExport(selectedFramework.id, selectedFramework.name)}
                disabled={oscalExporting}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-[var(--text-heading)] transition-all disabled:opacity-50"
              >
                {oscalExporting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                Export OSCAL
              </button>
              <span className="flex items-center gap-1 text-[9px] text-emerald-400/70">
                <Shield className="w-3 h-3" /> Signed &amp; verifiable
              </span>
            </div>
          </div>
        </div>

        {/* Search & filters */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search controls..."
              className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl pl-10 pr-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-500" />
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50"
            >
              <option value="all">All Statuses</option>
              <option value="met">Met</option>
              <option value="partial">Partial</option>
              <option value="not_met">Not Met</option>
            </select>
          </div>
        </div>

        {/* Content area: families + detail panel */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
          {/* Control Families Accordion */}
          <div className={`space-y-3 ${selectedControl ? 'lg:col-span-3' : 'lg:col-span-5'}`}>
            {detailLoading ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
              </div>
            ) : filteredFamilies.length === 0 ? (
              <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-10 text-center">
                <Search className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                <p className="text-sm font-semibold text-slate-400">No controls match your filters</p>
                <p className="text-xs text-slate-500 mt-1">Try adjusting your search query or status filter</p>
              </div>
            ) : (
              filteredFamilies.map(family => {
                const isExpanded = expandedFamilies.has(family.id);
                const metCount = family.controls.filter(c => c.evidenceStatus === 'met').length;
                const total = family.controls.length;
                return (
                  <div key={family.id} className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
                    <button
                      onClick={() => toggleFamily(family.id)}
                      className="w-full flex items-center justify-between px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        {isExpanded
                          ? <ChevronDown className="w-4 h-4 text-slate-400" />
                          : <ChevronRight className="w-4 h-4 text-slate-400" />
                        }
                        <span className="text-sm font-bold text-[var(--text-heading)]">{family.name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--bg-interactive)] text-slate-400 border border-[var(--border-color)]">
                          {total} controls
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-400">{metCount}/{total} met</span>
                        <div className="w-24 h-1.5 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${completenessColor(total > 0 ? (metCount / total) * 100 : 0)}`}
                            style={{ width: `${total > 0 ? (metCount / total) * 100 : 0}%` }}
                          />
                        </div>
                      </div>
                    </button>
                    {isExpanded && (
                      <div className="border-t border-[var(--border-subtle)]">
                        <table className="w-full">
                          <thead>
                            <tr className="text-[10px] uppercase tracking-wider text-slate-500 border-b border-[var(--border-subtle)]">
                              <th className="px-5 py-2.5 text-left font-semibold">Control ID</th>
                              <th className="px-5 py-2.5 text-left font-semibold">Control Name</th>
                              <th className="px-5 py-2.5 text-center font-semibold">Status</th>
                              <th className="px-5 py-2.5 text-center font-semibold">Artifacts</th>
                              <th className="px-5 py-2.5 text-left font-semibold">Last Reviewed</th>
                              <th className="px-5 py-2.5 text-center font-semibold">Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[var(--border-subtle)]">
                            {family.controls.map(control => (
                              <tr
                                key={control.controlId}
                                className={`hover:bg-[var(--bg-subtle)] transition-colors ${selectedControl?.controlId === control.controlId ? 'bg-blue-500/5' : ''}`}
                              >
                                <td className="px-5 py-3">
                                  <span className="font-mono text-xs font-bold text-slate-300">{control.controlId}</span>
                                </td>
                                <td className="px-5 py-3 text-xs text-slate-300 max-w-[240px] truncate">{control.name}</td>
                                <td className="px-5 py-3 text-center">
                                  <EvidenceStatusBadge status={control.evidenceStatus} />
                                </td>
                                <td className="px-5 py-3 text-center">
                                  <span className="text-xs text-slate-400">{control.artifactsCount}</span>
                                </td>
                                <td className="px-5 py-3 text-xs text-slate-500">{control.lastReviewed}</td>
                                <td className="px-5 py-3 text-center">
                                  <button
                                    onClick={() => loadControlDetail(selectedFramework.id, control.controlId)}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-[10px] font-semibold text-blue-400 transition-colors"
                                  >
                                    <Eye className="w-3 h-3" /> View
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>

          {/* Control Detail Panel */}
          {selectedControl && (
            <div className="lg:col-span-2">
              <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden sticky top-4 max-h-[calc(100vh-8rem)] flex flex-col">
                {controlLoading ? (
                  <div className="flex items-center justify-center py-16">
                    <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
                  </div>
                ) : (
                  <>
                    {/* Header */}
                    <div className="px-5 py-4 border-b border-[var(--border-color)] bg-blue-500/5 flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-xs font-bold bg-[var(--bg-interactive-hover)] px-2 py-0.5 rounded border border-[var(--border-color)] text-slate-300">{selectedControl.controlId}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">{selectedControl.status}</span>
                        </div>
                        <h3 className="text-sm font-bold text-[var(--text-heading)] mt-1">{selectedControl.name}</h3>
                      </div>
                      <button
                        onClick={() => setSelectedControl(null)}
                        className="p-1 rounded-lg hover:bg-[var(--bg-interactive-hover)] text-slate-400 transition-colors"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    {/* Scrollable content */}
                    <div className="flex-1 overflow-y-auto p-5 space-y-5">
                      {/* Description */}
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Description</h4>
                        <p className="text-xs text-slate-300 leading-relaxed">{selectedControl.description}</p>
                      </div>

                      {/* Implementation */}
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Implementation Details</h4>
                        <p className="text-xs text-slate-300 leading-relaxed">{selectedControl.implementation}</p>
                      </div>

                      {/* Evidence Artifacts */}
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                          Evidence Artifacts ({selectedControl.artifacts.length})
                        </h4>
                        <div className="space-y-2.5">
                          {selectedControl.artifacts.map((artifact, i) => (
                            <div key={i} className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3.5">
                              <div className="flex items-start justify-between gap-2 mb-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                                  <span className="text-xs font-semibold text-[var(--text-heading)]">{artifact.name}</span>
                                </div>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${ARTIFACT_TYPE_STYLES[artifact.type] || 'bg-[var(--bg-interactive)] text-slate-400 border-[var(--border-color)]'}`}>
                                    {artifact.type}
                                  </span>
                                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                                    artifact.collectionMethod === 'Automated'
                                      ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20'
                                      : 'bg-slate-500/10 text-slate-400 border-slate-500/20'
                                  }`}>
                                    {artifact.collectionMethod}
                                  </span>
                                </div>
                              </div>
                              <p className="text-[11px] text-slate-400 mb-1.5">{artifact.description}</p>
                              <div className="text-[10px] text-slate-500 mb-2">Collected: {artifact.collectedDate}</div>
                              <div className="bg-black/30 rounded-lg px-3 py-2 border border-[var(--border-subtle)]">
                                <p className="text-[10px] text-slate-400 font-mono leading-relaxed line-clamp-3">{artifact.contentPreview}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Testing Procedure */}
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Testing Procedure</h4>
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3.5">
                          <pre className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans">{selectedControl.testingProcedure}</pre>
                        </div>
                      </div>

                      {/* Review Info */}
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Reviewer</h4>
                          <div className="flex items-center gap-2">
                            <User className="w-3.5 h-3.5 text-blue-400" />
                            <span className="text-xs text-[var(--text-heading)] font-semibold">{selectedControl.reviewer}</span>
                          </div>
                        </div>
                        <div>
                          <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">Review Date</h4>
                          <div className="flex items-center gap-2">
                            <Calendar className="w-3.5 h-3.5 text-slate-400" />
                            <span className="text-xs text-slate-300">{selectedControl.reviewDate}</span>
                          </div>
                        </div>
                      </div>

                      {/* Status Notes */}
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">Status Notes</h4>
                        <p className="text-xs text-slate-300 leading-relaxed">{selectedControl.statusNotes}</p>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ---- Main Portal View ----
  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-5">
          <div>
            <h1 className="text-2xl font-extrabold text-[var(--text-heading)] flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
                <Shield className="w-5 h-5 text-[var(--text-heading)]" />
              </div>
              Auditor Evidence Portal
            </h1>
            <p className="text-sm text-slate-400 mt-1.5 ml-[52px]">Access compliance evidence packages across all frameworks</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                alert('Bulk download initiated for all frameworks (demo mode)');
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20"
            >
              <Archive className="w-4 h-4" /> Download All
            </button>
            {isPublicRoute && (
              <button
                onClick={() => {
                  localStorage.removeItem('grc_token');
                  navigate('/auditor-login');
                }}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-300 transition-all"
              >
                <LogOut className="w-4 h-4" /> Sign Out
              </button>
            )}
          </div>
        </div>

        {/* Cross-framework score bars */}
        {summary && (
          <div className="space-y-2.5">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Cross-Framework Compliance</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-9 gap-2.5">
              {summary.frameworkScores.map(fs => (
                <div key={fs.abbreviation} className="group">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-bold text-slate-400">{fs.abbreviation}</span>
                    <span className="text-[10px] font-bold text-slate-300">{fs.score}%</span>
                  </div>
                  <div className="h-2 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{ width: `${fs.score}%`, backgroundColor: fs.color }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Quick Stats */}
      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Total Controls Assessed', value: summary.totalControls.toLocaleString(), icon: Shield, cls: 'text-blue-400', border: 'border-blue-500/20', bg: 'bg-blue-500/10' },
            { label: 'Evidence Artifacts', value: summary.evidenceArtifacts.toLocaleString(), icon: FileText, cls: 'text-violet-400', border: 'border-violet-500/20', bg: 'bg-violet-500/10' },
            { label: 'Frameworks', value: summary.frameworkCount.toString(), icon: Layers, cls: 'text-cyan-400', border: 'border-cyan-500/20', bg: 'bg-cyan-500/10' },
            { label: 'Last Updated', value: new Date(summary.lastUpdated).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), icon: Clock, cls: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/10' },
          ].map(card => {
            const Icon = card.icon;
            return (
              <div key={card.label} className={`bg-[var(--bg-surface)] border ${card.border} rounded-2xl p-5`}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] text-slate-400 font-semibold">{card.label}</span>
                  <div className={`w-8 h-8 rounded-lg ${card.bg} flex items-center justify-center`}>
                    <Icon className={`w-4 h-4 ${card.cls}`} />
                  </div>
                </div>
                <p className={`text-2xl font-extrabold ${card.cls}`}>{card.value}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* Search & Filters */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search frameworks..."
            className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl pl-10 pr-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-[var(--text-heading)]">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50"
          >
            <option value="all">All Statuses</option>
            <option value="Ready for Audit">Ready for Audit</option>
            <option value="In Progress">In Progress</option>
            <option value="Needs Attention">Needs Attention</option>
          </select>
        </div>
      </div>

      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filteredFrameworks.map(fw => (
          <div
            key={fw.id}
            className={`bg-[var(--bg-surface)] border ${completenessBorder(fw.evidenceCompleteness)} rounded-2xl p-5 hover:bg-[var(--bg-subtle)] transition-all group`}
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div
                  className="w-11 h-11 rounded-xl flex items-center justify-center text-sm font-extrabold text-[var(--text-heading)] shrink-0"
                  style={{ backgroundColor: fw.color + '22', border: `1px solid ${fw.color}44` }}
                >
                  {fw.abbreviation}
                </div>
                <div>
                  <h3 className="text-sm font-bold text-[var(--text-heading)] group-hover:text-blue-400 transition-colors">{fw.name}</h3>
                  <span className="text-[10px] text-slate-500">Version {fw.version}</span>
                </div>
              </div>
              <FrameworkStatusBadge status={fw.status} />
            </div>

            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <span className="text-[10px] text-slate-500 block">Total Controls</span>
                <span className="text-lg font-bold text-[var(--text-heading)]">{fw.totalControls}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 block">Control Families</span>
                <span className="text-lg font-bold text-[var(--text-heading)]">{fw.controlFamilies}</span>
              </div>
            </div>

            {/* Completeness bar */}
            <div className="mb-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] text-slate-400">Evidence Completeness</span>
                <span className={`text-xs font-bold ${
                  fw.evidenceCompleteness >= 90 ? 'text-emerald-400' :
                  fw.evidenceCompleteness >= 70 ? 'text-amber-400' : 'text-red-400'
                }`}>{fw.evidenceCompleteness}%</span>
              </div>
              <div className="h-2 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${completenessColor(fw.evidenceCompleteness)}`}
                  style={{ width: `${fw.evidenceCompleteness}%` }}
                />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-500">Updated {fw.lastUpdated}</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={(e) => { e.stopPropagation(); handleDownload(fw.id, fw.name); }}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-[10px] font-semibold text-slate-300 transition-colors"
                >
                  <Download className="w-3 h-3" /> ZIP
                </button>
                <button
                  onClick={() => { setSelectedFramework(fw); setSearchQuery(''); setStatusFilter('all'); }}
                  className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-[10px] font-semibold text-blue-400 border border-blue-500/20 transition-colors"
                >
                  <Eye className="w-3 h-3" /> View Package
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredFrameworks.length === 0 && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-10 text-center">
          <Search className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <p className="text-sm font-semibold text-slate-400">No frameworks match your filters</p>
          <p className="text-xs text-slate-500 mt-1">Try adjusting your search query or status filter</p>
        </div>
      )}

      {/* Download & Export Section */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2 mb-4">
          <Download className="w-4 h-4 text-blue-400" /> Bulk Download & Export
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-4">
          <div>
            <label className="text-[10px] text-slate-500 block mb-1 font-semibold uppercase tracking-wider">Framework</label>
            <select
              value={downloadFilter.framework}
              onChange={e => setDownloadFilter({ ...downloadFilter, framework: e.target.value })}
              className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50"
            >
              <option value="all">All Frameworks</option>
              {frameworks.map(f => (
                <option key={f.id} value={f.id}>{f.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[10px] text-slate-500 block mb-1 font-semibold uppercase tracking-wider">Evidence Status</label>
            <select
              value={downloadFilter.status}
              onChange={e => setDownloadFilter({ ...downloadFilter, status: e.target.value })}
              className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50"
            >
              <option value="all">All Statuses</option>
              <option value="met">Met</option>
              <option value="partial">Partial</option>
              <option value="not_met">Not Met</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] text-slate-500 block mb-1 font-semibold uppercase tracking-wider">Export Format</label>
            <select
              value={downloadFilter.format}
              onChange={e => setDownloadFilter({ ...downloadFilter, format: e.target.value })}
              className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50"
            >
              <option value="zip">ZIP Archive</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={() => {
                const target = downloadFilter.framework === 'all' ? 'all frameworks' : frameworks.find(f => f.id === downloadFilter.framework)?.name || downloadFilter.framework;
                alert(`Exporting ${target} as ${downloadFilter.format.toUpperCase()} (demo mode)`);
              }}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20"
            >
              <Download className="w-4 h-4" /> Export
            </button>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {frameworks.map(fw => (
            <button
              key={fw.id}
              onClick={() => handleDownload(fw.id, fw.name)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-[10px] font-semibold text-slate-300 border border-[var(--border-subtle)] transition-colors"
            >
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: fw.color }} />
              {fw.abbreviation}
              <Download className="w-2.5 h-2.5 text-slate-500" />
            </button>
          ))}
        </div>
      </div>

      {/* Activity Feed */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[var(--border-subtle)]">
          <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-400" /> Recent Audit Activity
          </h3>
        </div>
        {activity.length === 0 ? (
          <div className="py-12 flex flex-col items-center gap-2 text-slate-500">
            <Activity className="w-8 h-8 text-slate-600" />
            <p className="text-xs">No recent activity</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {activity.map(evt => {
              const Icon = ACTIVITY_TYPE_ICONS[evt.type] || Activity;
              const typeStyle = evt.type === 'collection'
                ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400'
                : evt.type === 'review'
                ? 'bg-violet-500/10 border-violet-500/20 text-violet-400'
                : 'bg-amber-500/10 border-amber-500/20 text-amber-400';
              return (
                <div key={evt.id} className="px-5 py-3.5 hover:bg-[var(--bg-subtle)] transition-colors flex items-start gap-3">
                  <div className={`w-7 h-7 rounded-lg ${typeStyle} border flex items-center justify-center shrink-0 mt-0.5`}>
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-300 leading-relaxed">{evt.message}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[10px] text-slate-500">{evt.framework}</span>
                      <span className="text-[10px] text-slate-600">|</span>
                      <span className="text-[10px] text-slate-500">{evt.actor}</span>
                      <span className="text-[10px] text-slate-600">|</span>
                      <span className="text-[10px] text-slate-500">{new Date(evt.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
