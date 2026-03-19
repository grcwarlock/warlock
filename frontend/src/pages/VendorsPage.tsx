import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users, Shield, Search, AlertTriangle, CheckCircle, Calendar,
  ArrowLeft, FileText, ClipboardList, BarChart3, Flag,
  ChevronRight, X, Loader2, Upload, Clock, TrendingUp, Plus
} from 'lucide-react';
import api from '../lib/api';

/* ── Types ──────────────────────────────────────────────────────────── */

interface VendorResponse {
  id: string;
  name: string;
  category: string;
  criticality: string;
  contract_end: string;
  risk_score: number | null;
  risk_level: string | null;
  certifications: string[];
  last_assessment_date: string | null;
  is_active: boolean;
}

interface RiskComponent {
  value: number;
  description: string;
  details?: Array<{ certification: string; weight: number }>;
  days_since_assessment?: number | null;
}

interface VendorDetail extends VendorResponse {
  data_classification: string;
  contract_start: string | null;
  primary_contact: string | null;
  sla_uptime_target: number | null;
  assessment_frequency_days: number | null;
  notes: string | null;
  risk_breakdown: {
    total_score: number;
    risk_level: string;
    components: Record<string, RiskComponent>;
  };
  compliance_status: Array<{
    framework: string;
    framework_label: string;
    status: string;
    last_verified: string;
    controls_assessed: number;
    controls_passing: number;
    notes: string | null;
  }>;
  assessment_history: Array<{
    id: string;
    assessment_date: string;
    assessor: string;
    assessment_type: string;
    risk_score: number | null;
    risk_level: string | null;
    findings_count: number;
    critical_findings: number;
    status: string;
    summary: string;
  }>;
  documents: Array<{
    id: string;
    document_type: string;
    name: string;
    file_name: string;
    uploaded_at: string;
    uploaded_by: string;
    expiry_date: string | null;
    status: string;
    size_bytes: number;
  }>;
  linked_questionnaire_ids: string[];
  risk_overrides: Array<{
    id: string;
    previous_score: number | null;
    new_score: number;
    new_level: string;
    justification: string;
    override_by: string;
    created_at: string;
  }>;
  review_flags: Array<{
    id: string;
    reason: string;
    flagged_by: string;
    priority: string;
    status: string;
    created_at: string;
  }>;
}

/* ── Constants ──────────────────────────────────────────────────────── */

const RISK_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low:      'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
};

const RISK_BAR_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-emerald-500',
};

const COMPLIANCE_CLASSES: Record<string, string> = {
  compliant: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  partial: 'bg-amber-500/15 text-amber-400 border-amber-500/20',
  non_compliant: 'bg-red-500/15 text-red-400 border-red-500/20',
};

const CATEGORY_ICONS: Record<string, string> = {
  cloud_infrastructure: '\u2601\uFE0F',
  source_control: '\uD83D\uDC19',
  identity_access_management: '\uD83D\uDD10',
  security_monitoring: '\uD83D\uDCCA',
  endpoint_security: '\uD83D\uDEE1\uFE0F',
  observability: '\uD83D\uDD2D',
  application_security: '\uD83D\uDD0D',
  crm: '\uD83D\uDC65',
  payment_processing: '\uD83D\uDCB3',
  communications: '\uD83D\uDCF1',
  database: '\uD83D\uDDC4\uFE0F',
  cdn_security: '\uD83C\uDF10',
  incident_management: '\uD83D\uDEA8',
  project_management: '\uD83D\uDCCB',
};

const DOC_TYPE_LABELS: Record<string, string> = {
  soc2_report: 'SOC 2 Report',
  baa: 'BAA Agreement',
  security_policy: 'Security Policy',
  pen_test: 'Penetration Test',
  iso_cert: 'ISO 27001 Certificate',
  insurance: 'Cyber Insurance',
};

/* ── Create Vendor Form Data ────────────────────────────────────────── */

const CATEGORY_OPTIONS = [
  'cloud_infrastructure', 'source_control', 'identity_access_management',
  'security_monitoring', 'endpoint_security', 'observability',
  'application_security', 'crm', 'payment_processing', 'communications',
  'database', 'cdn_security', 'incident_management', 'project_management',
  'SaaS', 'IaaS', 'PaaS', 'Consulting', 'Hardware', 'Other',
];

/* ── Main Component ─────────────────────────────────────────────────── */

export default function VendorsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [selectedVendorId, setSelectedVendorId] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Action modals
  const [showQuestionnaireModal, setShowQuestionnaireModal] = useState(false);
  const [showAssessmentModal, setShowAssessmentModal] = useState(false);
  const [showRiskOverrideModal, setShowRiskOverrideModal] = useState(false);
  const [showFlagModal, setShowFlagModal] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);

  // Create form state
  const [createForm, setCreateForm] = useState({
    name: '', category: 'SaaS', criticality: 'Medium',
    data_classification: 'Internal',
    contract_start: new Date().toISOString().split('T')[0],
    contract_end: new Date(Date.now() + 365 * 86400000).toISOString().split('T')[0],
    certifications: [] as string[], sla_uptime_target: 99.9,
    primary_contact: '', notes: '',
  });

  const { data: vendors, isLoading } = useQuery<VendorResponse[]>({
    queryKey: ['vendors'],
    queryFn: async () => (await api.get('/vendors/')).data,
  });

  const { data: vendorDetail, isLoading: detailLoading } = useQuery<VendorDetail>({
    queryKey: ['vendor-detail', selectedVendorId],
    queryFn: async () => (await api.get(`/vendors/${selectedVendorId}`)).data,
    enabled: !!selectedVendorId,
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof createForm) => api.post('/vendors/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendors'] });
      setShowCreateForm(false);
    },
  });

  const questionnaireMutation = useMutation({
    mutationFn: async (data: { vendor_id: string; questionnaire_type: string; notes: string }) =>
      api.post(`/vendors/${data.vendor_id}/questionnaire`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-detail', selectedVendorId] });
      setShowQuestionnaireModal(false);
    },
  });

  const assessmentMutation = useMutation({
    mutationFn: async (data: { vendor_id: string; assessment_type: string; assigned_to: string }) =>
      api.post(`/vendors/${data.vendor_id}/assessment`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-detail', selectedVendorId] });
      setShowAssessmentModal(false);
    },
  });

  const riskOverrideMutation = useMutation({
    mutationFn: async (data: { vendor_id: string; new_risk_score: number; new_risk_level: string; justification: string }) =>
      api.put(`/vendors/${data.vendor_id}/risk-override`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-detail', selectedVendorId] });
      queryClient.invalidateQueries({ queryKey: ['vendors'] });
      setShowRiskOverrideModal(false);
    },
  });

  const flagMutation = useMutation({
    mutationFn: async (data: { vendor_id: string; reason: string; priority: string }) =>
      api.post(`/vendors/${data.vendor_id}/flag`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-detail', selectedVendorId] });
      setShowFlagModal(false);
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: { vendor_id: string; document_type: string; name: string; file_name: string }) =>
      api.post(`/vendors/${data.vendor_id}/documents`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vendor-detail', selectedVendorId] });
      setShowUploadModal(false);
    },
  });

  const allVendors = vendors ?? [];
  const categories = [...new Set(allVendors.map(v => v.category))];

  const filtered = allVendors.filter(v =>
    (!search || v.name.toLowerCase().includes(search.toLowerCase()) || v.category.includes(search.toLowerCase())) &&
    (!riskFilter || (v.risk_level ?? v.criticality) === riskFilter) &&
    (!categoryFilter || v.category === categoryFilter)
  );

  const riskDist = { critical: 0, high: 0, medium: 0, low: 0 };
  allVendors.forEach(v => {
    const lvl = (v.risk_level ?? v.criticality ?? 'medium').toLowerCase() as keyof typeof riskDist;
    if (lvl in riskDist) riskDist[lvl]++;
  });
  const totalActive = allVendors.filter(v => v.is_active).length;
  const expiringSoon = allVendors.filter(v => {
    if (!v.contract_end) return false;
    const days = Math.ceil((new Date(v.contract_end).getTime() - Date.now()) / 86400000);
    return days >= 0 && days < 90;
  }).length;

  /* ── DETAIL VIEW ──────────────────────────────────────────────────── */

  if (selectedVendorId) {
    const vd = vendorDetail;
    return (
      <div className="space-y-5 page-enter text-[var(--text-heading)]">
        {/* Back header */}
        <button
          onClick={() => setSelectedVendorId(null)}
          className="flex items-center gap-2 text-slate-400 hover:text-[var(--text-heading)] text-sm transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Vendor Portfolio
        </button>

        {detailLoading || !vd ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
          </div>
        ) : (
          <>
            {/* Vendor profile header */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 rounded-2xl bg-[var(--bg-interactive)] border border-[var(--border-color)] flex items-center justify-center text-3xl flex-shrink-0">
                    {CATEGORY_ICONS[vd.category] ?? '\uD83C\uDFE2'}
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-[var(--text-heading)]">{vd.name}</h2>
                    <p className="text-slate-400 text-sm capitalize">{vd.category.replace(/_/g, ' ')}</p>
                    <div className="flex gap-2 mt-2">
                      <span className={`${RISK_CLASSES[(vd.risk_level ?? 'medium').toLowerCase()] ?? ''} text-[10px] font-bold px-2 py-0.5 rounded-full border capitalize`}>
                        {(vd.risk_level ?? 'medium').toLowerCase()} risk
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">
                        {vd.criticality} criticality
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-400">
                        {vd.data_classification}
                      </span>
                    </div>
                  </div>
                </div>
                {/* Action buttons */}
                <div className="flex gap-2 flex-wrap">
                  <button onClick={() => setShowQuestionnaireModal(true)} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold hover:bg-blue-500/20 transition-colors">
                    <ClipboardList className="w-3.5 h-3.5" /> Send Questionnaire
                  </button>
                  <button onClick={() => setShowAssessmentModal(true)} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-semibold hover:bg-violet-500/20 transition-colors">
                    <Calendar className="w-3.5 h-3.5" /> Schedule Assessment
                  </button>
                  <button onClick={() => setShowRiskOverrideModal(true)} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-semibold hover:bg-amber-500/20 transition-colors">
                    <TrendingUp className="w-3.5 h-3.5" /> Update Risk
                  </button>
                  <button onClick={() => setShowFlagModal(true)} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-semibold hover:bg-red-500/20 transition-colors">
                    <Flag className="w-3.5 h-3.5" /> Flag for Review
                  </button>
                </div>
              </div>

              {/* Profile grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5">
                {[
                  { label: 'Contract Start', value: vd.contract_start ? new Date(vd.contract_start).toLocaleDateString() : 'N/A' },
                  { label: 'Contract End', value: vd.contract_end ? new Date(vd.contract_end).toLocaleDateString() : 'N/A' },
                  { label: 'SLA Uptime', value: vd.sla_uptime_target ? `${vd.sla_uptime_target}%` : 'N/A' },
                  { label: 'Assessment Freq', value: vd.assessment_frequency_days ? `${vd.assessment_frequency_days}d` : 'N/A' },
                ].map(item => (
                  <div key={item.label} className="bg-[var(--bg-subtle)] rounded-xl p-3">
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider">{item.label}</p>
                    <p className="text-sm font-semibold text-[var(--text-heading)] mt-0.5">{item.value}</p>
                  </div>
                ))}
              </div>

              {vd.certifications.length > 0 && (
                <div className="flex gap-1.5 flex-wrap mt-4">
                  {vd.certifications.map(c => (
                    <span key={c} className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 font-medium">{c}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Risk score breakdown */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
              <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2 mb-4">
                <BarChart3 className="w-4 h-4 text-amber-400" /> Risk Score Breakdown
              </h3>
              <div className="flex items-center gap-6 mb-5">
                <div className="relative w-20 h-20">
                  <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                    <path d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="var(--border-subtle)" strokeWidth="3" />
                    <path d="M18 2.0845a 15.9155 15.9155 0 0 1 0 31.831 15.9155 15.9155 0 0 1 0 -31.831" fill="none"
                      stroke={vd.risk_breakdown.total_score > 75 ? '#ef4444' : vd.risk_breakdown.total_score > 55 ? '#f97316' : vd.risk_breakdown.total_score > 35 ? '#f59e0b' : '#10b981'}
                      strokeWidth="3" strokeDasharray={`${vd.risk_breakdown.total_score}, 100`} strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-lg font-bold text-[var(--text-heading)]">{vd.risk_breakdown.total_score}</span>
                  </div>
                </div>
                <div className="flex-1 space-y-2">
                  {Object.entries(vd.risk_breakdown.components).map(([key, comp]) => (
                    <div key={key} className="flex items-center justify-between text-xs">
                      <span className="text-slate-400 capitalize">{key.replace(/_/g, ' ')}</span>
                      <div className="flex items-center gap-2">
                        <span className={`font-mono font-bold ${comp.value > 0 ? 'text-red-400' : comp.value < 0 ? 'text-emerald-400' : 'text-slate-500'}`}>
                          {comp.value > 0 ? '+' : ''}{comp.value}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {vd.risk_overrides.length > 0 && (
                <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-3 mt-3">
                  <p className="text-[10px] text-amber-400 font-bold uppercase mb-1">Manual Override Active</p>
                  <p className="text-xs text-slate-400">{vd.risk_overrides[0].justification}</p>
                  <p className="text-[10px] text-slate-500 mt-1">By {vd.risk_overrides[0].override_by} on {new Date(vd.risk_overrides[0].created_at).toLocaleDateString()}</p>
                </div>
              )}
            </div>

            {/* Compliance status */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
              <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2 mb-4">
                <Shield className="w-4 h-4 text-blue-400" /> Compliance Status
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {vd.compliance_status.map(cs => (
                  <div key={cs.framework} className="bg-[var(--bg-subtle)] rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-[var(--text-heading)]">{cs.framework_label}</span>
                      <span className={`${COMPLIANCE_CLASSES[cs.status] ?? ''} text-[10px] font-bold px-2 py-0.5 rounded-full border capitalize`}>
                        {cs.status.replace('_', ' ')}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500 mb-2">
                      <span>{cs.controls_passing}/{cs.controls_assessed} controls passing</span>
                      <span>Verified {new Date(cs.last_verified).toLocaleDateString()}</span>
                    </div>
                    <div className="h-1 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${cs.controls_assessed > 0 ? (cs.controls_passing / cs.controls_assessed * 100) : 0}%` }} />
                    </div>
                    {cs.notes && <p className="text-[10px] text-amber-400 mt-2">{cs.notes}</p>}
                  </div>
                ))}
              </div>
            </div>

            {/* Documents */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
                  <FileText className="w-4 h-4 text-violet-400" /> Documents
                </h3>
                <button onClick={() => setShowUploadModal(true)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-xs text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors">
                  <Upload className="w-3 h-3" /> Upload
                </button>
              </div>
              <div className="space-y-2">
                {vd.documents.map(doc => (
                  <div key={doc.id} className="flex items-center justify-between bg-[var(--bg-subtle)] rounded-xl p-3">
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-slate-500" />
                      <div>
                        <p className="text-xs font-medium text-[var(--text-heading)]">{doc.name}</p>
                        <p className="text-[10px] text-slate-500">
                          {DOC_TYPE_LABELS[doc.document_type] ?? doc.document_type} &middot; {(doc.size_bytes / 1000).toFixed(0)} KB &middot; Uploaded {new Date(doc.uploaded_at).toLocaleDateString()} by {doc.uploaded_by}
                        </p>
                      </div>
                    </div>
                    {doc.expiry_date && (
                      <span className={`text-[10px] ${new Date(doc.expiry_date) < new Date() ? 'text-red-400' : 'text-slate-500'}`}>
                        Expires {new Date(doc.expiry_date).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Assessment history */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">
              <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2 mb-4">
                <Clock className="w-4 h-4 text-emerald-400" /> Assessment History
              </h3>
              <div className="space-y-3">
                {vd.assessment_history.map(a => (
                  <div key={a.id} className="bg-[var(--bg-subtle)] rounded-xl p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <p className="text-xs font-bold text-[var(--text-heading)] capitalize">{a.assessment_type.replace(/_/g, ' ')}</p>
                        <p className="text-[10px] text-slate-500">{new Date(a.assessment_date).toLocaleDateString()} by {a.assessor}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        {a.risk_score != null && (
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${RISK_CLASSES[(a.risk_level ?? 'medium').toLowerCase()] ?? ''}`}>
                            {a.risk_score}/100
                          </span>
                        )}
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${a.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'}`}>
                          {a.status}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400">{a.summary}</p>
                    {a.findings_count > 0 && (
                      <p className="text-[10px] text-slate-500 mt-1">
                        {a.findings_count} findings ({a.critical_findings} critical)
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Review flags */}
            {vd.review_flags.length > 0 && (
              <div className="bg-[var(--bg-surface)] border border-red-500/20 rounded-2xl p-6">
                <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2 mb-4">
                  <Flag className="w-4 h-4 text-red-400" /> Review Flags
                </h3>
                <div className="space-y-2">
                  {vd.review_flags.map(f => (
                    <div key={f.id} className="flex items-center justify-between bg-red-500/5 rounded-xl p-3">
                      <div>
                        <p className="text-xs text-[var(--text-heading)]">{f.reason}</p>
                        <p className="text-[10px] text-slate-500">By {f.flagged_by} on {new Date(f.created_at).toLocaleDateString()}</p>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${RISK_CLASSES[f.priority] ?? ''} border`}>
                        {f.priority}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── Action Modals ──────────────────────────────────────── */}
            {showQuestionnaireModal && <ActionModal title="Send Security Questionnaire" onClose={() => setShowQuestionnaireModal(false)}
              onSubmit={(data) => questionnaireMutation.mutate({ vendor_id: selectedVendorId!, questionnaire_type: data.type, notes: data.notes })}
              isPending={questionnaireMutation.isPending}
              fields={[
                { key: 'type', label: 'Questionnaire Type', type: 'select', options: ['DDQ', 'SIG', 'CAIQ', 'Custom'], default: 'DDQ' },
                { key: 'notes', label: 'Notes', type: 'textarea', default: '' },
              ]}
            />}
            {showAssessmentModal && <ActionModal title="Schedule Vendor Assessment" onClose={() => setShowAssessmentModal(false)}
              onSubmit={(data) => assessmentMutation.mutate({ vendor_id: selectedVendorId!, assessment_type: data.type, assigned_to: data.assigned_to })}
              isPending={assessmentMutation.isPending}
              fields={[
                { key: 'type', label: 'Assessment Type', type: 'select', options: ['annual_review', 'onboarding', 'incident_triggered'], default: 'annual_review' },
                { key: 'assigned_to', label: 'Assigned To', type: 'text', default: 'Security Team' },
              ]}
            />}
            {showRiskOverrideModal && <ActionModal title="Override Risk Score" onClose={() => setShowRiskOverrideModal(false)}
              onSubmit={(data) => riskOverrideMutation.mutate({
                vendor_id: selectedVendorId!,
                new_risk_score: parseFloat(data.score),
                new_risk_level: data.level,
                justification: data.justification,
              })}
              isPending={riskOverrideMutation.isPending}
              fields={[
                { key: 'score', label: 'New Risk Score (0-100)', type: 'text', default: String(vd?.risk_breakdown?.total_score ?? 50) },
                { key: 'level', label: 'Risk Level', type: 'select', options: ['critical', 'high', 'medium', 'low'], default: 'medium' },
                { key: 'justification', label: 'Justification', type: 'textarea', default: '' },
              ]}
            />}
            {showFlagModal && <ActionModal title="Flag for Management Review" onClose={() => setShowFlagModal(false)}
              onSubmit={(data) => flagMutation.mutate({ vendor_id: selectedVendorId!, reason: data.reason, priority: data.priority })}
              isPending={flagMutation.isPending}
              fields={[
                { key: 'reason', label: 'Reason', type: 'textarea', default: '' },
                { key: 'priority', label: 'Priority', type: 'select', options: ['critical', 'high', 'medium', 'low'], default: 'high' },
              ]}
            />}
            {showUploadModal && <ActionModal title="Upload Document" onClose={() => setShowUploadModal(false)}
              onSubmit={(data) => uploadMutation.mutate({
                vendor_id: selectedVendorId!,
                document_type: data.type,
                name: data.name,
                file_name: data.file_name,
              })}
              isPending={uploadMutation.isPending}
              fields={[
                { key: 'type', label: 'Document Type', type: 'select', options: ['soc2_report', 'baa', 'security_policy', 'pen_test', 'iso_cert', 'insurance'], default: 'soc2_report' },
                { key: 'name', label: 'Document Name', type: 'text', default: '' },
                { key: 'file_name', label: 'File Name', type: 'text', default: '' },
              ]}
            />}
          </>
        )}
      </div>
    );
  }

  /* ── PORTFOLIO VIEW ─────────────────────────────────────────────── */

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <Users className="w-5 h-5 text-violet-400" /> Vendor Risk Management
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Third-party security posture across your supply chain</p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20"
        >
          <Plus className="w-4 h-4" /> Add Vendor
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Total Vendors', value: allVendors.length, icon: Users, cls: 'text-blue-400', border: 'border-blue-500/20', filterVal: '' },
          { label: 'Critical', value: riskDist.critical, icon: AlertTriangle, cls: 'text-red-400', border: 'border-red-500/20', filterVal: 'critical' },
          { label: 'High Risk', value: riskDist.high, icon: Shield, cls: 'text-orange-400', border: 'border-orange-500/20', filterVal: 'high' },
          { label: 'Active', value: totalActive, icon: CheckCircle, cls: 'text-emerald-400', border: 'border-emerald-500/20', filterVal: '' },
          { label: 'Expiring <90d', value: expiringSoon, icon: Calendar, cls: 'text-amber-400', border: 'border-amber-500/20', filterVal: '' },
        ].map(s => {
          const Icon = s.icon;
          const isActive = riskFilter === s.filterVal && s.filterVal !== '';
          return (
            <button key={s.label} onClick={() => setRiskFilter(riskFilter === s.filterVal ? '' : s.filterVal)} className={`bg-[var(--bg-surface)] border ${s.border} rounded-2xl p-5 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400">{s.label}</p>
                <Icon className={`w-4 h-4 ${s.cls}`} />
              </div>
              <p className={`text-3xl font-extrabold ${s.cls}`}>{s.value}</p>
            </button>
          );
        })}
      </div>

      {/* Risk distribution bar */}
      {allVendors.length > 0 && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
          <p className="text-xs text-slate-400 mb-3 font-semibold">Risk Distribution</p>
          <div className="flex h-3 rounded-full overflow-hidden bg-[var(--bg-interactive)]">
            {(['critical', 'high', 'medium', 'low'] as const).map(level => {
              const pct = allVendors.length > 0 ? (riskDist[level] / allVendors.length * 100) : 0;
              return pct > 0 ? <button key={level} onClick={() => setRiskFilter(riskFilter === level ? '' : level)} className={`${RISK_BAR_COLORS[level]} transition-all cursor-pointer hover:brightness-125`} style={{ width: `${pct}%` }} /> : null;
            })}
          </div>
          <div className="flex gap-4 mt-2">
            {(['critical', 'high', 'medium', 'low'] as const).map(level => (
              <button key={level} onClick={() => setRiskFilter(riskFilter === level ? '' : level)} className={`flex items-center gap-1.5 text-[10px] cursor-pointer transition-colors ${riskFilter === level ? 'text-[var(--text-heading)]' : 'text-slate-500 hover:text-slate-300'}`}>
                <span className={`w-2 h-2 rounded-full ${RISK_BAR_COLORS[level]}`} />
                <span className="capitalize">{level}</span> ({riskDist[level]})
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search vendors..."
            className="w-full bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl pl-9 pr-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
          className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20">
          <option value="" className="bg-[var(--bg-surface)]">All Risk Levels</option>
          {['critical', 'high', 'medium', 'low'].map(r => (
            <option key={r} value={r} className="bg-[var(--bg-surface)] capitalize">{r.charAt(0).toUpperCase() + r.slice(1)}</option>
          ))}
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
          className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20">
          <option value="" className="bg-[var(--bg-surface)]">All Categories</option>
          {categories.map(c => (
            <option key={c} value={c} className="bg-[var(--bg-surface)] capitalize">{c.replace(/_/g, ' ')}</option>
          ))}
        </select>
      </div>

      {/* Vendor grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {isLoading
          ? Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 animate-pulse">
                <div className="h-4 bg-[var(--bg-interactive)] rounded w-2/3 mb-3" />
                <div className="h-3 bg-[var(--bg-interactive)] rounded w-1/2 mb-4" />
                <div className="h-2 bg-[var(--bg-interactive)] rounded w-full" />
              </div>
            ))
          : filtered.map(vendor => {
              const riskLevel = (vendor.risk_level ?? vendor.criticality ?? 'unknown').toLowerCase();
              const riskCls = RISK_CLASSES[riskLevel] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/20';
              const daysUntilExpiry = vendor.contract_end
                ? Math.ceil((new Date(vendor.contract_end).getTime() - Date.now()) / 86400000)
                : null;

              return (
                <div
                  key={vendor.id}
                  onClick={() => setSelectedVendorId(vendor.id)}
                  className="group bg-[var(--bg-surface)] border border-[var(--border-color)] hover:border-[var(--border-color-hover)] rounded-2xl p-5 transition-all hover:bg-[var(--bg-subtle)] cursor-pointer"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] flex items-center justify-center text-xl flex-shrink-0">
                        {CATEGORY_ICONS[vendor.category] ?? '\uD83C\uDFE2'}
                      </div>
                      <div>
                        <h3 className="font-bold text-[var(--text-heading)] text-sm leading-tight">{vendor.name}</h3>
                        <p className="text-[11px] text-slate-500 capitalize mt-0.5">{vendor.category.replace(/_/g, ' ')}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`${riskCls} text-[10px] font-bold px-2 py-0.5 rounded-full border capitalize flex-shrink-0`}>
                        {riskLevel}
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 transition-colors" />
                    </div>
                  </div>

                  {vendor.certifications?.length > 0 && (
                    <div className="flex gap-1.5 flex-wrap mb-3">
                      {vendor.certifications.slice(0, 3).map(c => (
                        <button key={c} onClick={(e) => { e.stopPropagation(); setSearch(c); }} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 cursor-pointer hover:brightness-125 transition-all">{c}</button>
                      ))}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5" />
                      {vendor.last_assessment_date
                        ? `Assessed ${new Date(vendor.last_assessment_date).toLocaleDateString()}`
                        : 'Not yet assessed'}
                    </span>
                    {daysUntilExpiry != null && (
                      <span className={daysUntilExpiry < 90 ? 'text-amber-400' : 'text-slate-500'}>
                        Contract: {daysUntilExpiry < 0 ? 'Expired' : `${daysUntilExpiry}d`}
                      </span>
                    )}
                  </div>

                  {vendor.risk_score != null && (
                    <div className="mt-3">
                      <div className="flex items-center justify-between text-[10px] mb-1">
                        <span className="text-slate-500">Risk Score</span>
                        <span className="font-bold text-[var(--text-heading)]">{vendor.risk_score}/100</span>
                      </div>
                      <div className="h-1 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${vendor.risk_score > 70 ? 'bg-red-500' : vendor.risk_score > 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${vendor.risk_score}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              );
            })
        }
      </div>

      {/* Create Vendor Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setShowCreateForm(false)} />
          <div className="relative bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6 w-full max-w-lg max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-bold text-[var(--text-heading)]">Add Vendor</h3>
              <button onClick={() => setShowCreateForm(false)} className="text-slate-400 hover:text-[var(--text-heading)]"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Vendor Name *</label>
                <input type="text" value={createForm.name} onChange={e => setCreateForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" placeholder="e.g. Amazon Web Services" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Category</label>
                  <select value={createForm.category} onChange={e => setCreateForm(f => ({ ...f, category: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                    {CATEGORY_OPTIONS.map(c => <option key={c} value={c} className="bg-[var(--bg-surface)] capitalize">{c.replace(/_/g, ' ')}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Criticality</label>
                  <select value={createForm.criticality} onChange={e => setCreateForm(f => ({ ...f, criticality: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                    {['Critical', 'High', 'Medium', 'Low'].map(c => <option key={c} value={c} className="bg-[var(--bg-surface)]">{c}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Data Classification</label>
                <select value={createForm.data_classification} onChange={e => setCreateForm(f => ({ ...f, data_classification: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                  {['Restricted', 'Confidential', 'Internal', 'Public'].map(c => <option key={c} value={c} className="bg-[var(--bg-surface)]">{c}</option>)}
                </select>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Contract Start</label>
                  <input type="date" value={createForm.contract_start} onChange={e => setCreateForm(f => ({ ...f, contract_start: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Contract End</label>
                  <input type="date" value={createForm.contract_end} onChange={e => setCreateForm(f => ({ ...f, contract_end: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Primary Contact</label>
                <input type="text" value={createForm.primary_contact} onChange={e => setCreateForm(f => ({ ...f, primary_contact: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" placeholder="security@vendor.com" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Notes</label>
                <textarea value={createForm.notes} onChange={e => setCreateForm(f => ({ ...f, notes: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 h-20 resize-none" placeholder="Additional notes..." />
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button onClick={() => setShowCreateForm(false)} className="flex-1 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors">Cancel</button>
              <button
                onClick={() => createMutation.mutate(createForm)}
                disabled={!createForm.name || createMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-[var(--text-heading)] transition-all disabled:opacity-40 shadow-lg shadow-blue-500/20"
              >
                {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                Create Vendor
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Reusable action modal ─────────────────────────────────────────── */

interface ModalField {
  key: string;
  label: string;
  type: 'text' | 'textarea' | 'select';
  options?: string[];
  default: string;
}

function ActionModal({
  title, onClose, onSubmit, isPending, fields
}: {
  title: string;
  onClose: () => void;
  onSubmit: (data: Record<string, string>) => void;
  isPending: boolean;
  fields: ModalField[];
}) {
  const [formData, setFormData] = useState<Record<string, string>>(
    Object.fromEntries(fields.map(f => [f.key, f.default]))
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-sm font-bold text-[var(--text-heading)]">{title}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-[var(--text-heading)]"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-4">
          {fields.map(f => (
            <div key={f.key}>
              <label className="block text-xs font-medium text-slate-300 mb-1">{f.label}</label>
              {f.type === 'select' ? (
                <select value={formData[f.key]} onChange={e => setFormData(d => ({ ...d, [f.key]: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                  {f.options?.map(o => <option key={o} value={o} className="bg-[var(--bg-surface)] capitalize">{o.replace(/_/g, ' ')}</option>)}
                </select>
              ) : f.type === 'textarea' ? (
                <textarea value={formData[f.key]} onChange={e => setFormData(d => ({ ...d, [f.key]: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 h-20 resize-none" />
              ) : (
                <input type="text" value={formData[f.key]} onChange={e => setFormData(d => ({ ...d, [f.key]: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
              )}
            </div>
          ))}
        </div>
        <div className="flex gap-3 mt-5">
          <button onClick={onClose} className="flex-1 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors">Cancel</button>
          <button onClick={() => onSubmit(formData)} disabled={isPending}
            className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-[var(--text-heading)] transition-all disabled:opacity-40 shadow-lg shadow-blue-500/20">
            {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
            Submit
          </button>
        </div>
      </div>
    </div>
  );
}
