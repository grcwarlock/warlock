import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  ChevronDown, ChevronRight, CheckCircle, AlertTriangle,
  XCircle, Filter, X, BookOpen, Wrench, ExternalLink, ClipboardList, Loader2, Grid3X3,
  Shield, Clock, Layers, TrendingUp, Zap, Check, Info
} from 'lucide-react';
import api from '../lib/api';

interface AssessmentResult {
  id: string;
  control_id: string;
  check_id: string;
  assertion: string;
  status: string;
  severity: string;
  provider: string;
  region: string;
  findings: string[];
  remediation: string | null;
  assessed_at: string;
}

interface RemediationGuide {
  title: string;
  steps: string[];
  references: string[];
  raw: string | null;
}

const FRAMEWORKS = [
  { id: 'nist_800_53', name: 'NIST 800-53', desc: 'Security and Privacy Controls for Federal Information Systems' },
  { id: 'soc2',        name: 'SOC 2',        desc: 'Service Organization Control 2 — Trust Services Criteria' },
  { id: 'iso_27001',   name: 'ISO 27001',    desc: 'Information Security Management Systems Requirements' },
  { id: 'hipaa',       name: 'HIPAA',        desc: 'Health Insurance Portability and Accountability Act' },
  { id: 'cmmc_l2',     name: 'CMMC L2',      desc: 'Cybersecurity Maturity Model Certification Level 2' },
];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, pass: 4 };

function StatusBadge({ status, severity }: { status: string; severity: string }) {
  if (status === 'pass') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
        <CheckCircle className="w-3 h-3" /> Pass
      </span>
    );
  }
  if (severity === 'critical' || severity === 'high') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/20 capitalize">
        <XCircle className="w-3 h-3" /> {severity}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/20 capitalize">
      <AlertTriangle className="w-3 h-3" /> {severity || 'medium'}
    </span>
  );
}

function ControlDetailPanel({ control, remediation, remLoading, onClose, onCreatePOAM }: {
  control: AssessmentResult;
  remediation?: RemediationGuide;
  remLoading: boolean;
  onClose: () => void;
  onCreatePOAM: (control: AssessmentResult) => void;
}) {
  const isCritical = control.severity === 'critical' || control.severity === 'high';

  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden sticky top-4 max-h-[calc(100vh-8rem)] flex flex-col shadow-2xl shadow-black/40">
      <div className={`px-4 py-3 border-b flex items-start justify-between gap-2 ${
        isCritical ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'
      }`}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-[10px] font-bold bg-[var(--bg-interactive-hover)] px-1.5 py-0.5 rounded border border-[var(--border-color)] text-slate-300">
              {control.control_id}
            </span>
            <StatusBadge status={control.status} severity={control.severity} />
          </div>
          <p className="text-sm font-semibold text-[var(--text-heading)] leading-tight">{control.assertion || control.check_id}</p>
          <p className="text-xs text-slate-500 mt-1">{control.provider.toUpperCase()} · {control.region}</p>
        </div>
        <button onClick={onClose} className="p-1.5 hover:bg-[var(--bg-interactive-hover)] rounded-lg transition-colors flex-shrink-0">
          <X className="w-4 h-4 text-slate-500 hover:text-[var(--text-heading)]" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
        {control.findings?.length > 0 && (
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ClipboardList className="w-3.5 h-3.5 text-red-400" /> What's Wrong
            </h4>
            <div className={`rounded-xl border p-3 space-y-2 ${isCritical ? 'bg-red-500/10 border-red-500/20' : 'bg-amber-500/10 border-amber-500/20'}`}>
              {control.findings.map((finding, i) => (
                <div key={i} className="flex gap-2">
                  <span className={`text-xs mt-0.5 flex-shrink-0 ${isCritical ? 'text-red-400' : 'text-amber-400'}`}>•</span>
                  <p className="text-xs text-slate-300 leading-relaxed">{finding}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5 text-blue-400" /> Recommended Remediation
          </h4>
          {remLoading ? (
            <div className="flex items-center gap-2 py-4 text-slate-500">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span className="text-xs">Loading guidance…</span>
            </div>
          ) : remediation ? (
            <div className="space-y-2">
              {remediation.steps.map((step, i) => (
                <div key={i} className="flex gap-3 bg-blue-500/10 border border-blue-500/20 rounded-xl px-3 py-2.5">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-[var(--text-heading)] text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">{i + 1}</span>
                  <p className="text-xs text-slate-300 leading-relaxed">{step}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
              <p className="text-xs text-slate-400 leading-relaxed">{control.remediation || 'Review the control requirement and develop a remediation plan based on your system architecture.'}</p>
            </div>
          )}
        </div>

        {remediation?.references && remediation.references.length > 0 && (
          <div>
            <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5 text-slate-500" /> References
            </h4>
            <div className="space-y-1">
              {remediation.references.map((ref, i) => (
                <div key={i} className="flex items-center gap-1.5 text-xs text-blue-400">
                  <ExternalLink className="w-3 h-3 flex-shrink-0" /><span>{ref}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="pt-2 border-t border-[var(--border-subtle)]">
          <p className="text-[10px] text-slate-600">Assessed: {new Date(control.assessed_at).toLocaleString()}</p>
        </div>
      </div>

      <div className="p-3 border-t border-[var(--border-color)] flex gap-2">
        <button
          onClick={() => onCreatePOAM(control)}
          className="flex-1 py-2 text-xs font-bold bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-[var(--text-heading)] rounded-xl transition-all"
        >
          Create POAM Item
        </button>
        <button className="flex-1 py-2 text-xs font-semibold bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-slate-300 rounded-xl transition-colors">
          Assign Owner
        </button>
      </div>
    </div>
  );
}

// ── UCF Types ─────────────────────────────────────────────────────

interface UCFMapping {
  control_id: string;
  status: string;
  guidance: string;
}

interface UCFDomain {
  domain: string;
  description: string;
  mappings: Record<string, UCFMapping>;
}

interface UCFStats {
  total_domains: number;
  passing_count: number;
  failing_count: number;
  unknown_count: number;
  cross_framework_efficiency: number;
  framework_stats: Record<string, { total: number; passed: number; pass_rate: number }>;
}

interface UCFData {
  frameworks: string[];
  framework_labels: Record<string, string>;
  domains: UCFDomain[];
  stats: UCFStats;
}

type UCFFilter = 'all' | 'passing' | 'failing' | 'unknown';

function UCFStatusCell({ mapping }: { mapping: UCFMapping }) {
  if (!mapping || !mapping.control_id || mapping.control_id === 'N/A') {
    return (
      <div className="px-2 py-1.5 rounded-lg bg-slate-500/10 border border-slate-500/10 text-center">
        <span className="text-[10px] text-slate-600">N/A</span>
      </div>
    );
  }
  const s = mapping.status;
  if (s === 'pass') {
    return (
      <div className="px-2 py-1.5 rounded-lg border text-center bg-emerald-500/15 border-emerald-500/20">
        <div className="flex items-center justify-center gap-1">
          <Check className="w-3 h-3 text-emerald-400" />
          <span className="font-mono text-[10px] font-bold text-emerald-400">{mapping.control_id}</span>
        </div>
      </div>
    );
  }
  if (s === 'fail') {
    return (
      <div className="px-2 py-1.5 rounded-lg border text-center bg-red-500/15 border-red-500/20">
        <div className="flex items-center justify-center gap-1">
          <XCircle className="w-3 h-3 text-red-400" />
          <span className="font-mono text-[10px] font-bold text-red-400">{mapping.control_id}</span>
        </div>
      </div>
    );
  }
  return (
    <div className="px-2 py-1.5 rounded-lg border text-center bg-slate-500/10 border-[var(--border-color)]">
      <div className="flex items-center justify-center gap-1">
        <Clock className="w-3 h-3 text-slate-500" />
        <span className="font-mono text-[10px] font-bold text-slate-400">{mapping.control_id}</span>
      </div>
    </div>
  );
}

function getDomainStatus(domain: UCFDomain): 'passing' | 'failing' | 'unknown' {
  const statuses = Object.values(domain.mappings).map(m => m.status);
  if (statuses.some(s => s === 'fail')) return 'failing';
  if (statuses.some(s => s === 'pass')) return 'passing';
  return 'unknown';
}

function UnifiedControlsTab() {
  const [filter, setFilter] = useState<UCFFilter>('all');
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);

  const { data: ucfData, isLoading } = useQuery<UCFData>({
    queryKey: ['frameworks', 'ucf'],
    queryFn: async () => (await api.get('/frameworks/ucf')).data,
  });

  if (isLoading) {
    return (
      <div className="py-16 text-center text-slate-500">
        <Loader2 className="w-8 h-8 animate-spin mx-auto mb-3" />
        <p className="text-sm">Loading unified controls...</p>
      </div>
    );
  }

  if (!ucfData) return null;

  const fwKeys = ucfData.frameworks;
  const labels = ucfData.framework_labels;
  const stats = ucfData.stats;

  const filteredDomains = ucfData.domains.filter(d => {
    if (filter === 'all') return true;
    return getDomainStatus(d) === filter;
  });

  const toggleExpand = (domain: string) => {
    setExpandedDomain(prev => prev === domain ? null : domain);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h2 className="font-bold text-[var(--text-heading)] text-base flex items-center gap-2">
            <Grid3X3 className="w-4 h-4 text-violet-400" /> Unified Controls Framework
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">Cross-framework control mapping — fix one domain, satisfy requirements across all 5 frameworks</p>
        </div>
        <div className="flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-emerald-500/30 border border-emerald-500/30" /> Passing</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-red-500/30 border border-red-500/30" /> Failing</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-slate-500/20 border border-[var(--border-color)]" /> Pending</span>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="flex items-center justify-between mb-2">
            <Layers className="w-5 h-5 text-violet-400" />
            <span className="text-[10px] text-slate-600 font-semibold uppercase">Domains</span>
          </div>
          <div className="text-2xl font-extrabold text-[var(--text-heading)]">{stats.total_domains}</div>
          <p className="text-[10px] text-slate-500 mt-0.5">Control domains mapped</p>
        </div>
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="flex items-center justify-between mb-2">
            <CheckCircle className="w-5 h-5 text-emerald-400" />
            <span className="text-[10px] text-slate-600 font-semibold uppercase">Passing</span>
          </div>
          <div className="text-2xl font-extrabold text-emerald-400">{stats.passing_count}</div>
          <p className="text-[10px] text-slate-500 mt-0.5">Domains with coverage</p>
        </div>
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="flex items-center justify-between mb-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <span className="text-[10px] text-slate-600 font-semibold uppercase">Attention</span>
          </div>
          <div className="text-2xl font-extrabold text-red-400">{stats.failing_count}</div>
          <p className="text-[10px] text-slate-500 mt-0.5">Domains need remediation</p>
        </div>
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="flex items-center justify-between mb-2">
            <TrendingUp className="w-5 h-5 text-blue-400" />
            <span className="text-[10px] text-slate-600 font-semibold uppercase">Efficiency</span>
          </div>
          <div className="text-2xl font-extrabold text-blue-400">{stats.cross_framework_efficiency}%</div>
          <p className="text-[10px] text-slate-500 mt-0.5">Covered in 3+ frameworks</p>
        </div>
      </div>

      <div className="bg-gradient-to-r from-violet-500/10 to-blue-500/10 border border-violet-500/20 rounded-2xl px-4 py-3 flex items-start gap-3">
        <Zap className="w-5 h-5 text-violet-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-[var(--text-heading)]">Fix One, Cover Many</p>
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
            Each domain maps a single security objective across NIST 800-53, SOC 2, ISO 27001, HIPAA, and CMMC L2.
            Remediating one domain simultaneously satisfies requirements in all 5 frameworks — eliminating duplicated compliance work.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 text-xs">
        <Filter className="w-3.5 h-3.5 text-slate-500" />
        {([['all', 'All'], ['passing', 'Passing'], ['failing', 'Failing'], ['unknown', 'Pending']] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setFilter(key)}
            className={`px-3 py-1.5 rounded-full font-semibold transition-colors ${
              filter === key
                ? key === 'passing' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20'
                  : key === 'failing' ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                  : key === 'unknown' ? 'bg-slate-500/15 text-slate-300 border border-slate-500/20'
                  : 'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                : 'text-slate-500 hover:bg-[var(--bg-interactive)] hover:text-slate-300'
            }`}
          >
            {label}
          </button>
        ))}
        {filter !== 'all' && (
          <button onClick={() => setFilter('all')} className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 ml-1">
            <X className="w-3 h-3" /> Clear
          </button>
        )}
      </div>

      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[800px]">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-subtle)]">
                <th className="text-left px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider w-72">Control Domain</th>
                {fwKeys.map(fw => (
                  <th key={fw} className="text-center px-3 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-wider">
                    <div>{labels[fw]}</div>
                    {stats.framework_stats[fw] && (
                      <div className={`text-[9px] font-normal mt-0.5 ${
                        stats.framework_stats[fw].pass_rate >= 70 ? 'text-emerald-500' :
                        stats.framework_stats[fw].pass_rate >= 40 ? 'text-amber-500' : 'text-slate-600'
                      }`}>
                        {stats.framework_stats[fw].pass_rate}% pass
                      </div>
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {filteredDomains.map(domain => {
                const domStatus = getDomainStatus(domain);
                const isExpanded = expandedDomain === domain.domain;
                const passCount = Object.values(domain.mappings).filter(m => m.status === 'pass').length;
                const totalMapped = Object.values(domain.mappings).filter(m => m.control_id && m.control_id !== 'N/A').length;

                return (
                  <tr key={domain.domain} className="group">
                    <td colSpan={fwKeys.length + 1} className="p-0">
                      <div
                        className="flex items-center cursor-pointer hover:bg-[var(--bg-subtle)] transition-colors"
                        onClick={() => toggleExpand(domain.domain)}
                      >
                        <div className="px-4 py-3 w-72 flex-shrink-0">
                          <div className="flex items-center gap-2">
                            {isExpanded
                              ? <ChevronDown className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                              : <ChevronRight className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />}
                            <div className="min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-semibold text-sm text-[var(--text-heading)]">{domain.domain}</span>
                                {domStatus === 'passing' && <span className="w-2 h-2 rounded-full bg-emerald-500" />}
                                {domStatus === 'failing' && <span className="w-2 h-2 rounded-full bg-red-500" />}
                                {domStatus === 'unknown' && <span className="w-2 h-2 rounded-full bg-slate-500" />}
                              </div>
                              <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed line-clamp-1">{passCount}/{totalMapped} frameworks covered</p>
                            </div>
                          </div>
                        </div>
                        <div className="flex flex-1">
                          {fwKeys.map(fw => (
                            <div key={fw} className="flex-1 px-3 py-3">
                              <UCFStatusCell mapping={domain.mappings[fw]} />
                            </div>
                          ))}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="border-t border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-6 py-4">
                          <div className="flex items-start gap-3 mb-3">
                            <Info className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
                            <p className="text-xs text-slate-400 leading-relaxed">{domain.description}</p>
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                            {fwKeys.map(fw => {
                              const m = domain.mappings[fw];
                              if (!m || !m.control_id || m.control_id === 'N/A') return null;
                              return (
                                <div key={fw} className={`rounded-xl border px-3 py-2 ${
                                  m.status === 'pass' ? 'bg-emerald-500/5 border-emerald-500/15' :
                                  m.status === 'fail' ? 'bg-red-500/5 border-red-500/15' :
                                  'bg-[var(--bg-subtle)] border-[var(--border-subtle)]'
                                }`}>
                                  <div className="flex items-center justify-between">
                                    <span className="text-[10px] font-bold text-slate-500 uppercase">{labels[fw]}</span>
                                    {m.status === 'pass' && <Check className="w-3 h-3 text-emerald-400" />}
                                    {m.status === 'fail' && <XCircle className="w-3 h-3 text-red-400" />}
                                    {m.status !== 'pass' && m.status !== 'fail' && <Clock className="w-3 h-3 text-slate-500" />}
                                  </div>
                                  <div className="font-mono text-xs text-[var(--text-heading)] mt-1">{m.control_id}</div>
                                  <div className={`text-[10px] mt-0.5 font-semibold ${
                                    m.status === 'pass' ? 'text-emerald-400' :
                                    m.status === 'fail' ? 'text-red-400' : 'text-slate-500'
                                  }`}>
                                    {m.status === 'pass' ? 'Compliant' : m.status === 'fail' ? 'Non-compliant' : 'Not assessed'}
                                  </div>
                                  {m.guidance && (
                                    <p className="text-[10px] text-slate-500 mt-1 leading-relaxed">{m.guidance}</p>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
              {filteredDomains.length === 0 && (
                <tr>
                  <td colSpan={fwKeys.length + 1} className="py-12 text-center">
                    <Shield className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                    <p className="text-sm text-slate-500">No domains match the selected filter</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────

export default function FrameworksPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const urlFw = searchParams.get('fw');
  const urlFilter = searchParams.get('filter') as 'all' | 'medium' | 'critical' | null;

  const [activeTab, setActiveTab] = useState(urlFw || 'nist_800_53');
  const [expandedFamilies, setExpandedFamilies] = useState<Record<string, boolean>>({});
  const [statusFilter, setStatusFilter] = useState<'all' | 'pass' | 'medium' | 'critical'>(urlFilter || 'all');
  const [selectedControl, setSelectedControl] = useState<AssessmentResult | null>(null);
  const [poamToast, setPOAMToast] = useState<string | null>(null);

  useEffect(() => {
    if (urlFw && [...FRAMEWORKS.map(f => f.id), 'ucf'].includes(urlFw)) setActiveTab(urlFw);
    if (urlFilter) setStatusFilter(urlFilter as any);
  }, [urlFw, urlFilter]);

  // Clear toast after 3s
  useEffect(() => {
    if (poamToast) {
      const t = setTimeout(() => setPOAMToast(null), 3000);
      return () => clearTimeout(t);
    }
  }, [poamToast]);

  const isUCFTab = activeTab === 'ucf';

  const { data: runs, isLoading: runsLoading } = useQuery<any[]>({
    queryKey: ['assessments', 'runs', activeTab],
    queryFn: async () => (await api.get(`/assessments/runs?framework=${activeTab}&limit=1`)).data,
    enabled: !isUCFTab,
  });

  const latestRunId = runs?.[0]?.id;
  const latestRun = runs?.[0];

  const { data: results, isLoading: resultsLoading } = useQuery<AssessmentResult[]>({
    queryKey: ['assessments', 'results', latestRunId],
    queryFn: async () => {
      if (!latestRunId) return [];
      return (await api.get(`/assessments/runs/${latestRunId}/results`)).data;
    },
    enabled: !!latestRunId && !isUCFTab,
  });

  const { data: remediation, isLoading: remLoading } = useQuery<RemediationGuide>({
    queryKey: ['remediation', selectedControl?.control_id],
    queryFn: async () => (await api.get(`/assessments/remediation/${selectedControl!.control_id}`)).data,
    enabled: !!selectedControl && selectedControl.status !== 'pass',
  });

  const switchTab = (id: string) => {
    setActiveTab(id);
    setSelectedControl(null);
    setSearchParams({ fw: id, ...(statusFilter !== 'all' ? { filter: statusFilter } : {}) });
  };

  const changeFilter = (f: string) => {
    setStatusFilter(f as any);
    setSearchParams({ fw: activeTab, ...(f !== 'all' ? { filter: f } : {}) });
  };

  const handleCreatePOAM = async (control: AssessmentResult) => {
    try {
      await api.post('/issues', {
        title: `POAM: Remediate ${control.control_id} — ${control.assertion || control.check_id}`,
        description: `Auto-generated POAM item from assessment finding.\n\nControl: ${control.control_id}\nSeverity: ${control.severity}\nFindings: ${(control.findings || []).join('; ')}`,
        priority: control.severity === 'critical' || control.severity === 'high' ? 'critical' : 'medium',
        framework: activeTab,
        control_id: control.control_id,
        status: 'open',
      });
      setPOAMToast(`POAM item created for ${control.control_id}`);
    } catch {
      // Fallback: navigate to POAM page
      navigate('/poam');
    }
  };

  const familyGroups: Record<string, AssessmentResult[]> = {};
  (results ?? []).forEach(r => {
    const family = r.control_id.split('-')[0].split('.')[0] || 'GEN';
    if (!familyGroups[family]) familyGroups[family] = [];
    familyGroups[family].push(r);
  });
  Object.values(familyGroups).forEach(controls =>
    controls.sort((a, b) => {
      const aO = a.status === 'pass' ? 4 : SEVERITY_ORDER[a.severity] ?? 3;
      const bO = b.status === 'pass' ? 4 : SEVERITY_ORDER[b.severity] ?? 3;
      return aO - bO;
    })
  );

  const filterControl = (c: AssessmentResult) => {
    if (statusFilter === 'all') return true;
    if (statusFilter === 'pass') return c.status === 'pass';
    if (statusFilter === 'critical') return c.status !== 'pass' && (c.severity === 'critical' || c.severity === 'high');
    if (statusFilter === 'medium') return c.status !== 'pass' && c.severity === 'medium';
    return true;
  };

  const isLoading = runsLoading || resultsLoading;
  const activeFw = FRAMEWORKS.find(f => f.id === activeTab);
  const totalCritical = (results ?? []).filter(r => r.status !== 'pass' && (r.severity === 'critical' || r.severity === 'high')).length;
  const totalMedium = (results ?? []).filter(r => r.status !== 'pass' && r.severity === 'medium').length;
  const totalPassing = (results ?? []).filter(r => r.status === 'pass').length;

  return (
    <div className="space-y-4 page-enter text-[var(--text-heading)]">
      {/* POAM toast */}
      {poamToast && (
        <div className="fixed top-4 right-4 z-50 bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 px-4 py-2.5 rounded-xl text-sm font-medium flex items-center gap-2 shadow-2xl shadow-black/40 animate-in slide-in-from-top">
          <CheckCircle className="w-4 h-4" /> {poamToast}
        </div>
      )}

      {/* Framework tabs */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-x-auto scrollbar-hide">
        <nav className="flex min-w-max border-b border-[var(--border-subtle)]">
          {FRAMEWORKS.map(fw => (
            <button
              key={fw.id}
              onClick={() => switchTab(fw.id)}
              className={`px-5 py-3.5 text-sm font-semibold border-b-2 transition-colors whitespace-nowrap ${
                activeTab === fw.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-[var(--border-color-hover)]'
              }`}
            >
              {fw.name}
            </button>
          ))}
          <button
            onClick={() => switchTab('ucf')}
            className={`px-5 py-3.5 text-sm font-semibold border-b-2 transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              activeTab === 'ucf'
                ? 'border-violet-500 text-violet-400'
                : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-[var(--border-color-hover)]'
            }`}
          >
            <Grid3X3 className="w-3.5 h-3.5" /> Unified Controls
          </button>
        </nav>
      </div>

      {isUCFTab ? (
        <UnifiedControlsTab />
      ) : (
        <>
          {/* Framework info + run status */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <h2 className="font-bold text-[var(--text-heading)] text-base">{activeFw?.name}</h2>
              <p className="text-xs text-slate-500 mt-0.5">{activeFw?.desc}</p>
            </div>
            {latestRun && (
              <div className="flex items-center gap-3 text-xs text-slate-500">
                <span>Last run: {new Date(latestRun.started_at).toLocaleString()}</span>
                {latestRun.pass_rate != null && (
                  <span className={`font-bold px-2 py-0.5 rounded-full border text-xs ${
                    latestRun.pass_rate >= 80 ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                    latestRun.pass_rate >= 60 ? 'bg-amber-500/15 text-amber-400 border-amber-500/20' :
                    'bg-red-500/15 text-red-400 border-red-500/20'
                  }`}>{latestRun.pass_rate.toFixed(1)}% pass rate</span>
                )}
              </div>
            )}
          </div>

          {/* Stats row */}
          {results && results.length > 0 && (
            <div className="grid grid-cols-3 gap-3">
              {[
                { filter: 'critical', value: totalCritical, label: 'Critical / High', icon: XCircle, cls: 'text-red-400', border: 'border-red-500/20', activeBorder: 'border-red-500/40 ring-1 ring-red-500/30', bg: 'bg-red-500/10' },
                { filter: 'medium',   value: totalMedium,   label: 'Medium Risk',     icon: AlertTriangle, cls: 'text-amber-400', border: 'border-amber-500/20', activeBorder: 'border-amber-500/40 ring-1 ring-amber-500/30', bg: 'bg-amber-500/10' },
                { filter: 'pass',     value: totalPassing,  label: 'Passing',         icon: CheckCircle, cls: 'text-emerald-400', border: 'border-emerald-500/20', activeBorder: 'border-emerald-500/40 ring-1 ring-emerald-500/30', bg: 'bg-emerald-500/10' },
              ].map(s => {
                const Icon = s.icon;
                const isActive = statusFilter === s.filter;
                return (
                  <button
                    key={s.filter}
                    onClick={() => changeFilter(isActive ? 'all' : s.filter)}
                    className={`flex items-center justify-between p-3.5 rounded-2xl border transition-all bg-[var(--bg-surface)] ${isActive ? s.activeBorder : s.border} hover:bg-[var(--bg-interactive)]`}
                  >
                    <div className="text-left">
                      <div className={`text-2xl font-extrabold ${s.cls}`}>{s.value}</div>
                      <div className="text-xs text-slate-500 mt-0.5">{s.label}</div>
                    </div>
                    <Icon className={`w-5 h-5 ${s.cls}`} />
                  </button>
                );
              })}
            </div>
          )}

          <div className="flex gap-4 min-h-0">
            <div className="flex-1 min-w-0 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
              {/* Filter bar */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)] bg-[var(--bg-subtle)]">
                <div className="flex items-center gap-2 text-xs text-slate-500 flex-wrap">
                  <Filter className="w-3.5 h-3.5" />
                  {(['all', 'critical', 'medium', 'pass'] as const).map(f => (
                    <button
                      key={f}
                      onClick={() => changeFilter(f)}
                      className={`px-2.5 py-1 rounded-full font-semibold transition-colors ${
                        statusFilter === f
                          ? f === 'critical' ? 'bg-red-500/15 text-red-400 border border-red-500/20' :
                            f === 'medium'   ? 'bg-amber-500/15 text-amber-400 border border-amber-500/20' :
                            f === 'pass'     ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20' :
                            'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                          : 'text-slate-500 hover:bg-[var(--bg-interactive)] hover:text-slate-300'
                      }`}
                    >
                      {f === 'all' ? 'All' : f === 'pass' ? 'Passing' : f === 'critical' ? 'Critical/High' : 'Medium'}
                    </button>
                  ))}
                </div>
                {statusFilter !== 'all' && (
                  <button onClick={() => changeFilter('all')} className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors">
                    <X className="w-3 h-3" /> Clear
                  </button>
                )}
              </div>

              {isLoading ? (
                <div className="py-16 text-center text-slate-500">
                  <Loader2 className="w-8 h-8 animate-spin mx-auto mb-3" />
                  <p className="text-sm">Loading controls…</p>
                </div>
              ) : !latestRunId ? (
                <div className="py-16 text-center">
                  <AlertTriangle className="w-10 h-10 text-slate-700 mx-auto mb-3" />
                  <h3 className="text-sm font-semibold text-slate-400">No assessment data</h3>
                  <p className="text-xs text-slate-600 mt-1">Run an assessment for this framework to see controls.</p>
                </div>
              ) : (
                <div className="divide-y divide-[var(--border-subtle)] max-h-[70vh] overflow-auto scrollbar-thin">
                  {Object.entries(familyGroups).map(([family, controls]) => {
                    const filtered = controls.filter(filterControl);
                    if (filtered.length === 0 && statusFilter !== 'all') return null;
                    const isExpanded = expandedFamilies[family] !== false;
                    const passCount = controls.filter(c => c.status === 'pass').length;
                    const critCount = controls.filter(c => c.status !== 'pass' && (c.severity === 'critical' || c.severity === 'high')).length;

                    return (
                      <div key={family}>
                        <button
                          onClick={() => setExpandedFamilies(p => ({ ...p, [family]: !isExpanded }))}
                          className="w-full flex items-center justify-between px-4 py-3 hover:bg-[var(--bg-subtle)] transition-colors text-left"
                        >
                          <div className="flex items-center gap-2">
                            {isExpanded
                              ? <ChevronDown className="w-4 h-4 text-slate-500" />
                              : <ChevronRight className="w-4 h-4 text-slate-500" />}
                            <span className="font-bold text-[var(--text-heading)] text-sm">{family} Family</span>
                            {critCount > 0 && (
                              <span className="text-[10px] px-1.5 py-0.5 bg-red-500/15 text-red-400 rounded-full border border-red-500/20 font-bold">{critCount} critical</span>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-600">{passCount}/{controls.length} passing</span>
                            <div className="w-16 h-1.5 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                              <div className="h-full bg-emerald-500" style={{ width: `${(passCount / controls.length) * 100}%` }} />
                            </div>
                          </div>
                        </button>

                        {isExpanded && (
                          <div className="divide-y divide-[var(--border-color)] bg-[var(--bg-subtle)]">
                            {(statusFilter === 'all' ? controls : filtered).map(control => {
                              const isFailing = control.status !== 'pass';
                              const isCritical = isFailing && (control.severity === 'critical' || control.severity === 'high');
                              const isMedium = isFailing && control.severity === 'medium';
                              const isSelected = selectedControl?.id === control.id;

                              return (
                                <div
                                  key={control.id}
                                  onClick={() => isFailing ? setSelectedControl(isSelected ? null : control) : undefined}
                                  className={`flex items-start gap-3 px-4 py-3 transition-all ${
                                    isFailing ? 'cursor-pointer hover:bg-[var(--bg-subtle)]' : 'cursor-default'
                                  } ${isSelected ? 'bg-blue-500/10 border-l-2 border-l-blue-500 pl-[14px]' : ''}`}
                                >
                                  <div className={`mt-0.5 flex-shrink-0 ${isCritical ? 'text-red-400' : isMedium ? 'text-amber-400' : 'text-emerald-400'}`}>
                                    {isCritical ? <XCircle className="w-4 h-4" /> :
                                     isMedium ? <AlertTriangle className="w-4 h-4" /> :
                                     <CheckCircle className="w-4 h-4" />}
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="font-mono text-[10px] font-bold bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-300 px-1.5 py-0.5 rounded">{control.control_id}</span>
                                      <span className="text-sm text-[var(--text-heading)] font-medium truncate">{control.assertion || control.check_id}</span>
                                    </div>
                                    <p className="text-xs text-slate-600 mt-0.5">{control.provider.toUpperCase()} · {control.region}</p>
                                    {isFailing && control.findings?.length > 0 && (
                                      <p className="text-xs text-slate-500 mt-1 line-clamp-1">{control.findings[0]}</p>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2 flex-shrink-0">
                                    <StatusBadge status={control.status} severity={control.severity} />
                                    {isFailing && (
                                      <ChevronRight className={`w-4 h-4 text-slate-600 transition-transform ${isSelected ? 'rotate-90 text-blue-400' : ''}`} />
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {selectedControl && (
              <div className="w-96 flex-shrink-0">
                <ControlDetailPanel
                  control={selectedControl}
                  remediation={remediation}
                  remLoading={remLoading}
                  onClose={() => setSelectedControl(null)}
                  onCreatePOAM={handleCreatePOAM}
                />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
