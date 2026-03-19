import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  HardDrive, Search, AlertTriangle, RefreshCw,
  Database, Cloud, Code, FileText, MessageSquare, Shield,
  ChevronDown, ChevronRight, Zap, Eye, Loader2,
  Plus, X, Terminal, Lock, Trash2, ArrowRightLeft
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../lib/api';

interface Finding { type: string; count: number; severity: string; description: string; }
interface DetailedFinding {
  id: string; type: string; severity: string; data_type: string;
  file_path: string; line_number: number | null; column: string | null;
  sample: string; description: string;
  framework_violations: string[];
  remediation_actions: { action: string; label: string; command: string }[];
}
interface DataSilo {
  id: string; name: string; source_type: string; provider: string;
  connected: boolean; last_scanned: string | null; status: string;
  risk_level: string; total_objects: number; flagged_objects: number;
  data_types: string[]; frameworks: string[]; findings: Finding[];
}
interface SiloSummary {
  total_silos: number; connected: number; total_flagged: number;
  critical_findings: number; high_risk_silos: number; silos: DataSilo[];
}
interface ScanJob {
  job_id: string; silo_id: string; status: string; progress: number;
  current_stage: string; current_stage_label: string;
  objects_scanned: number; findings_count: number;
  stages_completed: { stage: string; completed_at: string }[];
}

const SOURCE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  cloud_storage: Cloud, source_control: Code, database: Database,
  document_store: FileText, data_warehouse: HardDrive, messaging: MessageSquare,
  default: HardDrive,
};

const RISK_CLASSES: Record<string, { card: string; badge: string }> = {
  critical: { card: 'border-red-500/30',    badge: 'bg-red-500/15 text-red-400 border-red-500/20' },
  high:     { card: 'border-orange-500/30', badge: 'bg-orange-500/15 text-orange-400 border-orange-500/20' },
  medium:   { card: 'border-amber-500/30',  badge: 'bg-amber-500/15 text-amber-400 border-amber-500/20' },
  low:      { card: 'border-emerald-500/30',badge: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' },
  unknown:  { card: 'border-[var(--border-color)]',       badge: 'bg-slate-500/15 text-slate-400 border-slate-500/20' },
};

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-blue-500', unknown: 'bg-slate-500',
};

const FW_CLASSES: Record<string, string> = {
  'HIPAA':      'bg-blue-500/10 border-blue-500/20 text-blue-400',
  'SOC 2':      'bg-violet-500/10 border-violet-500/20 text-violet-400',
  'NIST 800-53':'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  'ISO 27001':  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  'CMMC L2':    'bg-orange-500/10 border-orange-500/20 text-orange-400',
  'PCI DSS':    'bg-red-500/10 border-red-500/20 text-red-400',
  'GDPR':       'bg-cyan-500/10 border-cyan-500/20 text-cyan-400',
};

const REMEDIATION_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  mask_pii: Eye,
  encrypt: Lock,
  delete: Trash2,
  move_to_vault: ArrowRightLeft,
  rotate_credentials: RefreshCw,
  restrict_access: Shield,
};

const FW_ROUTE_MAP: Record<string, string> = {
  'HIPAA': 'hipaa', 'SOC 2': 'soc2', 'NIST 800-53': 'nist_800_53',
  'ISO 27001': 'iso_27001', 'CMMC L2': 'cmmc_l2', 'PCI DSS': 'pci_dss', 'GDPR': 'gdpr',
};

export default function DataSilosPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [filter, setFilter] = useState<'all' | 'connected' | 'findings'>('all');
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showAddForm, setShowAddForm] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [statFilter, setStatFilter] = useState<string | null>(null);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [addForm, setAddForm] = useState({
    name: '', source_type: 'cloud_storage', provider: 'aws',
    connection_string: '', frameworks: [] as string[], notes: '',
  });

  const { data, isLoading } = useQuery<SiloSummary>({
    queryKey: ['data-silos'],
    queryFn: async () => (await api.get('/data-silos/')).data,
    refetchInterval: 30000,
  });

  // Detailed findings for any expanded silo
  const expandedSiloIds = Object.entries(expanded).filter(([, v]) => v).map(([k]) => k);
  const expandedSiloId = expandedSiloIds.length > 0 ? expandedSiloIds[expandedSiloIds.length - 1] : null;
  const { data: siloFindings } = useQuery<{ findings: DetailedFinding[]; severity_breakdown: Record<string, number> }>({
    queryKey: ['data-silos', expandedSiloId, 'findings'],
    queryFn: async () => (await api.get(`/data-silos/${expandedSiloId}/findings`)).data,
    enabled: !!expandedSiloId,
  });

  // Scan job polling
  const { data: scanJobStatus } = useQuery<ScanJob>({
    queryKey: ['data-silos', 'scan-job', scanJobId],
    queryFn: async () => (await api.get(`/data-silos/scan-job/${scanJobId}`)).data,
    enabled: !!scanJobId,
    refetchInterval: (query) => {
      const d = query.state.data as ScanJob | undefined;
      return d?.status === 'completed' ? false : 1500;
    },
  });

  const scanMutation = useMutation({
    mutationFn: async (siloId: string) => (await api.post(`/data-silos/${siloId}/scan`)).data,
    onSuccess: (data: { job_id: string }) => {
      setScanJobId(data.job_id);
      queryClient.invalidateQueries({ queryKey: ['data-silos'] });
    },
  });

  const scanAllMutation = useMutation({
    mutationFn: async () => (await api.post('/data-silos/scan-all')).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['data-silos'] }),
  });

  const addMutation = useMutation({
    mutationFn: async () => (await api.post('/data-silos/', addForm)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['data-silos'] });
      setShowAddForm(false);
      setAddForm({ name: '', source_type: 'cloud_storage', provider: 'aws', connection_string: '', frameworks: [], notes: '' });
    },
  });

  const remediateMutation = useMutation({
    mutationFn: async ({ siloId, findingId, action }: { siloId: string; findingId: string; action: string }) =>
      (await api.post(`/data-silos/${siloId}/remediate/${findingId}`, { action, dry_run: true })).data,
  });

  const silos = data?.silos ?? [];
  const filtered = silos.filter(s => {
    if (filter === 'connected' && !s.connected) return false;
    if (filter === 'findings' && !s.flagged_objects) return false;
    if (search && !s.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <HardDrive className="w-5 h-5 text-amber-400" /> Data Silos
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">PII, PHI, and secrets discovery across your entire data landscape</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddForm(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-sm font-semibold text-slate-300 transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Source
          </button>
          <button
            onClick={() => scanAllMutation.mutate()}
            disabled={scanAllMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60 whitespace-nowrap"
          >
            {scanAllMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            Scan All Connected
          </button>
        </div>
      </div>

      {/* Add Data Source Form */}
      {showAddForm && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/30 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2"><Plus className="w-4 h-4 text-blue-400" /> Add Data Source</h3>
            <button onClick={() => setShowAddForm(false)} className="text-slate-500 hover:text-[var(--text-heading)]"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input value={addForm.name} onChange={e => setAddForm(p => ({ ...p, name: e.target.value }))} placeholder="Data source name" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <select value={addForm.source_type} onChange={e => setAddForm(p => ({ ...p, source_type: e.target.value }))} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 appearance-none">
              {['cloud_storage', 'database', 'source_control', 'document_store', 'data_warehouse', 'messaging'].map(t => (
                <option key={t} value={t} className="bg-[var(--bg-surface)]">{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <input value={addForm.provider} onChange={e => setAddForm(p => ({ ...p, provider: e.target.value }))} placeholder="Provider (aws, azure, gcp, etc.)" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            <input value={addForm.connection_string} onChange={e => setAddForm(p => ({ ...p, connection_string: e.target.value }))} placeholder="Connection string or bucket path (e.g., s3://my-bucket)" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <input value={addForm.notes} onChange={e => setAddForm(p => ({ ...p, notes: e.target.value }))} placeholder="Notes" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="flex justify-end mt-4">
            <button onClick={() => addMutation.mutate()} disabled={!addForm.name || addMutation.isPending} className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-sm font-bold text-[var(--text-heading)] transition-colors disabled:opacity-50">
              {addMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />} Add Data Source
            </button>
          </div>
        </div>
      )}

      {/* Scan Progress */}
      {scanJobId && scanJobStatus && scanJobStatus.status !== 'completed' && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/30 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
            <h3 className="text-sm font-bold text-[var(--text-heading)]">Scanning...</h3>
          </div>
          <div className="h-2 bg-[var(--bg-interactive)] rounded-full overflow-hidden mb-2">
            <div className="h-full bg-gradient-to-r from-blue-500 to-violet-500 rounded-full transition-all duration-500" style={{ width: `${scanJobStatus.progress}%` }} />
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">{scanJobStatus.current_stage_label}</span>
            <span className="text-slate-500">{scanJobStatus.progress}% - {scanJobStatus.objects_scanned.toLocaleString()} objects scanned</span>
          </div>
          {scanJobStatus.stages_completed.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {scanJobStatus.stages_completed.map((s, i) => (
                <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{s.stage}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { key: 'all', label: 'Data Sources',    value: data?.total_silos ?? 0,       sub: `${data?.connected ?? 0} connected`,         icon: Database,      cls: 'text-blue-400',   border: 'border-blue-500/20' },
          { key: 'findings', label: 'Total Flagged',   value: data?.total_flagged ?? 0,     sub: 'objects with sensitive data',               icon: Eye,           cls: 'text-amber-400',  border: 'border-amber-500/20' },
          { key: 'critical', label: 'Critical Findings',value: data?.critical_findings ?? 0,sub: 'need immediate action',                     icon: AlertTriangle, cls: 'text-red-400',    border: 'border-red-500/20' },
          { key: 'high_risk', label: 'High Risk Silos',  value: data?.high_risk_silos ?? 0,  sub: 'require remediation',                       icon: Shield,        cls: 'text-orange-400', border: 'border-orange-500/20' },
        ].map(s => {
          const Icon = s.icon;
          const isActive = statFilter === s.key;
          return (
            <button key={s.label} onClick={() => { setStatFilter(isActive ? null : s.key); if (s.key === 'findings') setFilter('findings'); else if (s.key === 'all') setFilter('all'); }} className={`bg-[var(--bg-surface)] border ${s.border} rounded-2xl p-5 cursor-pointer hover:bg-[var(--bg-interactive)] transition-all text-left ${isActive ? 'ring-1 ring-[var(--border-color-hover)]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-slate-400">{s.label}</p>
                <Icon className={`w-4 h-4 ${s.cls}`} />
              </div>
              <p className={`text-3xl font-extrabold ${s.cls} mb-0.5`}>{s.value.toLocaleString()}</p>
              <p className="text-[11px] text-slate-500">{s.sub}</p>
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex gap-1 bg-[var(--bg-surface)] border border-[var(--border-color)] p-1 rounded-xl">
          {(['all', 'connected', 'findings'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all capitalize ${filter === f ? 'bg-[var(--bg-interactive-hover)] text-[var(--text-heading)]' : 'text-slate-500 hover:text-slate-300'}`}
            >
              {f === 'findings' ? 'With Findings' : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search data sources..."
            className="w-full bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl pl-9 pr-4 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
      </div>

      {/* Silo cards */}
      <div className="space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 animate-pulse">
              <div className="h-4 bg-[var(--bg-interactive)] rounded w-1/3 mb-3" />
              <div className="h-3 bg-[var(--bg-interactive)] rounded w-2/3" />
            </div>
          ))
        ) : filtered.map(silo => {
          const SrcIcon = SOURCE_ICONS[silo.source_type] ?? HardDrive;
          const risk = silo.risk_level?.toLowerCase() ?? 'unknown';
          const riskCls = RISK_CLASSES[risk] ?? RISK_CLASSES.unknown;
          const isExpanded = expanded[silo.id];
          const isScanning = scanMutation.isPending && scanMutation.variables === silo.id;

          return (
            <div key={silo.id} className={`bg-[var(--bg-surface)] border ${riskCls.card} rounded-2xl overflow-hidden transition-all`}>
              <div className="p-5">
                <div className="flex items-start gap-4">
                  <div className="w-10 h-10 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] flex items-center justify-center flex-shrink-0">
                    <SrcIcon className="w-5 h-5 text-blue-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <h3 className="font-bold text-[var(--text-heading)] text-sm">{silo.name}</h3>
                      {silo.connected && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 font-semibold">Connected</span>}
                      {risk !== 'unknown' && <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-bold capitalize ${riskCls.badge}`}>{risk} Risk</span>}
                    </div>
                    <p className="text-xs text-slate-500">
                      {silo.total_objects?.toLocaleString()} objects scanned{' '}
                      {silo.flagged_objects > 0 && <span className="text-amber-400 font-semibold">| {silo.flagged_objects} flagged</span>}
                      {silo.last_scanned && <span className="ml-1">| Last scan {new Date(silo.last_scanned).toLocaleString()}</span>}
                    </p>
                    {silo.data_types?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {silo.data_types.map(dt => (
                          <span key={dt} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400">{dt}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      onClick={() => scanMutation.mutate(silo.id)}
                      disabled={!silo.connected || isScanning}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-xs font-semibold text-slate-300 transition-colors disabled:opacity-40"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} /> Scan
                    </button>
                    {(silo.findings?.length > 0 || silo.flagged_objects > 0) && (
                      <button
                        onClick={() => setExpanded(p => ({ ...p, [silo.id]: !p[silo.id] }))}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-semibold transition-colors ${isExpanded ? 'bg-blue-500/15 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-interactive)] border-[var(--border-color)] text-slate-300 hover:bg-[var(--bg-interactive-hover)]'}`}
                      >
                        <Eye className="w-3.5 h-3.5" /> {isExpanded ? 'Collapse' : 'Investigate'}
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Findings drill-down — shows when expanded */}
              {isExpanded && (
                <div className="border-t border-[var(--border-subtle)] px-5 pb-5">
                  {/* Framework badges */}
                  {silo.frameworks?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-3">
                      {silo.frameworks.map(fw => (
                        <button key={fw} onClick={() => navigate(`/frameworks?fw=${FW_ROUTE_MAP[fw] || 'nist_800_53'}`)} className={`text-[10px] px-2 py-0.5 rounded border cursor-pointer hover:brightness-125 transition-all ${FW_CLASSES[fw] ?? 'bg-slate-500/10 border-slate-500/20 text-slate-400'}`}>{fw}</button>
                      ))}
                    </div>
                  )}

                  <div className="flex items-center justify-between py-3">
                    <div className="flex items-center gap-2">
                      <h4 className="text-[10px] font-bold text-slate-400 uppercase">Findings — click to see remediation</h4>
                      {expandedSiloId === silo.id && siloFindings?.severity_breakdown && (
                        <div className="flex gap-1.5">
                          {Object.entries(siloFindings.severity_breakdown).map(([sev, cnt]) => (
                            <span key={sev} className={`text-[9px] px-1.5 py-0.5 rounded border font-bold capitalize ${RISK_CLASSES[sev]?.badge ?? RISK_CLASSES.unknown.badge}`}>
                              {sev}: {cnt}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Loading state */}
                  {expandedSiloId === silo.id && !siloFindings && (
                    <div className="flex items-center gap-2 py-4 text-slate-500 text-xs">
                      <Loader2 className="w-4 h-4 animate-spin" /> Loading detailed findings...
                    </div>
                  )}

                  {/* Summary findings if detailed not loaded yet */}
                  {expandedSiloId !== silo.id && silo.findings?.length > 0 && (
                    <div className="space-y-2">
                      {silo.findings.map((finding, i) => (
                        <div key={i} className="flex items-center justify-between py-2 px-3 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-subtle)]">
                          <div className="flex items-center gap-3">
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[finding.severity] ?? SEV_DOT.unknown}`} />
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="font-bold text-[var(--text-heading)] text-xs">{finding.type}</span>
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border capitalize ${RISK_CLASSES[finding.severity]?.badge ?? RISK_CLASSES.unknown.badge}`}>{finding.severity}</span>
                                <span className="text-[11px] text-slate-500">{finding.count} instances</span>
                              </div>
                              <p className="text-[11px] text-slate-500">{finding.description}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Detailed findings with remediation */}
                  {expandedSiloId === silo.id && siloFindings && (
                  <div className="space-y-2">
                    {siloFindings.findings.map((finding) => {
                      const isFindingExpanded = expandedFinding === finding.id;
                      return (
                        <div key={finding.id} className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl overflow-hidden">
                          <button
                            onClick={() => setExpandedFinding(isFindingExpanded ? null : finding.id)}
                            className="w-full px-4 py-3 flex items-center justify-between hover:bg-[var(--bg-subtle)] transition-colors text-left"
                          >
                            <div className="flex items-center gap-3">
                              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${SEV_DOT[finding.severity] ?? SEV_DOT.unknown}`} />
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-bold text-[var(--text-heading)]">{finding.data_type}</span>
                                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border capitalize ${RISK_CLASSES[finding.severity]?.badge ?? RISK_CLASSES.unknown.badge}`}>{finding.severity}</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-interactive)] text-slate-400">{finding.type}</span>
                                </div>
                                <p className="text-[11px] text-slate-500 mt-0.5">{finding.description}</p>
                              </div>
                            </div>
                            {isFindingExpanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                          </button>

                          {isFindingExpanded && (
                            <div className="border-t border-[var(--border-subtle)] px-4 py-3 space-y-3">
                              {/* Location */}
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                  <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-1">Location</h5>
                                  <p className="text-xs text-slate-300 font-mono">{finding.file_path}</p>
                                  {finding.line_number && <p className="text-[10px] text-slate-500">Line: {finding.line_number}</p>}
                                  {finding.column && <p className="text-[10px] text-slate-500">Column: {finding.column}</p>}
                                  {finding.sample && (
                                    <pre className="mt-1 bg-black/40 border border-[var(--border-subtle)] rounded px-2 py-1 text-[10px] text-amber-400 font-mono">{finding.sample}</pre>
                                  )}
                                </div>
                                <div>
                                  <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-1">Framework Violations</h5>
                                  <div className="flex flex-wrap gap-1">
                                    {finding.framework_violations.map((fv, i) => (
                                      <button key={i} onClick={() => navigate(`/frameworks?fw=nist_800_53`)} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 cursor-pointer hover:brightness-125 transition-all">{fv}</button>
                                    ))}
                                  </div>
                                </div>
                              </div>

                              {/* Remediation Actions */}
                              <div>
                                <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Remediation Actions</h5>
                                <div className="space-y-2">
                                  {finding.remediation_actions.map((action, i) => {
                                    const RIcon = REMEDIATION_ICONS[action.action] ?? Terminal;
                                    const isRemediating = remediateMutation.isPending && remediateMutation.variables?.findingId === finding.id && remediateMutation.variables?.action === action.action;
                                    return (
                                      <div key={i} className="bg-black/20 border border-[var(--border-subtle)] rounded-lg p-3">
                                        <div className="flex items-center justify-between mb-2">
                                          <div className="flex items-center gap-2">
                                            <RIcon className="w-3.5 h-3.5 text-blue-400" />
                                            <span className="text-xs font-bold text-[var(--text-heading)]">{action.label}</span>
                                          </div>
                                          <button
                                            onClick={() => remediateMutation.mutate({ siloId: silo.id, findingId: finding.id, action: action.action })}
                                            disabled={isRemediating}
                                            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-blue-600/20 border border-blue-500/30 text-[10px] font-bold text-blue-400 hover:bg-blue-600/30 transition-colors disabled:opacity-50"
                                          >
                                            {isRemediating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Terminal className="w-3 h-3" />}
                                            Dry Run
                                          </button>
                                        </div>
                                        <pre className="bg-black/40 border border-[var(--border-subtle)] rounded px-2 py-1.5 text-[10px] text-emerald-400 font-mono overflow-x-auto whitespace-pre-wrap max-h-32">
                                          {action.command}
                                        </pre>
                                        {/* Show remediation result */}
                                        {remediateMutation.data && remediateMutation.variables?.findingId === finding.id && remediateMutation.variables?.action === action.action && (
                                          <div className="mt-2 text-[10px] bg-emerald-500/10 border border-emerald-500/20 rounded px-2 py-1.5 text-emerald-400">
                                            {remediateMutation.data.message}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {!isLoading && filtered.length === 0 && (
          <div className="py-16 text-center text-slate-500 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl">
            <HardDrive className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No data sources found</p>
          </div>
        )}
      </div>
    </div>
  );
}
