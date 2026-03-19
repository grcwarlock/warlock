import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Download, Search, Database, CheckCircle, XCircle, Filter, RefreshCw,
  Upload, X, Loader2, Shield, Clock, ChevronDown, ChevronRight,
  FileText, Play, AlertTriangle, Code
} from 'lucide-react';
import api from '../lib/api';

interface EvidenceItem {
  id: string;
  control_id: string;
  check_id: string;
  provider: string;
  service: string;
  resource_type: string;
  region: string;
  account_id: string;
  collected_at: string;
  status: string;
  sha256_hash: string;
  normalized_data?: Record<string, unknown>;
}

interface EvidenceListResponse {
  items: EvidenceItem[];
  total: number;
  page: number;
  page_size: number;
}

interface CollectionJob {
  job_id: string;
  status: string;
  current_stage: string;
  current_stage_label: string;
  progress: number;
  artifacts_collected: number;
  stages_completed: { stage: string; completed_at: string }[];
}

const PROVIDER_COLORS: Record<string, string> = {
  aws:     'bg-amber-500/15 text-amber-400 border-amber-500/20',
  azure:   'bg-blue-500/15 text-blue-400 border-blue-500/20',
  gcp:     'bg-emerald-500/15 text-emerald-400 border-emerald-500/20',
  okta:    'bg-violet-500/15 text-violet-400 border-violet-500/20',
  manual:  'bg-slate-500/15 text-slate-400 border-slate-500/20',
  qualys:  'bg-red-500/15 text-red-400 border-red-500/20',
  splunk:  'bg-orange-500/15 text-orange-400 border-orange-500/20',
};

function providerBadge(provider: string) {
  const cls = PROVIDER_COLORS[provider.toLowerCase()] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/20';
  return `${cls} text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase`;
}

export default function EvidencePage() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [providerFilter, setProviderFilter] = useState('');
  const [searchControl, setSearchControl] = useState('');
  const [expandedItem, setExpandedItem] = useState<string | null>(null);
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ id: string; valid: boolean } | null>(null);
  const [collectionJobId, setCollectionJobId] = useState<string | null>(null);
  const [uploadForm, setUploadForm] = useState({
    title: '', control_id: '', provider: 'manual', description: '',
    file_name: '', service: 'manual_upload', resource_type: 'document', region: 'global',
  });
  const [showOscalExport, setShowOscalExport] = useState(false);
  const [oscalFw, setOscalFw] = useState('soc2');
  const [oscalDocType, setOscalDocType] = useState('assessment-results');
  const [oscalFmt, setOscalFmt] = useState('json');
  const [oscalExporting, setOscalExporting] = useState(false);

  const { data, isLoading, refetch } = useQuery<EvidenceListResponse>({
    queryKey: ['evidence', page, providerFilter, searchControl],
    queryFn: async () => {
      let url = `/evidence/?page=${page}&page_size=25`;
      if (providerFilter) url += `&provider=${providerFilter}`;
      if (searchControl) url += `&control_id=${searchControl}`;
      return (await api.get(url)).data;
    },
  });

  // Fetch evidence detail when expanded
  const { data: evidenceDetail } = useQuery<EvidenceItem>({
    queryKey: ['evidence', 'detail', expandedItem],
    queryFn: async () => (await api.get(`/evidence/${expandedItem}`)).data,
    enabled: !!expandedItem,
  });

  // Fetch history when expanded
  const { data: evidenceHistory } = useQuery<{ history: { event: string; at: string }[]; collection_chain: { action: string; by: string; at: string }[] }>({
    queryKey: ['evidence', 'history', expandedItem],
    queryFn: async () => (await api.get(`/evidence/${expandedItem}/history`)).data,
    enabled: !!expandedItem,
  });

  // Collection job polling
  const { data: jobStatus } = useQuery<CollectionJob>({
    queryKey: ['evidence', 'job', collectionJobId],
    queryFn: async () => (await api.get(`/evidence/jobs/${collectionJobId}`)).data,
    enabled: !!collectionJobId,
    refetchInterval: (query) => {
      const d = query.state.data as CollectionJob | undefined;
      return d?.status === 'completed' ? false : 2000;
    },
  });

  const collectMutation = useMutation({
    mutationFn: async () => (await api.post('/evidence/collect', { framework: 'nist_800_53', providers: ['aws'] })).data,
    onSuccess: (data: { run_id: string }) => {
      setCollectionJobId(data.run_id);
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async () => (await api.post('/evidence/upload', uploadForm)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] });
      setShowUploadForm(false);
      setUploadForm({ title: '', control_id: '', provider: 'manual', description: '', file_name: '', service: 'manual_upload', resource_type: 'document', region: 'global' });
    },
  });

  const handleVerify = async (id: string) => {
    setVerifyingId(id);
    try {
      const res = await api.get(`/evidence/${id}/verify`);
      setVerifyResult({ id, valid: res.data.integrity_valid });
    } catch {
      setVerifyResult({ id, valid: false });
    } finally {
      setVerifyingId(null);
    }
  };

  const handleExport = async () => {
    try {
      const res = await api.get('/export/evidence?format=csv', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `evidence_export_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(a);
      a.click();
      a.parentNode?.removeChild(a);
    } catch (e) { console.error(e); }
  };

  const handleOscalExport = async () => {
    setOscalExporting(true);
    try {
      const res = await api.get(
        `/export/oscal?framework=${oscalFw}&document_type=${oscalDocType}&format=${oscalFmt}`,
        { responseType: 'blob' }
      );
      const ext = oscalFmt === 'xml' ? 'zip' : 'json';
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `oscal_${oscalDocType}_${oscalFw}.${ext}`);
      document.body.appendChild(a);
      a.click();
      a.parentNode?.removeChild(a);
    } catch (e) { console.error(e); }
    finally { setOscalExporting(false); setShowOscalExport(false); }
  };

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 25);

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <Database className="w-5 h-5 text-blue-400" /> Evidence Repository
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">
            {total.toLocaleString()} immutable records - raw configuration states and logs
          </p>
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <button onClick={() => collectMutation.mutate()} disabled={collectMutation.isPending} className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-[var(--text-heading)] px-4 py-2.5 rounded-xl text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60">
            {collectMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} Collect Evidence
          </button>
          <button onClick={() => setShowUploadForm(true)} className="flex items-center gap-2 bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-slate-300 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors">
            <Upload className="w-4 h-4" /> Upload
          </button>
          <button onClick={() => refetch()} className="p-2.5 bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl text-slate-400 hover:text-[var(--text-heading)] hover:bg-[var(--bg-interactive-hover)] transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={handleExport} className="flex items-center gap-2 bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-slate-300 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors">
            <Download className="w-4 h-4" /> Export CSV
          </button>
          <div className="relative">
            <button onClick={() => setShowOscalExport(!showOscalExport)} className="flex items-center gap-2 bg-emerald-600/20 border border-emerald-500/30 hover:bg-emerald-600/30 text-emerald-400 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors">
              <Code className="w-4 h-4" /> Export OSCAL
            </button>
            {showOscalExport && (
              <div className="absolute right-0 top-full mt-2 w-72 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-4 z-50 shadow-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[var(--text-heading)]">OSCAL Export</span>
                  <button onClick={() => setShowOscalExport(false)} className="text-slate-500 hover:text-[var(--text-heading)]"><X className="w-3.5 h-3.5" /></button>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Framework</label>
                  <select value={oscalFw} onChange={e => setOscalFw(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50">
                    <option value="soc2">SOC 2</option>
                    <option value="iso_27001">ISO 27001</option>
                    <option value="nist800_53">NIST 800-53</option>
                    <option value="hipaa">HIPAA</option>
                    <option value="gdpr">GDPR</option>
                    <option value="fedramp">FedRAMP</option>
                    <option value="cmmc">CMMC</option>
                    <option value="pci_dss">PCI DSS</option>
                    <option value="iso42001">ISO 42001</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Document Type</label>
                  <select value={oscalDocType} onChange={e => setOscalDocType(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50">
                    <option value="assessment-results">Assessment Results</option>
                    <option value="poam">Plan of Action &amp; Milestones</option>
                    <option value="ssp">System Security Plan</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1">Format</label>
                  <select value={oscalFmt} onChange={e => setOscalFmt(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50">
                    <option value="json">JSON</option>
                    <option value="xml">XML</option>
                  </select>
                </div>
                <button onClick={handleOscalExport} disabled={oscalExporting} className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-[var(--text-heading)] transition-all disabled:opacity-50">
                  {oscalExporting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                  Export OSCAL
                </button>
                <div className="flex items-center gap-1 text-[9px] text-emerald-400/70">
                  <Shield className="w-3 h-3" /> Signed &amp; verifiable (JWS)
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Collection Job Progress */}
      {collectionJobId && jobStatus && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/30 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {jobStatus.status === 'completed' ? (
                <CheckCircle className="w-4 h-4 text-emerald-400" />
              ) : (
                <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />
              )}
              <h3 className="text-sm font-bold text-[var(--text-heading)]">Evidence Collection</h3>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${jobStatus.status === 'completed' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-blue-500/15 text-blue-400'}`}>
                {jobStatus.status}
              </span>
            </div>
            {jobStatus.status === 'completed' && (
              <button onClick={() => { setCollectionJobId(null); refetch(); }} className="text-xs text-slate-500 hover:text-[var(--text-heading)]">Dismiss</button>
            )}
          </div>
          {/* Progress bar */}
          <div className="h-2 bg-[var(--bg-interactive)] rounded-full overflow-hidden mb-2">
            <div className="h-full bg-gradient-to-r from-blue-500 to-violet-500 rounded-full transition-all duration-500" style={{ width: `${jobStatus.progress}%` }} />
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-400">{jobStatus.current_stage_label}</span>
            <span className="text-slate-500">{jobStatus.progress}% - {jobStatus.artifacts_collected} artifacts collected</span>
          </div>
          {/* Stage history */}
          {jobStatus.stages_completed.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {jobStatus.stages_completed.map((s, i) => (
                <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {s.stage}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Upload form */}
      {showUploadForm && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/30 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
              <Upload className="w-4 h-4 text-blue-400" /> Upload Evidence
            </h3>
            <button onClick={() => setShowUploadForm(false)} className="text-slate-500 hover:text-[var(--text-heading)]"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input value={uploadForm.title} onChange={e => setUploadForm(p => ({ ...p, title: e.target.value }))} placeholder="Evidence title" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <input value={uploadForm.control_id} onChange={e => setUploadForm(p => ({ ...p, control_id: e.target.value }))} placeholder="Control ID (e.g., AC-2)" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <select value={uploadForm.provider} onChange={e => setUploadForm(p => ({ ...p, provider: e.target.value }))} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 appearance-none">
              {['manual', 'aws', 'azure', 'gcp', 'okta', 'qualys', 'splunk'].map(p => (
                <option key={p} value={p} className="bg-[var(--bg-surface)]">{p.toUpperCase()}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
            <input value={uploadForm.description} onChange={e => setUploadForm(p => ({ ...p, description: e.target.value }))} placeholder="Description" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <input value={uploadForm.file_name} onChange={e => setUploadForm(p => ({ ...p, file_name: e.target.value }))} placeholder="File name (e.g., mfa_report.pdf)" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="flex justify-end mt-4">
            <button onClick={() => uploadMutation.mutate()} disabled={!uploadForm.title || !uploadForm.control_id || uploadMutation.isPending} className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-sm font-bold text-[var(--text-heading)] transition-colors disabled:opacity-50">
              {uploadMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />} Upload Evidence
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={searchControl}
            onChange={e => { setSearchControl(e.target.value); setPage(1); }}
            placeholder="Search by control ID (e.g. AC-2, A.5.1)"
            className="w-full bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl pl-9 pr-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <select
            value={providerFilter}
            onChange={e => { setProviderFilter(e.target.value); setPage(1); }}
            className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl pl-9 pr-8 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 appearance-none"
          >
            <option value="" className="bg-[var(--bg-surface)]">All Providers</option>
            {['aws', 'azure', 'gcp', 'okta', 'manual', 'qualys', 'splunk'].map(p => (
              <option key={p} value={p} className="bg-[var(--bg-surface)] capitalize">{p.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-[var(--border-color)]">
              <tr>
                {['', 'Control / Check', 'Provider & Resource', 'Status', 'Collected At', 'Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-semibold uppercase tracking-wider whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {isLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    {[...Array(6)].map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-3 bg-[var(--bg-interactive)] rounded animate-pulse" style={{ width: `${60 + Math.random() * 30}%` }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <Database className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    No evidence records found
                  </td>
                </tr>
              ) : items.map(item => {
                const isExpanded = expandedItem === item.id;
                return (
                  <tr key={item.id} className="group cursor-pointer hover:bg-[var(--bg-subtle)] transition-colors" onClick={() => setExpandedItem(isExpanded ? null : item.id)}>
                    <td className="px-2 py-3 w-8">
                      <span className="p-1 text-slate-500 group-hover:text-[var(--text-heading)] transition-colors">
                        {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-bold text-blue-400">{item.control_id}</div>
                      <div className="text-slate-600 mt-0.5">{item.check_id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <button onClick={(e) => { e.stopPropagation(); setProviderFilter(item.provider); setPage(1); }} className={`${providerBadge(item.provider)} cursor-pointer hover:brightness-125 transition-all`}>{item.provider}</button>
                        <span className="text-slate-300 font-medium">{item.service}</span>
                      </div>
                      <div className="text-slate-600">{item.region} - {item.resource_type}</div>
                    </td>
                    <td className="px-4 py-3">
                      {item.status === 'collected' ? (
                        <span className="flex items-center gap-1 text-emerald-400 font-semibold">
                          <CheckCircle className="w-3.5 h-3.5" /> Collected
                        </span>
                      ) : item.status === 'failed' ? (
                        <span className="flex items-center gap-1 text-red-400 font-semibold">
                          <XCircle className="w-3.5 h-3.5" /> Failed
                        </span>
                      ) : (
                        <span className="text-slate-500 capitalize">{item.status}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                      {new Date(item.collected_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => handleVerify(item.id)}
                          disabled={verifyingId === item.id}
                          className="flex items-center gap-1 px-2 py-1 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-[10px] font-semibold text-slate-400 hover:text-[var(--text-heading)] hover:bg-[var(--bg-interactive-hover)] transition-colors disabled:opacity-50"
                        >
                          {verifyingId === item.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Shield className="w-3 h-3" />}
                          Verify
                        </button>
                        {verifyResult?.id === item.id && (
                          <span className={`flex items-center gap-0.5 text-[10px] font-bold ${verifyResult.valid ? 'text-emerald-400' : 'text-red-400'}`}>
                            {verifyResult.valid ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                            {verifyResult.valid ? 'Valid' : 'Tampered'}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Expanded evidence detail */}
        {expandedItem && evidenceDetail && (
          <div className="border-t border-[var(--border-color)] bg-[var(--bg-subtle)] px-5 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Normalized Data */}
              <div>
                <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-2 flex items-center gap-1">
                  <FileText className="w-3 h-3" /> Normalized Data
                </h4>
                {evidenceDetail.normalized_data ? (
                  <pre className="bg-black/40 border border-[var(--border-subtle)] rounded-lg p-3 text-[10px] text-slate-300 font-mono overflow-x-auto max-h-48 whitespace-pre-wrap">
                    {JSON.stringify(evidenceDetail.normalized_data, null, 2)}
                  </pre>
                ) : (
                  <p className="text-xs text-slate-500">No normalized data available</p>
                )}
                <button
                  onClick={() => { if (evidenceDetail.sha256_hash) { navigator.clipboard.writeText(evidenceDetail.sha256_hash); } }}
                  className="mt-2 text-[10px] text-slate-500 hover:text-blue-400 cursor-pointer transition-colors group"
                  title="Click to copy hash"
                >
                  <span className="font-mono">SHA-256: {evidenceDetail.sha256_hash || 'N/A'}</span>
                  <span className="ml-1 opacity-0 group-hover:opacity-100 text-blue-400 transition-opacity">copy</span>
                </button>
              </div>

              {/* History & Chain */}
              <div>
                <h4 className="text-[10px] font-bold text-slate-400 uppercase mb-2 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> Collection Timeline
                </h4>
                {evidenceHistory ? (
                  <div className="space-y-2">
                    {evidenceHistory.history.map((h, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 flex-shrink-0" />
                        <div>
                          <p className="text-xs text-[var(--text-heading)] capitalize">{h.event.replace(/_/g, ' ')}</p>
                          <p className="text-[10px] text-slate-500">{new Date(h.at).toLocaleString()}</p>
                        </div>
                      </div>
                    ))}
                    {evidenceHistory.collection_chain.length > 0 && (
                      <div className="mt-3">
                        <h5 className="text-[10px] font-bold text-slate-500 uppercase mb-1">Chain of Custody</h5>
                        {evidenceHistory.collection_chain.map((c, i) => (
                          <div key={i} className="flex items-center gap-2 text-[10px] text-slate-400">
                            <CheckCircle className="w-3 h-3 text-emerald-500" />
                            <span>{c.action} by {c.by}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">Loading history...</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="border-t border-[var(--border-color)] px-4 py-3 flex items-center justify-between">
            <p className="text-xs text-slate-500">{total.toLocaleString()} records</p>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-xs text-slate-400 hover:bg-[var(--bg-interactive-hover)] disabled:opacity-30 transition-colors">
                Previous
              </button>
              <span className="text-xs text-slate-400">Page {page} of {totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-xs text-slate-400 hover:bg-[var(--bg-interactive-hover)] disabled:opacity-30 transition-colors">
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
