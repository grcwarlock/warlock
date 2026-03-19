import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  FileCode, Download, Loader2,
  Shield, ChevronDown, ChevronRight, Code, CheckCircle
} from 'lucide-react';
import api from '../lib/api';

const STATUS_CLASSES: Record<string, string> = {
  implemented: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  partially_implemented: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  planned: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const FRAMEWORK_OPTIONS = [
  { value: 'nist_800_53', label: 'NIST 800-53' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso_27001', label: 'ISO 27001' },
  { value: 'hipaa', label: 'HIPAA' },
  { value: 'cmmc_l2', label: 'CMMC Level 2' },
];

const OSCAL_DOC_TYPES = [
  { value: 'ssp', label: 'System Security Plan' },
  { value: 'poam', label: 'Plan of Action & Milestones' },
  { value: 'assessment_results', label: 'Assessment Results' },
];

export default function SSPPage() {
  const [framework, setFramework] = useState('nist_800_53');
  const [systemName, setSystemName] = useState('Warlock Platform');
  const [categorization, setCategorization] = useState('Moderate');
  const [expandedCtrl, setExpandedCtrl] = useState<string | null>(null);
  const [familyFilter, setFamilyFilter] = useState('');
  const [oscalType, setOscalType] = useState('ssp');
  const [showOscal, setShowOscal] = useState(false);
  const [oscalFormat, setOscalFormat] = useState('json');
  const [oscalDownloading, setOscalDownloading] = useState(false);

  const generateMut = useMutation({
    mutationFn: (data: any) => api.post('/ssp/generate', data),
  });

  const oscalMut = useMutation({
    mutationFn: (data: any) => api.post('/ssp/oscal', data),
  });

  const handleOscalDownload = async () => {
    setOscalDownloading(true);
    try {
      const res = await api.get(
        `/export/oscal?framework=${framework}&document_type=${oscalType}&format=${oscalFormat}`,
        { responseType: 'blob' }
      );
      const ext = oscalFormat === 'xml' ? 'zip' : 'json';
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `oscal_${oscalType}_${framework}.${ext}`);
      document.body.appendChild(a);
      a.click();
      a.parentNode?.removeChild(a);
    } catch (e) { console.error(e); }
    finally { setOscalDownloading(false); }
  };

  const ssp = generateMut.data?.data;
  const oscalData = oscalMut.data?.data;

  const narratives = ssp?.control_narratives ?? [];
  const families = Array.from(new Set<string>(narratives.map((n: any) => n.family)));
  const filtered = familyFilter ? narratives.filter((n: any) => n.family === familyFilter) : narratives;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <FileCode className="w-5 h-5 text-blue-400" /> SSP Generator & OSCAL Export
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Auto-generate System Security Plans with control narratives & OSCAL output</p>
        </div>
      </div>

      {/* Generation form */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-[var(--text-heading)]">Generate SSP</h3>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
          <div>
            <label className="text-xs text-slate-500 block mb-1">Framework</label>
            <select value={framework} onChange={e => setFramework(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
              {FRAMEWORK_OPTIONS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">System Name</label>
            <input value={systemName} onChange={e => setSystemName(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">Security Categorization</label>
            <select value={categorization} onChange={e => setCategorization(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
              <option value="Low">Low</option>
              <option value="Moderate">Moderate</option>
              <option value="High">High</option>
            </select>
          </div>
          <div className="flex items-end">
            <button onClick={() => generateMut.mutate({ framework, system_name: systemName, security_categorization: categorization })} disabled={generateMut.isPending} className="w-full px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20 disabled:opacity-50">
              {generateMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : 'Generate SSP'}
            </button>
          </div>
        </div>
      </div>

      {/* OSCAL Export */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 space-y-4">
        <button onClick={() => setShowOscal(!showOscal)} className="w-full flex items-center justify-between">
          <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2"><Code className="w-4 h-4 text-violet-400" /> OSCAL Export (Machine-Readable)</h3>
          {showOscal ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
        </button>
        {showOscal && (
          <div className="space-y-4">
            <p className="text-xs text-slate-400">Export compliance data in NIST OSCAL format for FedRAMP 20x, eMASS, and machine-readable compliance.</p>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div>
                <label className="text-xs text-slate-500 block mb-1">Document Type</label>
                <select value={oscalType} onChange={e => setOscalType(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                  {OSCAL_DOC_TYPES.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500 block mb-1">Framework</label>
                <select value={framework} onChange={e => setFramework(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                  {FRAMEWORK_OPTIONS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-500 block mb-1">Format</label>
                <select value={oscalFormat} onChange={e => setOscalFormat(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                  <option value="json">JSON</option>
                  <option value="xml">XML</option>
                </select>
              </div>
              <div className="flex flex-col items-stretch justify-end gap-1.5">
                <button onClick={() => oscalMut.mutate({ framework, document_type: oscalType, format: 'json' })} disabled={oscalMut.isPending} className="w-full px-4 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all disabled:opacity-50">
                  {oscalMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : 'Preview OSCAL'}
                </button>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={handleOscalDownload} disabled={oscalDownloading} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-sm font-bold text-[var(--text-heading)] transition-all disabled:opacity-50">
                {oscalDownloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                Export as OSCAL
              </button>
              <span className="flex items-center gap-1.5 text-[10px] text-emerald-400/80">
                <CheckCircle className="w-3.5 h-3.5" /> Signed &amp; verifiable (JWS)
              </span>
            </div>
            {oscalData && (
              <div className="bg-black/30 border border-[var(--border-color)] rounded-xl p-4 max-h-[300px] overflow-auto">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[10px] font-bold text-violet-400 uppercase tracking-wider">OSCAL {oscalData.oscal_version} — {oscalData.document_type}</p>
                  <button onClick={() => {
                    const blob = new Blob([JSON.stringify(oscalData.document, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a'); a.href = url; a.download = `oscal-${oscalData.document_type}.json`; a.click();
                  }} className="text-[10px] text-blue-400 hover:text-blue-300 flex items-center gap-1">
                    <Download className="w-3 h-3" /> Download
                  </button>
                </div>
                <pre className="text-[11px] text-slate-400 leading-relaxed font-mono whitespace-pre-wrap">{JSON.stringify(oscalData.document, null, 2).substring(0, 3000)}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* SSP Results */}
      {ssp && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-4 gap-4">
            <button onClick={() => setFamilyFilter('')} className={`bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${!familyFilter ? 'ring-1 ring-[var(--border-color-hover)]' : ''}`}>
              <span className="text-xs text-slate-400">System</span>
              <p className="text-sm font-bold text-[var(--text-heading)] mt-1 truncate">{ssp.system_name}</p>
            </button>
            <button onClick={() => { const impl = narratives.filter((n: any) => n.status === 'implemented'); if (impl.length > 0) setExpandedCtrl(impl[0].control_id); }} className="bg-[var(--bg-surface)] border border-emerald-500/20 rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all">
              <span className="text-xs text-slate-400">Implementation Rate</span>
              <p className="text-3xl font-extrabold text-emerald-400 mt-1">{ssp.implementation_rate}%</p>
            </button>
            <button onClick={() => setFamilyFilter('')} className="bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all">
              <span className="text-xs text-slate-400">Total Controls</span>
              <p className="text-3xl font-extrabold text-blue-400 mt-1">{ssp.total_controls}</p>
            </button>
            <button onClick={() => {}} className="bg-[var(--bg-surface)] border border-violet-500/20 rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all">
              <span className="text-xs text-slate-400">Categorization</span>
              <p className="text-sm font-bold text-violet-400 mt-1">{ssp.security_categorization}</p>
            </button>
          </div>

          {/* Family filter */}
          <div className="flex gap-2 flex-wrap">
            <button onClick={() => setFamilyFilter('')} className={`px-3 py-1.5 rounded-xl text-xs font-semibold border ${!familyFilter ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400'}`}>
              All ({narratives.length})
            </button>
            {families.map((f: string) => (
              <button key={f} onClick={() => setFamilyFilter(f)} className={`px-3 py-1.5 rounded-xl text-xs font-semibold border ${familyFilter === f ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400'}`}>
                {f} ({narratives.filter((n: any) => n.family === f).length})
              </button>
            ))}
          </div>

          {/* Control narratives */}
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden divide-y divide-[var(--border-subtle)]">
            {filtered.map((n: any) => (
              <div key={n.control_id}>
                <button onClick={() => setExpandedCtrl(expandedCtrl === n.control_id ? null : n.control_id)} className="w-full text-left px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors flex items-center gap-4">
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-4 gap-3 items-center">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-blue-400">{n.control_id}</span>
                      <button onClick={(e) => { e.stopPropagation(); }} className={`${STATUS_CLASSES[n.status] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border cursor-pointer hover:brightness-125 transition-all`}>{n.status.replace('_', ' ')}</button>
                    </div>
                    <div className="sm:col-span-2 text-xs text-slate-300 line-clamp-1">{n.title}</div>
                    <div className="text-xs text-slate-500">{n.family_name}</div>
                  </div>
                  {expandedCtrl === n.control_id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>
                {expandedCtrl === n.control_id && (
                  <div className="px-5 pb-5 bg-[var(--bg-subtle)] space-y-3">
                    <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4">
                      <p className="text-[10px] font-bold text-blue-400 uppercase tracking-wider mb-2">Implementation Narrative</p>
                      <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{n.narrative}</p>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-500">
                      <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> {n.responsible_role}</span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
