import { useState } from 'react';
import { Download, Loader2, Shield, Code, Package, CheckCircle } from 'lucide-react';
import api from '../lib/api';

const FRAMEWORKS = [
  { value: 'soc2', label: 'SOC 2 Type II' },
  { value: 'iso_27001', label: 'ISO 27001:2022' },
  { value: 'nist800_53', label: 'NIST 800-53 Rev 5' },
  { value: 'hipaa', label: 'HIPAA' },
  { value: 'gdpr', label: 'GDPR' },
  { value: 'fedramp', label: 'FedRAMP Moderate' },
  { value: 'cmmc', label: 'CMMC Level 2' },
  { value: 'pci_dss', label: 'PCI DSS v4.0' },
  { value: 'iso42001', label: 'ISO 42001' },
];

const DOC_TYPES = [
  { value: 'assessment-results', label: 'Assessment Results', desc: 'OSCAL AR — findings & observations for each control' },
  { value: 'poam', label: 'Plan of Action & Milestones', desc: 'OSCAL POA&M — remediation items for non-satisfied controls' },
  { value: 'ssp', label: 'System Security Plan', desc: 'OSCAL SSP — full system security plan with implemented requirements' },
];

export default function OSCALExportPage() {
  const [framework, setFramework] = useState('soc2');
  const [docType, setDocType] = useState('assessment-results');
  const [format, setFormat] = useState('json');
  const [exporting, setExporting] = useState(false);
  const [lastExport, setLastExport] = useState<string | null>(null);

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await api.get(
        `/export/oscal?framework=${framework}&document_type=${docType}&format=${format}`,
        { responseType: 'blob' }
      );
      const ext = format === 'xml' ? 'zip' : 'json';
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.setAttribute('download', `oscal_${docType}_${framework}.${ext}`);
      document.body.appendChild(a);
      a.click();
      a.parentNode?.removeChild(a);
      setLastExport(`oscal_${docType}_${framework}.${ext}`);
    } catch (e) { console.error(e); }
    finally { setExporting(false); }
  };

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
          <Package className="w-5 h-5 text-emerald-400" /> OSCAL Export
        </h2>
        <p className="text-slate-400 text-sm mt-0.5">
          Export compliance data in NIST OSCAL 1.1.2 format — machine-readable, signed, and verifiable
        </p>
      </div>

      {/* Export form */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 space-y-5">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="text-xs text-slate-500 block mb-1.5">Framework</label>
            <select value={framework} onChange={e => setFramework(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50">
              {FRAMEWORKS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1.5">Document Type</label>
            <select value={docType} onChange={e => setDocType(e.target.value)} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-emerald-500/50">
              {DOC_TYPES.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1.5">Format</label>
            <div className="flex gap-2">
              <button
                onClick={() => setFormat('json')}
                className={`flex-1 px-3 py-2.5 rounded-lg text-sm font-medium border transition-all ${format === 'json' ? 'bg-emerald-600/20 border-emerald-500/30 text-emerald-400' : 'bg-[var(--bg-interactive)] border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive-hover)]'}`}
              >
                JSON
              </button>
              <button
                onClick={() => setFormat('xml')}
                className={`flex-1 px-3 py-2.5 rounded-lg text-sm font-medium border transition-all ${format === 'xml' ? 'bg-emerald-600/20 border-emerald-500/30 text-emerald-400' : 'bg-[var(--bg-interactive)] border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive-hover)]'}`}
              >
                XML
              </button>
            </div>
          </div>
        </div>

        {/* Description of selected doc type */}
        <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3 flex items-start gap-3">
          <Code className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-xs font-semibold text-[var(--text-heading)]">{DOC_TYPES.find(d => d.value === docType)?.label}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">{DOC_TYPES.find(d => d.value === docType)?.desc}</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button onClick={handleExport} disabled={exporting} className="flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50">
            {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Export OSCAL {format.toUpperCase()}
          </button>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400/80">
            <Shield className="w-4 h-4" />
            <span>Includes JWS integrity signature</span>
          </div>
        </div>

        {lastExport && (
          <div className="flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>Exported: {lastExport}</span>
          </div>
        )}
      </div>

      {/* Info cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">OSCAL Version</div>
          <p className="text-2xl font-extrabold text-emerald-400">1.1.2</p>
          <p className="text-[11px] text-slate-400 mt-1">NIST Open Security Controls Assessment Language</p>
        </div>
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Integrity</div>
          <p className="text-2xl font-extrabold text-blue-400">JWS</p>
          <p className="text-[11px] text-slate-400 mt-1">JSON Web Signature with SHA-256 digest</p>
        </div>
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4">
          <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Compatibility</div>
          <p className="text-2xl font-extrabold text-violet-400">FedRAMP</p>
          <p className="text-[11px] text-slate-400 mt-1">Compatible with FedRAMP 20x, eMASS, and OSCAL tools</p>
        </div>
      </div>
    </div>
  );
}
