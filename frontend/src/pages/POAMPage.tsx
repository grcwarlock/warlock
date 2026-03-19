import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileText, Download, ChevronDown, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Shield, Loader2, Package
} from 'lucide-react';
import api from '../lib/api';

const SEVERITY_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/20',
};

const STATUS_CLASSES: Record<string, string> = {
  open:        'bg-red-500/10 text-red-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  completed:   'bg-emerald-500/10 text-emerald-400',
  deferred:    'bg-slate-500/10 text-slate-400',
};

export default function POAMPage() {
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
  const [sevFilter, setSevFilter] = useState('');

  const { data: runs } = useQuery({
    queryKey: ['assessments', 'runs'],
    queryFn: async () => (await api.get('/assessments/runs?limit=1')).data,
  });

  const latestRunId = runs?.[0]?.id;

  const { data: poamData, isLoading } = useQuery({
    queryKey: ['exports', 'poam', latestRunId],
    queryFn: async () => (await api.get(`/export/poam?assessment_run_id=${latestRunId}&format=json`)).data,
    enabled: !!latestRunId,
  });

  const toggleRow = (id: string) => setExpandedRows(p => ({ ...p, [id]: !p[id] }));

  const downloadPOAM = () => { if (latestRunId) window.location.href = `/api/v1/export/poam?assessment_run_id=${latestRunId}&format=txt`; };
  const downloadAudit = () => { if (latestRunId) window.location.href = `/api/v1/export/audit-package?assessment_run_id=${latestRunId}&target_framework=nist_800_53`; };

  const items: any[] = poamData?.items ?? [];
  const filteredItems = sevFilter ? items.filter(i => i.severity === sevFilter) : items;
  const critCount = items.filter(i => i.severity === 'critical' || i.severity === 'high').length;
  const medCount  = items.filter(i => i.severity === 'medium').length;
  const lowCount  = items.filter(i => i.severity === 'low').length;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" /> POAM — Plan of Action & Milestones
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Audit-ready finding tracker with step-by-step remediation</p>
        </div>
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={downloadPOAM}
            disabled={!latestRunId}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-sm font-medium text-slate-300 transition-colors disabled:opacity-40"
          >
            <Download className="w-4 h-4" /> POAM.txt
          </button>
          <button
            onClick={downloadAudit}
            disabled={!latestRunId}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20 disabled:opacity-40"
          >
            <Package className="w-4 h-4" /> Audit Package
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Critical / High', value: critCount, cls: 'text-red-400 border-red-500/20', bg: 'bg-red-500/10', icon: AlertTriangle, filterVal: 'critical' },
          { label: 'Medium', value: medCount, cls: 'text-amber-400 border-amber-500/20', bg: 'bg-amber-500/10', icon: Clock, filterVal: 'medium' },
          { label: 'Low', value: lowCount, cls: 'text-blue-400 border-blue-500/20', bg: 'bg-blue-500/10', icon: Shield, filterVal: 'low' },
        ].map(c => {
          const Icon = c.icon;
          const isActive = sevFilter === c.filterVal;
          return (
            <button key={c.label} onClick={() => setSevFilter(isActive ? '' : c.filterVal)} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]}`}>{isLoading ? '—' : c.value}</p>
            </button>
          );
        })}
      </div>

      {/* Filter */}
      <div className="flex gap-2 flex-wrap">
        {['', 'critical', 'high', 'medium', 'low'].map(s => (
          <button
            key={s}
            onClick={() => setSevFilter(s)}
            className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${sevFilter === s ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:border-[var(--border-color-hover)]'}`}
          >
            {s === '' ? `All (${items.length})` : `${s.charAt(0).toUpperCase() + s.slice(1)} (${items.filter(i => i.severity === s).length})`}
          </button>
        ))}
      </div>

      {/* POAM table */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Loader2 className="w-7 h-7 animate-spin" />
            <p className="text-sm">Loading POAM data…</p>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <CheckCircle className="w-10 h-10 text-emerald-500/40" />
            <p className="text-sm font-semibold">No findings</p>
            <p className="text-xs">Trigger an assessment run to generate POAM items</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {filteredItems.map((item: any) => (
              <div key={item.id}>
                <button
                  onClick={() => toggleRow(item.id)}
                  className="w-full text-left px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors flex items-center gap-4"
                >
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-4 gap-3 sm:gap-6 items-center">
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-bold text-blue-400 text-sm">{item.control_id}</span>
                        {item.severity && (
                          <button onClick={(e) => { e.stopPropagation(); setSevFilter(sevFilter === item.severity ? '' : item.severity); }} className={`${SEVERITY_CLASSES[item.severity] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border cursor-pointer hover:brightness-125 transition-all`}>
                            {item.severity}
                          </button>
                        )}
                      </div>
                      <p className="text-xs text-slate-500 leading-tight line-clamp-1">{item.weakness}</p>
                    </div>
                    <div className="text-xs text-slate-400">
                      <span className="text-slate-600">Detection: </span>
                      {item.detection_date ? new Date(item.detection_date).toLocaleDateString() : '—'}
                    </div>
                    <div className="text-xs text-slate-400">
                      <span className="text-slate-600">Scheduled: </span>
                      {item.scheduled_completion ? new Date(item.scheduled_completion).toLocaleDateString() : '—'}
                    </div>
                    <div>
                      {item.status && (
                        <span className={`${STATUS_CLASSES[item.status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize`}>
                          {item.status.replace('_', ' ')}
                        </span>
                      )}
                    </div>
                  </div>
                  {expandedRows[item.id]
                    ? <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
                    : <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />}
                </button>

                {expandedRows[item.id] && (
                  <div className="px-5 pb-5 bg-[var(--bg-subtle)] grid grid-cols-1 md:grid-cols-2 gap-4">
                    {item.description && (
                      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-4">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Description</p>
                        <p className="text-xs text-slate-300 leading-relaxed">{item.description}</p>
                      </div>
                    )}
                    {item.remediation_steps?.length > 0 && (
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
                        <p className="text-[10px] font-bold text-blue-400 uppercase tracking-wider mb-3">Remediation Steps</p>
                        <ol className="space-y-2">
                          {item.remediation_steps.map((step: string, i: number) => (
                            <li key={i} className="flex gap-2.5 text-xs text-slate-300 leading-relaxed">
                              <span className="flex-shrink-0 w-4 h-4 rounded-full bg-blue-500/20 border border-blue-500/30 flex items-center justify-center font-bold text-blue-400 text-[9px]">{i + 1}</span>
                              {step}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                    {item.resources && (
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Resources Required</p>
                        <p className="text-xs text-slate-300">{item.resources}</p>
                      </div>
                    )}
                    {item.milestones?.length > 0 && (
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Milestones</p>
                        {item.milestones.map((m: any, i: number) => (
                          <div key={i} className="flex items-center gap-2 text-xs text-slate-400 py-1">
                            <CheckCircle className="w-3 h-3 text-slate-600 flex-shrink-0" />
                            <span>{m.description || m}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
