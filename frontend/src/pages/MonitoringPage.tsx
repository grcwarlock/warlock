import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Activity, Play, Plus, Clock, AlertTriangle, CheckCircle,
  Loader2, Wifi, WifiOff, Bell, ChevronDown, ChevronRight, Shield
} from 'lucide-react';
import api from '../lib/api';

const CADENCE_OPTIONS = ['hourly', 'daily', 'weekly'];
const FRAMEWORK_OPTIONS = ['nist_800_53', 'soc2', 'iso_27001', 'hipaa', 'cmmc', 'pci_dss', 'gdpr', 'fedramp_moderate', 'iso_42001'];

export default function MonitoringPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [cardFilter, setCardFilter] = useState<'all' | 'active' | 'drift' | 'healthy' | 'paused'>('all');
  const [form, setForm] = useState({ name: '', framework: 'nist_800_53', cadence: 'daily', alert_on_drift: true, alert_channels: [] as string[], providers: ['aws'] });

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['monitoring', 'schedules'],
    queryFn: async () => (await api.get('/monitoring/schedules')).data,
  });

  const createMut = useMutation({
    mutationFn: (data: any) => api.post('/monitoring/schedules', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['monitoring'] }); setShowCreate(false); setForm({ name: '', framework: 'nist_800_53', cadence: 'daily', alert_on_drift: true, alert_channels: [], providers: ['aws'] }); },
  });

  const runMut = useMutation({
    mutationFn: (id: string) => api.post(`/monitoring/schedules/${id}/run`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['monitoring'] }),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) => api.put(`/monitoring/schedules/${id}`, { is_active }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['monitoring'] }),
  });

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" /> Continuous Monitoring
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Automated compliance monitoring with drift detection & alerting</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20">
          <Plus className="w-4 h-4" /> New Schedule
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">Create Monitoring Schedule</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-500 block mb-1">Name</label>
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Production NIST Monitor" className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Framework</label>
              <select value={form.framework} onChange={e => setForm({ ...form, framework: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                {FRAMEWORK_OPTIONS.map(f => <option key={f} value={f}>{f.replace(/_/g, ' ').toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Cadence</label>
              <select value={form.cadence} onChange={e => setForm({ ...form, cadence: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                {CADENCE_OPTIONS.map(c => <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
              <input type="checkbox" checked={form.alert_on_drift} onChange={e => setForm({ ...form, alert_on_drift: e.target.checked })} className="rounded" />
              Alert on drift
            </label>
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.name || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-[var(--text-heading)] disabled:opacity-40">
              {createMut.isPending ? 'Creating…' : 'Create Schedule'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { key: 'active' as const, label: 'Active Monitors', value: schedules.filter((s: any) => s.is_active).length, icon: Wifi, cls: 'text-emerald-400 border-emerald-500/20' },
          { key: 'drift' as const, label: 'Drift Detected', value: schedules.filter((s: any) => s.drift_detected).length, icon: AlertTriangle, cls: 'text-red-400 border-red-500/20' },
          { key: 'healthy' as const, label: 'Healthy', value: schedules.filter((s: any) => s.is_active && !s.drift_detected).length, icon: CheckCircle, cls: 'text-blue-400 border-blue-500/20' },
          { key: 'paused' as const, label: 'Paused', value: schedules.filter((s: any) => !s.is_active).length, icon: WifiOff, cls: 'text-slate-400 border-slate-500/20' },
        ].map(c => {
          const Icon = c.icon;
          const isActive = cardFilter === c.key;
          return (
            <button key={c.label} onClick={() => setCardFilter(isActive ? 'all' : c.key)} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 cursor-pointer hover:bg-[var(--bg-interactive)] transition-all text-left ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]}`}>{isLoading ? '—' : c.value}</p>
            </button>
          );
        })}
      </div>

      {/* Schedules list */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Loader2 className="w-7 h-7 animate-spin" />
            <p className="text-sm">Loading monitors…</p>
          </div>
        ) : schedules.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Activity className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No monitoring schedules</p>
            <p className="text-xs">Create a schedule to enable continuous compliance monitoring</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {schedules.filter((s: any) => {
              if (cardFilter === 'active') return s.is_active;
              if (cardFilter === 'drift') return s.drift_detected;
              if (cardFilter === 'healthy') return s.is_active && !s.drift_detected;
              if (cardFilter === 'paused') return !s.is_active;
              return true;
            }).map((s: any) => (
              <div key={s.id}>
                <button onClick={() => setExpandedId(expandedId === s.id ? null : s.id)} className="w-full text-left px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors flex items-center gap-4">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${s.drift_detected ? 'bg-red-500 animate-pulse' : s.is_active ? 'bg-emerald-500' : 'bg-slate-600'}`} />
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-5 gap-3 items-center">
                    <div>
                      <p className="font-semibold text-sm text-[var(--text-heading)]">{s.name}</p>
                      <p className="text-xs text-slate-500">{s.framework.replace(/_/g, ' ').toUpperCase()}</p>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <span className="text-xs text-slate-400 capitalize">{s.cadence}</span>
                    </div>
                    <div className="text-xs text-slate-400">
                      {s.last_run_at ? `Last: ${new Date(s.last_run_at).toLocaleString()}` : 'Never run'}
                    </div>
                    <div>
                      {s.last_pass_rate !== null && s.last_pass_rate !== undefined ? (
                        <span className={`text-xs font-bold ${s.last_pass_rate >= 90 ? 'text-emerald-400' : s.last_pass_rate >= 70 ? 'text-amber-400' : 'text-red-400'}`}>
                          {s.last_pass_rate.toFixed(1)}% pass
                        </span>
                      ) : <span className="text-xs text-slate-600">—</span>}
                    </div>
                    <div className="flex items-center gap-2">
                      {s.drift_detected && (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/20 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> DRIFT
                        </span>
                      )}
                      {s.alert_on_drift && <Bell className="w-3.5 h-3.5 text-slate-500" />}
                    </div>
                  </div>
                  {expandedId === s.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {expandedId === s.id && (
                  <div className="px-5 pb-5 bg-[var(--bg-subtle)] space-y-3">
                    <div className="flex gap-2">
                      <button onClick={() => runMut.mutate(s.id)} disabled={runMut.isPending} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/20 text-xs font-semibold text-blue-400 hover:bg-blue-600/30">
                        <Play className="w-3 h-3" /> {runMut.isPending ? 'Running…' : 'Run Now'}
                      </button>
                      <button onClick={() => toggleMut.mutate({ id: s.id, is_active: !s.is_active })} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold ${s.is_active ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'}`}>
                        {s.is_active ? <WifiOff className="w-3 h-3" /> : <Wifi className="w-3 h-3" />} {s.is_active ? 'Pause' : 'Resume'}
                      </button>
                    </div>
                    {s.drift_details && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 space-y-2">
                        <p className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> Drift Details</p>
                        {s.drift_details.degraded?.map((d: any, i: number) => (
                          <p key={i} className="text-xs text-slate-300">Pass rate dropped from <span className="text-amber-400 font-semibold">{d.previous?.toFixed(1)}%</span> to <span className="text-red-400 font-semibold">{d.current?.toFixed(1)}%</span> ({d.delta > 0 ? '+' : ''}{d.delta?.toFixed(1)}%)</p>
                        ))}
                        {s.drift_details.new_failures?.map((f: any, i: number) => (
                          <p key={i} className="text-xs text-slate-300 flex items-center gap-1.5">
                            <Shield className="w-3 h-3 text-red-400" /> <span className="text-red-400 font-semibold">{f.control_id}</span> newly failed
                          </p>
                        ))}
                      </div>
                    )}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Providers</p>
                        <p className="text-xs text-slate-300">{(s.providers || []).join(', ').toUpperCase() || 'All'}</p>
                      </div>
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Alert Channels</p>
                        <p className="text-xs text-slate-300">{(s.alert_channels || []).join(', ') || 'None'}</p>
                      </div>
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Created</p>
                        <p className="text-xs text-slate-300">{s.created_at ? new Date(s.created_at).toLocaleDateString() : '—'}</p>
                      </div>
                    </div>
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
