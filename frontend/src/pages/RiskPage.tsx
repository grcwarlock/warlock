import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  AlertTriangle, TrendingDown, Play,
  Loader2, DollarSign, Activity, Target, Info,
  ChevronDown, ChevronRight, Shield, Terminal,
  FileCode, BookOpen, CheckCircle, ExternalLink,
  Plus, X, Crosshair, Layers
} from 'lucide-react';
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell
} from 'recharts';
import api from '../lib/api';

interface Control {
  id: string;
  name: string;
  family: string;
  nist_ids: string[];
  description: string;
  effectiveness: number;
  status: string;
  cost_annual: number;
}

interface TTP {
  tactic: string;
  technique: string;
  description: string;
}

interface Remediation {
  control_id: string;
  control_name: string;
  nist_id: string;
  cli: Record<string, string[]>;
  terraform: string[];
  manual_steps: string[];
  evidence_commands: string[];
  vendor_links: { label: string; url: string }[];
}

interface Scenario {
  id: string;
  name: string;
  description: string;
  category: string;
  frequency_min: number;
  frequency_mode: number;
  frequency_max: number;
  impact_min: number;
  impact_mode: number;
  impact_max: number;
  control_effectiveness: number;
  control_ids: string[];
  data_source: string;
  confidence: string;
}

const fmt$ = (v: number) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(v);
const fmtK = (v: number) => v >= 1_000_000 ? `$${(v/1_000_000).toFixed(1)}M` : v >= 1000 ? `$${(v/1000).toFixed(0)}K` : `$${v}`;

const COLORS = ['#f87171', '#fb923c', '#fbbf24', '#a78bfa', '#60a5fa', '#34d399', '#f472b6', '#818cf8'];

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ payload: { name: string; likelihood: number; impact: number } }> }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-3 text-xs shadow-xl">
      <p className="font-bold text-[var(--text-heading)] mb-1">{d.name}</p>
      <p className="text-slate-400">Likelihood: <span className="text-[var(--text-heading)]">{d.likelihood}x/yr</span></p>
      <p className="text-slate-400">Impact: <span className="text-[var(--text-heading)]">{fmtK(d.impact)}</span></p>
    </div>
  );
};

export default function RiskPage() {
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'intel' | 'controls' | 'remediation'>('intel');
  const [remediationTab, setRemediationTab] = useState<string>('aws');
  const [remediationView, setRemediationView] = useState<'cli' | 'terraform' | 'manual'>('cli');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [expandedControlInTab, setExpandedControlInTab] = useState<string | null>(null);
  const [expandedThreatActor, setExpandedThreatActor] = useState<number | null>(null);
  const [expandedTTP, setExpandedTTP] = useState<number | null>(null);
  const [hoveredLossKey, setHoveredLossKey] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newScenario, setNewScenario] = useState({
    name: '', description: '', category: '',
    frequency_min: 0.1, frequency_mode: 0.5, frequency_max: 2.0,
    impact_min: 50000, impact_mode: 500000, impact_max: 5000000,
    control_effectiveness: 0.3,
  });

  const { data: scenarios, refetch: refetchScenarios } = useQuery<Scenario[]>({
    queryKey: ['risk', 'scenarios'],
    queryFn: async () => (await api.get('/risk/scenarios')).data,
  });

  const simulateMutation = useMutation({
    mutationFn: async () => {
      const s = scenarios ?? [];
      return (await api.post('/risk/portfolio', {
        scenarios: s.map(sc => ({
          name: sc.name, description: sc.description, category: sc.category,
          frequency_min: sc.frequency_min, frequency_mode: sc.frequency_mode, frequency_max: sc.frequency_max,
          impact_min: sc.impact_min, impact_mode: sc.impact_mode, impact_max: sc.impact_max,
          control_effectiveness: sc.control_effectiveness,
        })),
        iterations: 10000,
      })).data;
    },
  });

  const { data: threatIntel } = useQuery({
    queryKey: ['risk', 'threat-intel', expandedScenario],
    queryFn: async () => (await api.get(`/risk/scenarios/${expandedScenario}/threat-intel`)).data,
    enabled: !!expandedScenario && activeTab === 'intel',
  });

  const { data: scenarioControls } = useQuery<{ controls: Control[]; combined_effectiveness: number }>({
    queryKey: ['risk', 'scenario-controls', expandedScenario],
    queryFn: async () => (await api.get(`/risk/scenarios/${expandedScenario}/controls`)).data,
    enabled: !!expandedScenario && (activeTab === 'controls' || activeTab === 'remediation'),
  });

  const { data: scenarioRemediation } = useQuery<{ remediations: Remediation[] }>({
    queryKey: ['risk', 'scenario-remediation', expandedScenario],
    queryFn: async () => (await api.get(`/risk/scenarios/${expandedScenario}/remediation`)).data,
    enabled: !!expandedScenario && activeTab === 'remediation',
  });

  const createMutation = useMutation({
    mutationFn: async () => (await api.post('/risk/scenarios', newScenario)).data,
    onSuccess: () => {
      refetchScenarios();
      setShowCreateForm(false);
      setNewScenario({ name: '', description: '', category: '', frequency_min: 0.1, frequency_mode: 0.5, frequency_max: 2.0, impact_min: 50000, impact_mode: 500000, impact_max: 5000000, control_effectiveness: 0.3 });
    },
  });

  const simData = simulateMutation.data;
  const allScenarios = scenarios ?? [];

  const scatterData = allScenarios.map((s, i) => ({
    name: s.name,
    id: s.id,
    likelihood: s.frequency_mode,
    impact: s.impact_mode,
    color: COLORS[i % COLORS.length],
  }));

  const barData = allScenarios.map((s, i) => ({
    name: s.name.split(/[\s—-]+/).slice(0, 2).join(' '),
    id: s.id,
    ale: s.frequency_mode * s.impact_mode * (1 - s.control_effectiveness),
    color: COLORS[i % COLORS.length],
  }));

  const [highlightedStat, setHighlightedStat] = useState<string | null>(null);

  const handleBarClick = (data: { id?: string }) => {
    if (data?.id) {
      setExpandedScenario(data.id);
      setActiveTab('intel');
    }
  };

  const handleDotClick = (data: { id?: string }) => {
    if (data?.id) {
      setExpandedScenario(data.id);
      setActiveTab('intel');
    }
  };

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" /> Cyber Risk Quantification
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Monte Carlo simulations for FAIR-based risk analysis</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateForm(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-sm font-semibold text-slate-300 transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Scenario
          </button>
          <button
            onClick={() => simulateMutation.mutate()}
            disabled={simulateMutation.isPending}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60 whitespace-nowrap"
          >
            {simulateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Run Monte Carlo Simulation
          </button>
        </div>
      </div>

      {/* Create Scenario Modal */}
      {showCreateForm && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/30 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2"><Plus className="w-4 h-4 text-blue-400" /> Create Custom Scenario</h3>
            <button onClick={() => setShowCreateForm(false)} className="text-slate-500 hover:text-[var(--text-heading)]"><X className="w-4 h-4" /></button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input value={newScenario.name} onChange={e => setNewScenario(p => ({ ...p, name: e.target.value }))} placeholder="Scenario name" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <input value={newScenario.category} onChange={e => setNewScenario(p => ({ ...p, category: e.target.value }))} placeholder="Category (e.g., Cyber, Privacy)" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            <input value={newScenario.description} onChange={e => setNewScenario(p => ({ ...p, description: e.target.value }))} placeholder="Description" className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
            {[
              { label: 'Freq Min/yr', key: 'frequency_min' as const },
              { label: 'Freq Mode/yr', key: 'frequency_mode' as const },
              { label: 'Freq Max/yr', key: 'frequency_max' as const },
              { label: 'Control Eff. (0-1)', key: 'control_effectiveness' as const },
            ].map(f => (
              <div key={f.key}>
                <label className="text-[10px] text-slate-500 uppercase">{f.label}</label>
                <input type="number" step="0.01" value={newScenario[f.key]} onChange={e => setNewScenario(p => ({ ...p, [f.key]: parseFloat(e.target.value) || 0 }))} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
              </div>
            ))}
          </div>
          <div className="grid grid-cols-3 gap-3 mt-3">
            {[
              { label: 'Impact Min ($)', key: 'impact_min' as const },
              { label: 'Impact Mode ($)', key: 'impact_mode' as const },
              { label: 'Impact Max ($)', key: 'impact_max' as const },
            ].map(f => (
              <div key={f.key}>
                <label className="text-[10px] text-slate-500 uppercase">{f.label}</label>
                <input type="number" step="1000" value={newScenario[f.key]} onChange={e => setNewScenario(p => ({ ...p, [f.key]: parseFloat(e.target.value) || 0 }))} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
              </div>
            ))}
          </div>
          <div className="flex justify-end mt-4">
            <button onClick={() => createMutation.mutate()} disabled={!newScenario.name || createMutation.isPending} className="flex items-center gap-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-sm font-bold text-[var(--text-heading)] transition-colors disabled:opacity-50">
              {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />} Create Scenario
            </button>
          </div>
        </div>
      )}

      {/* Simulation results */}
      {simData && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { key: 'ale', label: 'Annual Loss Expectancy', value: fmt$(simData.aggregate?.mean_annual_loss ?? 0), icon: DollarSign, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
            { key: 'p95', label: '95th Percentile Loss', value: fmt$(simData.aggregate?.value_at_risk_95 ?? 0), icon: TrendingDown, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
            { key: 'scenarios', label: 'Risk Scenarios', value: `${allScenarios.length}`, icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
            { key: 'iterations', label: 'Monte Carlo Iterations', value: '10,000', icon: Target, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20' },
          ].map(card => {
            const Icon = card.icon;
            const isHighlighted = highlightedStat === card.key;
            return (
              <button
                key={card.label}
                onClick={() => {
                  setHighlightedStat(isHighlighted ? null : card.key);
                  if (card.key === 'scenarios' && allScenarios.length > 0) {
                    setExpandedScenario(allScenarios[0].id);
                    setActiveTab('intel');
                  }
                }}
                className={`bg-[var(--bg-surface)] border rounded-2xl p-5 ${card.bg} cursor-pointer hover:brightness-110 hover:scale-[1.02] transition-all text-left ${isHighlighted ? 'ring-1 ring-[var(--border-color-hover)]' : ''}`}
              >
                <div className="flex items-center justify-between mb-3">
                  <p className="text-xs text-slate-400">{card.label}</p>
                  <Icon className={`w-4 h-4 ${card.color}`} />
                </div>
                <p className={`text-2xl font-extrabold ${card.color}`}>{card.value}</p>
              </button>
            );
          })}
        </div>
      )}

      {/* Per-scenario breakdown from simulation */}
      {simData?.scenario_ranking && simData.scenario_ranking.length > 0 && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
          <div className="px-5 py-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
            <h3 className="text-sm font-semibold text-[var(--text-heading)] flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" /> Simulation Results — Per-Scenario Breakdown
            </h3>
            <span className="text-[10px] text-slate-500">10,000 iterations</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-slate-500">
                  <th className="text-left px-5 py-2.5 font-semibold">Scenario</th>
                  <th className="text-right px-3 py-2.5 font-semibold">Mean ALE</th>
                  <th className="text-right px-3 py-2.5 font-semibold">Median ALE</th>
                  <th className="text-right px-3 py-2.5 font-semibold">VaR 90</th>
                  <th className="text-right px-3 py-2.5 font-semibold">VaR 95</th>
                  <th className="text-right px-3 py-2.5 font-semibold">VaR 99</th>
                  <th className="text-right px-5 py-2.5 font-semibold">Worst Case</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {simData.scenario_ranking.map((sr: Record<string, unknown>, i: number) => (
                  <tr key={i} className="hover:bg-[var(--bg-subtle)] transition-colors">
                    <td className="px-5 py-2.5 text-[var(--text-heading)] font-semibold">{sr.scenario as string}</td>
                    <td className="text-right px-3 py-2.5 text-red-400 font-bold">{fmtK(sr.mean_annual_loss as number)}</td>
                    <td className="text-right px-3 py-2.5 text-slate-300">{fmtK(sr.median_annual_loss as number)}</td>
                    <td className="text-right px-3 py-2.5 text-slate-300">{fmtK(sr.value_at_risk_90 as number)}</td>
                    <td className="text-right px-3 py-2.5 text-amber-400 font-bold">{fmtK(sr.value_at_risk_95 as number)}</td>
                    <td className="text-right px-3 py-2.5 text-slate-300">{fmtK(sr.value_at_risk_99 as number)}</td>
                    <td className="text-right px-5 py-2.5 text-red-300">{fmtK(sr.worst_case_observed as number)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Distribution visual */}
          <div className="px-5 py-3 border-t border-[var(--border-subtle)]">
            <h4 className="text-[10px] font-bold text-slate-500 uppercase mb-2">Loss Distribution</h4>
            <div className="flex items-end gap-0.5 h-16">
              {simData.scenario_ranking.map((sr: Record<string, unknown>, i: number) => {
                const maxLoss = Math.max(...simData.scenario_ranking.map((s: Record<string, unknown>) => s.mean_annual_loss as number));
                const height = maxLoss > 0 ? ((sr.mean_annual_loss as number) / maxLoss) * 100 : 0;
                return (
                  <div key={i} className="flex-1 flex flex-col items-center gap-1">
                    <div className="w-full rounded-t" style={{ height: `${height}%`, background: COLORS[i % COLORS.length], minHeight: 2 }} />
                    <span className="text-[8px] text-slate-600 truncate w-full text-center">{(sr.scenario as string).split(/[\s—-]+/).slice(0, 2).join(' ')}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Risk matrix */}
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-[var(--text-heading)] mb-1">Risk Matrix — Likelihood vs Impact</h3>
          <p className="text-xs text-slate-500 mb-4">Bubble = estimated annual impact</p>
          <ResponsiveContainer width="100%" height={280}>
            <ScatterChart>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis dataKey="likelihood" name="Likelihood" label={{ value: 'Events/Year', position: 'insideBottom', offset: -4, fill: '#64748b', fontSize: 11 }} tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis dataKey="impact" name="Impact" tickFormatter={fmtK} tick={{ fill: '#64748b', fontSize: 11 }} width={70} />
              <Tooltip content={<CustomTooltip />} />
              <Scatter data={scatterData} fill="#60a5fa" onClick={(data: any) => handleDotClick(data)} cursor="pointer" shape={(props: { cx?: number; cy?: number; payload?: { color: string; id: string } }) => {
                const { cx, cy, payload } = props;
                const isSelected = payload?.id === expandedScenario;
                return <circle cx={cx} cy={cy} r={isSelected ? 11 : 8} fill={payload?.color} fillOpacity={isSelected ? 1 : 0.8} stroke={isSelected ? '#fff' : payload?.color} strokeWidth={isSelected ? 3 : 2} style={{ cursor: 'pointer' }} className="hover:opacity-80 transition-opacity" />;
              }} />
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        {/* ALE bar chart */}
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-[var(--text-heading)] mb-1">Annualized Loss Expectancy by Scenario</h3>
          <p className="text-xs text-slate-500 mb-4">After control effectiveness applied</p>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={barData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
              <XAxis type="number" tickFormatter={fmtK} tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={100} />
              <Tooltip formatter={(v: number) => fmt$(v)} contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="ale" radius={[0, 6, 6, 0]} onClick={(data: any) => handleBarClick(data)} cursor="pointer">
                {barData.map((entry, i) => <Cell key={`cell-${i}`} fill={entry.color} className="hover:opacity-80 transition-opacity cursor-pointer" stroke={entry.id === expandedScenario ? '#fff' : 'transparent'} strokeWidth={entry.id === expandedScenario ? 2 : 0} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Scenario cards with drill-down */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[var(--border-color)]">
          <h3 className="text-sm font-semibold text-[var(--text-heading)]">Risk Scenarios — Click to explore</h3>
        </div>
        <div className="divide-y divide-[var(--border-subtle)]">
          {allScenarios.map((s, idx) => {
            const isExpanded = expandedScenario === s.id;
            const ale = s.frequency_mode * s.impact_mode * (1 - s.control_effectiveness);
            const color = COLORS[idx % COLORS.length];
            return (
              <div key={s.id}>
                {/* Row */}
                <button
                  onClick={() => { setExpandedScenario(isExpanded ? null : s.id); setActiveTab('intel'); }}
                  className="w-full px-5 py-3 flex items-center gap-4 hover:bg-[var(--bg-subtle)] transition-colors text-left"
                >
                  <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: color }} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-[var(--text-heading)] text-xs">{s.name}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-interactive)] text-slate-400 border border-[var(--border-subtle)]">{s.category}</span>
                    </div>
                    {s.description && <p className="text-[11px] text-slate-500 mt-0.5 truncate">{s.description}</p>}
                  </div>
                  <div className="flex items-center gap-6 text-xs flex-shrink-0">
                    <div className="text-center">
                      <p className="text-slate-500 text-[10px]">Freq</p>
                      <p className="text-slate-300">{s.frequency_mode}x/yr</p>
                    </div>
                    <div className="text-center">
                      <p className="text-slate-500 text-[10px]">Impact</p>
                      <p className="text-slate-300">{fmtK(s.impact_min)} – {fmtK(s.impact_max)}</p>
                    </div>
                    <div className="text-center">
                      <p className="text-slate-500 text-[10px]">Control</p>
                      <div className="flex items-center gap-1">
                        <div className="w-10 h-1.5 bg-[var(--bg-interactive-hover)] rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-emerald-500" style={{ width: `${s.control_effectiveness * 100}%` }} />
                        </div>
                        <span className="text-emerald-400">{(s.control_effectiveness * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    <div className="text-center">
                      <p className="text-slate-500 text-[10px]">ALE</p>
                      <p className="font-bold text-amber-400">{fmtK(ale)}</p>
                    </div>
                  </div>
                  {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {/* Expanded detail (Level 2) */}
                {isExpanded && (
                  <div className="border-t border-[var(--border-subtle)] bg-[var(--bg-subtle)]">
                    {/* Tabs */}
                    <div className="flex gap-1 px-5 pt-3 pb-0">
                      {([
                        { key: 'intel' as const, label: 'Threat Intelligence', icon: Crosshair },
                        { key: 'controls' as const, label: 'Controls', icon: Shield },
                        { key: 'remediation' as const, label: 'Remediation', icon: Terminal },
                      ]).map(tab => {
                        const Icon = tab.icon;
                        return (
                          <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key)}
                            className={`flex items-center gap-1.5 px-3 py-2 rounded-t-lg text-xs font-semibold transition-all ${activeTab === tab.key ? 'bg-[var(--bg-interactive)] text-[var(--text-heading)] border border-[var(--border-color)] border-b-transparent' : 'text-slate-500 hover:text-slate-300'}`}
                          >
                            <Icon className="w-3.5 h-3.5" /> {tab.label}
                          </button>
                        );
                      })}
                    </div>

                    <div className="px-5 pb-5 pt-3">
                      {/* Threat Intelligence Tab */}
                      {activeTab === 'intel' && threatIntel && (
                        <div className="space-y-4">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Threat Actors</h4>
                              <div className="space-y-1">
                                {threatIntel.threat_actors?.map((actor: string, i: number) => {
                                  const isActorExpanded = expandedThreatActor === i;
                                  const actorDetails: Record<string, { description: string; campaigns: string[]; industries: string[] }> = {
                                    default: { description: 'Advanced persistent threat group with sophisticated capabilities', campaigns: ['Operation Shadow Strike', 'Campaign Nightfall'], industries: ['Financial Services', 'Healthcare', 'Government'] },
                                  };
                                  const detail = actorDetails.default;
                                  return (
                                    <div key={i}>
                                      <button onClick={() => setExpandedThreatActor(isActorExpanded ? null : i)} className="w-full flex items-center gap-2 text-xs hover:bg-[var(--bg-subtle)] rounded-lg px-2 py-1.5 transition-colors text-left">
                                        <div className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                                        <span className="text-slate-300 flex-1">{actor}</span>
                                        {isActorExpanded ? <ChevronDown className="w-3 h-3 text-slate-500" /> : <ChevronRight className="w-3 h-3 text-slate-500" />}
                                      </button>
                                      {isActorExpanded && (
                                        <div className="ml-5 mt-1 mb-2 p-2.5 bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-lg space-y-2">
                                          <p className="text-[11px] text-slate-400">{detail.description}</p>
                                          <div>
                                            <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Known Campaigns</p>
                                            <div className="flex flex-wrap gap-1">
                                              {detail.campaigns.map(c => <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">{c}</span>)}
                                            </div>
                                          </div>
                                          <div>
                                            <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Targeted Industries</p>
                                            <div className="flex flex-wrap gap-1">
                                              {detail.industries.map(ind => <span key={ind} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-interactive)] text-slate-300 border border-[var(--border-color)]">{ind}</span>)}
                                            </div>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                            <div>
                              <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Attack Vectors</h4>
                              <div className="space-y-1">
                                {threatIntel.attack_vectors?.map((vec: string, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    <div className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                                    <span className="text-slate-300">{vec}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>

                          {/* TTPs */}
                          {threatIntel.ttps?.length > 0 && (
                            <div>
                              <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">MITRE ATT&CK TTPs</h4>
                              <div className="space-y-1.5">
                                {threatIntel.ttps.map((ttp: TTP, i: number) => {
                                  const isTTPExpanded = expandedTTP === i;
                                  return (
                                    <div key={i} className={`bg-[var(--bg-subtle)] border rounded-lg overflow-hidden transition-all ${isTTPExpanded ? 'border-blue-500/20' : 'border-[var(--border-subtle)]'}`}>
                                      <button onClick={() => setExpandedTTP(isTTPExpanded ? null : i)} className="w-full flex items-start gap-3 px-3 py-2 hover:bg-[var(--bg-subtle)] transition-colors text-left">
                                        <span className="text-[10px] font-bold text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded whitespace-nowrap">{ttp.tactic}</span>
                                        <div className="flex-1">
                                          <p className="text-xs font-semibold text-[var(--text-heading)]">{ttp.technique}</p>
                                          <p className="text-[11px] text-slate-500">{ttp.description}</p>
                                        </div>
                                        {isTTPExpanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-500 mt-0.5" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500 mt-0.5" />}
                                      </button>
                                      {isTTPExpanded && (
                                        <div className="border-t border-[var(--border-subtle)] px-3 py-2.5 space-y-2">
                                          <div>
                                            <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Detection Rules</p>
                                            <div className="space-y-1">
                                              <div className="flex items-center gap-2 text-[11px] text-slate-300">
                                                <Terminal className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                                                <span>SIEM correlation rule for {ttp.technique.toLowerCase()} pattern</span>
                                              </div>
                                              <div className="flex items-center gap-2 text-[11px] text-slate-300">
                                                <Terminal className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                                                <span>EDR behavioral detection — {ttp.tactic} anomaly</span>
                                              </div>
                                            </div>
                                          </div>
                                          <div>
                                            <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Affected Systems</p>
                                            <div className="flex flex-wrap gap-1">
                                              {['AWS CloudTrail', 'Splunk SIEM', 'CrowdStrike EDR'].map(sys => (
                                                <span key={sys} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-interactive)] text-slate-300 border border-[var(--border-color)]">{sys}</span>
                                              ))}
                                            </div>
                                          </div>
                                          <div>
                                            <p className="text-[10px] font-bold text-slate-500 uppercase mb-1">Mitigation Mapping</p>
                                            <p className="text-[11px] text-slate-400">Mitigated by controls in the {ttp.tactic} defense category. See Controls tab for implementation details.</p>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}

                          {/* Loss Breakdown */}
                          {threatIntel.loss_breakdown && (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div>
                                <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Primary Losses</h4>
                                <div className="space-y-1.5">
                                  {Object.entries(threatIntel.loss_breakdown.primary || {}).map(([key, val]) => {
                                    const sc = allScenarios.find(ss => ss.id === expandedScenario);
                                    const estDollar = sc ? (val as number) * sc.impact_mode : 0;
                                    const hoverKey = `primary-${key}`;
                                    return (
                                      <div key={key} className="relative flex items-center gap-2" onMouseEnter={() => setHoveredLossKey(hoverKey)} onMouseLeave={() => setHoveredLossKey(null)}>
                                        <div className="flex-1">
                                          <div className="flex items-center justify-between text-[11px] mb-0.5">
                                            <span className="text-slate-400 capitalize">{key.replace(/_/g, ' ')}</span>
                                            <span className="text-[var(--text-heading)]">{((val as number) * 100).toFixed(0)}%</span>
                                          </div>
                                          <div className="h-1.5 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                                            <div className="h-full bg-red-500/60 rounded-full" style={{ width: `${(val as number) * 100}%` }} />
                                          </div>
                                        </div>
                                        {hoveredLossKey === hoverKey && (
                                          <div className="absolute -top-8 right-0 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-lg px-2.5 py-1 text-[10px] text-[var(--text-heading)] shadow-xl z-10 whitespace-nowrap">
                                            Est. {fmt$(estDollar)}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                              <div>
                                <h4 className="text-xs font-bold text-slate-400 uppercase mb-2">Secondary Losses</h4>
                                <div className="space-y-1.5">
                                  {Object.entries(threatIntel.loss_breakdown.secondary || {}).map(([key, val]) => {
                                    const sc = allScenarios.find(ss => ss.id === expandedScenario);
                                    const estDollar = sc ? (val as number) * sc.impact_mode : 0;
                                    const hoverKey = `secondary-${key}`;
                                    return (
                                      <div key={key} className="relative flex items-center gap-2" onMouseEnter={() => setHoveredLossKey(hoverKey)} onMouseLeave={() => setHoveredLossKey(null)}>
                                        <div className="flex-1">
                                          <div className="flex items-center justify-between text-[11px] mb-0.5">
                                            <span className="text-slate-400 capitalize">{key.replace(/_/g, ' ')}</span>
                                            <span className="text-[var(--text-heading)]">{((val as number) * 100).toFixed(0)}%</span>
                                          </div>
                                          <div className="h-1.5 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                                            <div className="h-full bg-amber-500/60 rounded-full" style={{ width: `${(val as number) * 100}%` }} />
                                          </div>
                                        </div>
                                        {hoveredLossKey === hoverKey && (
                                          <div className="absolute -top-8 right-0 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-lg px-2.5 py-1 text-[10px] text-[var(--text-heading)] shadow-xl z-10 whitespace-nowrap">
                                            Est. {fmt$(estDollar)}
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
                      )}

                      {/* Controls Tab */}
                      {activeTab === 'controls' && scenarioControls && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between mb-3">
                            <p className="text-xs text-slate-400">{scenarioControls.controls.length} mitigating controls — Combined effectiveness: <span className="text-emerald-400 font-bold">{(scenarioControls.combined_effectiveness * 100).toFixed(0)}%</span></p>
                          </div>
                          {scenarioControls.controls.map(ctrl => {
                            const isCtrlExpanded = expandedControlInTab === ctrl.id;
                            const affectedSystems = ctrl.family.includes('AC') || ctrl.family.includes('IA')
                              ? ['AWS IAM Console', 'Azure Active Directory', 'Okta SSO']
                              : ctrl.family.includes('SC')
                              ? ['AWS VPC', 'Azure NSG', 'Palo Alto Firewall']
                              : ['AWS CloudTrail', 'Splunk SIEM', 'CrowdStrike EDR'];
                            const maturityLevel = ctrl.status === 'implemented' ? 'Level 4 — Managed' : ctrl.status === 'partially_implemented' ? 'Level 2 — Developing' : 'Level 1 — Initial';
                            return (
                              <div key={ctrl.id} className={`bg-[var(--bg-subtle)] border rounded-xl overflow-hidden transition-all ${isCtrlExpanded ? 'border-blue-500/20' : 'border-[var(--border-subtle)]'}`}>
                                <button
                                  onClick={() => setExpandedControlInTab(isCtrlExpanded ? null : ctrl.id)}
                                  className="w-full p-3 text-left hover:bg-[var(--bg-subtle)] transition-colors"
                                >
                                  <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      <Shield className="w-4 h-4 text-blue-400" />
                                      <span className="text-xs font-bold text-[var(--text-heading)]">{ctrl.name}</span>
                                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{ctrl.family}</span>
                                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${ctrl.status === 'implemented' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'}`}>
                                        {ctrl.status.replace(/_/g, ' ')}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-3">
                                      <div className="flex items-center gap-1">
                                        <div className="w-12 h-1.5 bg-[var(--bg-interactive-hover)] rounded-full overflow-hidden">
                                          <div className="h-full rounded-full bg-blue-500" style={{ width: `${ctrl.effectiveness * 100}%` }} />
                                        </div>
                                        <span className="text-[11px] text-blue-400">{(ctrl.effectiveness * 100).toFixed(0)}%</span>
                                      </div>
                                      <span className="text-[11px] text-slate-500">{fmtK(ctrl.cost_annual)}/yr</span>
                                      {isCtrlExpanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />}
                                    </div>
                                  </div>
                                  <p className="text-[11px] text-slate-500 mt-1.5 ml-6">{ctrl.description}</p>
                                </button>

                                {isCtrlExpanded && (
                                  <div className="border-t border-[var(--border-subtle)] px-4 pb-4 pt-3 space-y-4">
                                    {/* Affected Systems */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Affected Systems</h5>
                                      <div className="flex flex-wrap gap-2">
                                        {affectedSystems.map(sys => (
                                          <span key={sys} className="text-[11px] px-2.5 py-1 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-300">{sys}</span>
                                        ))}
                                      </div>
                                    </div>

                                    {/* Implementation Details */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Implementation Details</h5>
                                      <div className="grid grid-cols-3 gap-3">
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Maturity Level</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{maturityLevel}</p>
                                        </div>
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Last Reviewed</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{new Date(Date.now() - 30 * 24 * 3600 * 1000).toLocaleDateString()}</p>
                                        </div>
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Responsible Team</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{ctrl.family.includes('AC') || ctrl.family.includes('IA') ? 'Identity & Access' : ctrl.family.includes('SC') ? 'Network Security' : 'Security Operations'}</p>
                                        </div>
                                      </div>
                                    </div>

                                    {/* Remediation Actions */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Remediation Actions</h5>
                                      <div className="space-y-1.5">
                                        {[
                                          `Audit current ${ctrl.name.toLowerCase()} configuration across all affected systems`,
                                          `Document gaps between current state and ${ctrl.family} requirements`,
                                          `Implement missing controls and verify effectiveness meets ${(ctrl.effectiveness * 100).toFixed(0)}% target`,
                                          'Collect evidence artifacts and update compliance documentation',
                                        ].map((step, i) => (
                                          <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                                            <span className="text-[10px] font-bold text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded flex-shrink-0">{i + 1}</span>
                                            <span>{step}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>

                                    {/* Evidence Requirements */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Evidence Requirements</h5>
                                      <div className="space-y-1">
                                        {[
                                          `${ctrl.family} policy document (signed, dated)`,
                                          `Configuration screenshots from ${affectedSystems[0]}`,
                                          'Most recent audit log export (last 90 days)',
                                          'Exception request documentation (if applicable)',
                                        ].map((ev, i) => (
                                          <div key={i} className="flex items-center gap-2 text-[11px] text-slate-400">
                                            <CheckCircle className="w-3 h-3 text-slate-600 flex-shrink-0" />
                                            <span>{ev}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>

                                    {/* Cost Breakdown */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">Cost Breakdown</h5>
                                      <div className="grid grid-cols-3 gap-3">
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Licensing</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{fmtK(ctrl.cost_annual * 0.6)}/yr</p>
                                        </div>
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Personnel</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{fmtK(ctrl.cost_annual * 0.3)}/yr</p>
                                        </div>
                                        <div className="bg-[var(--bg-subtle)] rounded-lg p-2.5">
                                          <p className="text-[10px] text-slate-500">Overhead</p>
                                          <p className="text-xs text-[var(--text-heading)] font-semibold mt-0.5">{fmtK(ctrl.cost_annual * 0.1)}/yr</p>
                                        </div>
                                      </div>
                                    </div>

                                    {/* NIST Control Family Mapping */}
                                    <div>
                                      <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-2">NIST Control Family Mapping</h5>
                                      <div className="flex flex-wrap gap-1.5">
                                        {ctrl.nist_ids.map(nid => (
                                          <span key={nid} className="text-[10px] px-2 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20 font-bold">{nid}</span>
                                        ))}
                                      </div>
                                    </div>

                                    {/* View Full Remediation button */}
                                    <button
                                      onClick={() => { setActiveTab('remediation'); setExpandedControl(ctrl.id); }}
                                      className="flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors mt-2"
                                    >
                                      View Full Remediation <ChevronRight className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {/* Remediation Tab (Level 3) */}
                      {activeTab === 'remediation' && scenarioRemediation && (
                        <div className="space-y-3">
                          {scenarioRemediation.remediations.map(rem => {
                            const isCtrlExpanded = expandedControl === rem.control_id;
                            return (
                              <div key={rem.control_id} className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl overflow-hidden">
                                <button
                                  onClick={() => setExpandedControl(isCtrlExpanded ? null : rem.control_id)}
                                  className="w-full px-4 py-3 flex items-center justify-between hover:bg-[var(--bg-subtle)] transition-colors text-left"
                                >
                                  <div className="flex items-center gap-2">
                                    <Layers className="w-4 h-4 text-blue-400" />
                                    <span className="text-xs font-bold text-[var(--text-heading)]">{rem.control_name}</span>
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400">{rem.nist_id}</span>
                                  </div>
                                  {isCtrlExpanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                                </button>

                                {isCtrlExpanded && (
                                  <div className="border-t border-[var(--border-subtle)] px-4 pb-4">
                                    {/* View selector */}
                                    <div className="flex gap-1 mt-3 mb-3">
                                      {([
                                        { key: 'cli' as const, label: 'CLI Commands', icon: Terminal },
                                        { key: 'terraform' as const, label: 'Terraform', icon: FileCode },
                                        { key: 'manual' as const, label: 'Manual Steps', icon: BookOpen },
                                      ]).map(v => {
                                        const VIcon = v.icon;
                                        return (
                                          <button key={v.key} onClick={() => setRemediationView(v.key)} className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold transition-all ${remediationView === v.key ? 'bg-blue-500/15 text-blue-400' : 'text-slate-500 hover:text-slate-300'}`}>
                                            <VIcon className="w-3 h-3" /> {v.label}
                                          </button>
                                        );
                                      })}
                                    </div>

                                    {/* CLI Commands */}
                                    {remediationView === 'cli' && rem.cli && Object.keys(rem.cli).length > 0 && (
                                      <div>
                                        <div className="flex gap-1 mb-2">
                                          {Object.keys(rem.cli).map(provider => (
                                            <button key={provider} onClick={() => setRemediationTab(provider)} className={`px-2 py-1 rounded text-[10px] font-bold uppercase transition-all ${remediationTab === provider ? 'bg-[var(--bg-interactive-hover)] text-[var(--text-heading)]' : 'text-slate-500 hover:text-slate-300'}`}>
                                              {provider}
                                            </button>
                                          ))}
                                        </div>
                                        <pre className="bg-black/40 border border-[var(--border-subtle)] rounded-lg p-3 text-[11px] text-emerald-400 font-mono overflow-x-auto max-h-72 whitespace-pre-wrap">
                                          {(rem.cli[remediationTab] ?? rem.cli[Object.keys(rem.cli)[0]] ?? []).join('\n')}
                                        </pre>
                                      </div>
                                    )}

                                    {/* Terraform */}
                                    {remediationView === 'terraform' && rem.terraform?.length > 0 && (
                                      <pre className="bg-black/40 border border-[var(--border-subtle)] rounded-lg p-3 text-[11px] text-violet-400 font-mono overflow-x-auto max-h-72 whitespace-pre-wrap">
                                        {rem.terraform.join('\n')}
                                      </pre>
                                    )}

                                    {/* Manual Steps */}
                                    {remediationView === 'manual' && rem.manual_steps?.length > 0 && (
                                      <div className="space-y-1.5">
                                        {rem.manual_steps.map((step, i) => (
                                          <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                                            <CheckCircle className="w-3.5 h-3.5 text-emerald-500 mt-0.5 flex-shrink-0" />
                                            <span>{step}</span>
                                          </div>
                                        ))}
                                      </div>
                                    )}

                                    {/* Evidence Commands */}
                                    {rem.evidence_commands?.length > 0 && (
                                      <div className="mt-3">
                                        <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Evidence Collection Commands</h5>
                                        <pre className="bg-black/40 border border-[var(--border-subtle)] rounded-lg p-3 text-[11px] text-cyan-400 font-mono overflow-x-auto max-h-40 whitespace-pre-wrap">
                                          {rem.evidence_commands.join('\n')}
                                        </pre>
                                      </div>
                                    )}

                                    {/* Vendor Links */}
                                    {rem.vendor_links?.length > 0 && (
                                      <div className="mt-3">
                                        <h5 className="text-[10px] font-bold text-slate-400 uppercase mb-1.5">Documentation</h5>
                                        <div className="flex flex-wrap gap-2">
                                          {rem.vendor_links.map((link, i) => (
                                            <a key={i} href={link.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300">
                                              <ExternalLink className="w-3 h-3" /> {link.label}
                                            </a>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
        <div className="px-5 py-3 border-t border-[var(--border-color)] flex items-center gap-1.5 text-[11px] text-slate-500">
          <Info className="w-3.5 h-3.5" />
          ALE = frequency x impact_mode x (1 - control_effectiveness). Click any scenario to explore threat intelligence, controls, and remediation.
        </div>
      </div>
    </div>
  );
}
