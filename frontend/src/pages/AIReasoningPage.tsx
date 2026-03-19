import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Brain, Sparkles, FileText, Search, ClipboardList, GitBranch,
  TrendingUp, MessageSquare, Play, Loader2, Check, X,
  Clock, Zap, ChevronRight, AlertTriangle, Settings, Copy
} from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '../lib/api';

const TASK_ICONS: Record<string, any> = {
  control_narrative: FileText,
  gap_analysis: Search,
  poam_narrative: ClipboardList,
  evidence_mapping: GitBranch,
  risk_narrative: TrendingUp,
  questionnaire_answer: MessageSquare,
};

const TASK_COLORS: Record<string, string> = {
  control_narrative:    'from-blue-500/20 to-cyan-500/10 border-blue-500/20',
  gap_analysis:         'from-violet-500/20 to-purple-500/10 border-violet-500/20',
  poam_narrative:       'from-orange-500/20 to-red-500/10 border-orange-500/20',
  evidence_mapping:     'from-emerald-500/20 to-teal-500/10 border-emerald-500/20',
  risk_narrative:       'from-amber-500/20 to-yellow-500/10 border-amber-500/20',
  questionnaire_answer: 'from-pink-500/20 to-rose-500/10 border-pink-500/20',
};

const TASK_CONTEXT_FIELDS: Record<string, { key: string; label: string; placeholder: string; multiline?: boolean }[]> = {
  control_narrative: [
    { key: 'control_id', label: 'Control ID', placeholder: 'e.g., AC-2' },
    { key: 'control_name', label: 'Control Name', placeholder: 'e.g., Account Management' },
    { key: 'control_description', label: 'Control Description', placeholder: 'Describe the control requirement…', multiline: true },
    { key: 'evidence', label: 'Evidence (comma-separated)', placeholder: 'e.g., okta_mfa_report, access_review_Q1' },
  ],
  gap_analysis: [
    { key: 'findings_summary', label: 'Assessment Findings', placeholder: 'Describe failed controls and findings…', multiline: true },
    { key: 'severity_breakdown', label: 'Severity Breakdown', placeholder: 'e.g., 3 critical, 7 high, 12 medium' },
  ],
  poam_narrative: [
    { key: 'control_id', label: 'Control ID', placeholder: 'e.g., AC-12' },
    { key: 'finding', label: 'Finding Description', placeholder: 'Describe what was found…', multiline: true },
    { key: 'severity', label: 'Severity', placeholder: 'critical, high, medium, or low' },
  ],
  evidence_mapping: [
    { key: 'evidence_description', label: 'Evidence Artifacts', placeholder: 'Describe the evidence items to map…', multiline: true },
    { key: 'target_framework', label: 'Target Framework', placeholder: 'e.g., nist_800_53' },
  ],
  risk_narrative: [
    { key: 'mean_ale', label: 'Mean Annual Loss ($)', placeholder: 'e.g., 1870000' },
    { key: 'var_95', label: 'VaR 95th Percentile ($)', placeholder: 'e.g., 4200000' },
    { key: 'top_scenarios', label: 'Top Scenarios', placeholder: 'e.g., Ransomware, Data Breach' },
  ],
  questionnaire_answer: [
    { key: 'question', label: 'Question', placeholder: 'Enter the security questionnaire question…', multiline: true },
    { key: 'category', label: 'Category', placeholder: 'e.g., Data Protection, Access Control' },
  ],
};

const FRAMEWORKS = [
  { id: 'nist_800_53', name: 'NIST 800-53' },
  { id: 'soc2', name: 'SOC 2' },
  { id: 'iso_27001', name: 'ISO 27001' },
  { id: 'hipaa', name: 'HIPAA' },
  { id: 'cmmc_l2', name: 'CMMC Level 2' },
];

export default function AIReasoningPage() {
  const qc = useQueryClient();
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [contextForm, setContextForm] = useState<Record<string, string>>({});
  const [framework, setFramework] = useState('nist_800_53');
  const [activeResult, setActiveResult] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  const { data: tasksMeta } = useQuery({
    queryKey: ['ai-reasoning', 'tasks'],
    queryFn: async () => (await api.get('/ai-reasoning/tasks')).data,
  });

  const { data: aiSettings } = useQuery({
    queryKey: ['settings', 'ai-reasoning'],
    queryFn: async () => (await api.get('/ai-reasoning/settings')).data,
  });

  const { data: history } = useQuery({
    queryKey: ['ai-reasoning', 'history'],
    queryFn: async () => (await api.get('/ai-reasoning/history')).data,
    refetchInterval: 10000,
  });

  const analyzeMutation = useMutation({
    mutationFn: async (body: { task: string; context: Record<string, any>; framework: string }) =>
      (await api.post('/ai-reasoning/analyze', body)).data,
    onSuccess: (data) => {
      setActiveResult(data);
      qc.invalidateQueries({ queryKey: ['ai-reasoning', 'history'] });
    },
  });

  const isEnabled = aiSettings?.enabled;
  const tasks = tasksMeta?.tasks ?? {};

  const handleRun = () => {
    if (!selectedTask) return;
    // Transform comma-separated evidence into array
    const context: Record<string, any> = { ...contextForm };
    if (context.evidence) {
      context.evidence = context.evidence.split(',').map((s: string) => s.trim()).filter(Boolean);
    }
    analyzeMutation.mutate({ task: selectedTask, context, framework });
  };

  const copyResult = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 text-[var(--text-heading)] page-enter">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500/20 to-orange-500/20 border border-amber-500/20 flex items-center justify-center">
            <Brain className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-[var(--text-heading)] flex items-center gap-2">
              AI Reasoning
              {tasksMeta?.demo_mode && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-bold">
                  DEMO MODE
                </span>
              )}
            </h2>
            <p className="text-sm text-slate-400 mt-0.5">
              LLM-powered compliance analysis — {isEnabled ? 'active' : 'disabled'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {isEnabled ? (
            <span className="px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 font-medium flex items-center gap-1.5">
              <Sparkles className="w-3 h-3" /> {aiSettings?.provider ?? 'openai'} · {aiSettings?.model || 'default'}
            </span>
          ) : (
            <Link
              to="/settings"
              className="px-3 py-1.5 rounded-full bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 hover:text-[var(--text-heading)] hover:bg-[var(--bg-interactive-hover)] font-medium flex items-center gap-1.5 transition-colors"
            >
              <Settings className="w-3 h-3" /> Enable in Settings
            </Link>
          )}
        </div>
      </div>

      {/* Disabled state */}
      {!isEnabled && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-8 text-center">
          <Brain className="w-12 h-12 text-slate-700 mx-auto mb-4" />
          <h3 className="text-lg font-bold text-[var(--text-heading)] mb-2">AI Reasoning is Disabled</h3>
          <p className="text-sm text-slate-500 max-w-md mx-auto mb-5">
            Enable the AI Reasoning Layer in Settings to unlock LLM-powered compliance analysis including
            control narrative generation, gap analysis, POA&M drafting, and more.
          </p>
          <Link
            to="/settings"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-sm font-bold transition-all shadow-lg shadow-amber-500/20"
          >
            <Settings className="w-4 h-4" /> Go to Settings
          </Link>
        </div>
      )}

      {/* Main content — only when enabled */}
      {isEnabled && (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Left: Task selection + form */}
          <div className="xl:col-span-2 space-y-5">
            {/* Task cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {Object.entries(tasks).map(([taskId, meta]: [string, any]) => {
                const Icon = TASK_ICONS[taskId] ?? Sparkles;
                const colors = TASK_COLORS[taskId] ?? 'from-slate-500/20 to-slate-500/10 border-slate-500/20';
                const isSelected = selectedTask === taskId;
                return (
                  <button
                    key={taskId}
                    onClick={() => {
                      setSelectedTask(taskId);
                      setContextForm({});
                      setActiveResult(null);
                    }}
                    className={`relative text-left bg-gradient-to-br ${colors} border rounded-xl p-4 transition-all group ${
                      isSelected ? 'ring-2 ring-amber-500/40 scale-[1.02]' : 'hover:scale-[1.02]'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="w-5 h-5 text-[var(--text-heading)]/80" />
                      {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />}
                    </div>
                    <h3 className="font-bold text-sm text-[var(--text-heading)] leading-tight">{meta.name}</h3>
                    <p className="text-[10px] text-slate-400 mt-1 line-clamp-2">{meta.description}</p>
                  </button>
                );
              })}
            </div>

            {/* Context form */}
            {selectedTask && (
              <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
                    <Zap className="w-4 h-4 text-amber-400" />
                    {tasks[selectedTask]?.name}
                  </h3>
                  <button
                    onClick={() => { setSelectedTask(null); setActiveResult(null); }}
                    className="p-1 text-slate-500 hover:text-[var(--text-heading)] rounded-lg hover:bg-[var(--bg-interactive)] transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* Framework selector */}
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1.5">Target Framework</label>
                  <div className="flex gap-2 flex-wrap">
                    {FRAMEWORKS.map(fw => (
                      <button
                        key={fw.id}
                        onClick={() => setFramework(fw.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                          framework === fw.id
                            ? 'bg-amber-500/15 border border-amber-500/25 text-amber-300'
                            : 'bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive-hover)]'
                        }`}
                      >
                        {fw.name}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Dynamic context fields */}
                {(TASK_CONTEXT_FIELDS[selectedTask] ?? []).map(field => (
                  <div key={field.key}>
                    <label className="block text-xs font-semibold text-slate-400 mb-1.5">{field.label}</label>
                    {field.multiline ? (
                      <textarea
                        value={contextForm[field.key] ?? ''}
                        onChange={e => setContextForm(p => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        rows={3}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/30 resize-none"
                      />
                    ) : (
                      <input
                        type="text"
                        value={contextForm[field.key] ?? ''}
                        onChange={e => setContextForm(p => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-amber-500/50 focus:ring-1 focus:ring-amber-500/30"
                      />
                    )}
                  </div>
                ))}

                {/* Run button */}
                <button
                  onClick={handleRun}
                  disabled={analyzeMutation.isPending}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-sm font-bold transition-all shadow-lg shadow-amber-500/20 disabled:opacity-50"
                >
                  {analyzeMutation.isPending ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" /> Reasoning…
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" /> Run Analysis
                    </>
                  )}
                </button>

                {/* Error */}
                {analyzeMutation.isError && (
                  <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                    <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-red-300">Analysis failed</p>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {(analyzeMutation.error as any)?.response?.data?.detail ?? 'An error occurred'}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Result display */}
            {activeResult && (
              <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
                    <Check className="w-4 h-4 text-emerald-400" /> Result
                  </h3>
                  <div className="flex items-center gap-2 text-[10px] text-slate-500">
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {activeResult.latency_ms}ms</span>
                    <span>{activeResult.tokens_used} tokens</span>
                    <span className="text-slate-600">·</span>
                    <span className="text-amber-400">{activeResult.provider}/{activeResult.model}</span>
                  </div>
                </div>

                {/* Structured output */}
                {activeResult.structured && Object.keys(activeResult.structured).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(activeResult.structured).map(([key, value]: [string, any]) => (
                      <div key={key} className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-4">
                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                          {key.replace(/_/g, ' ')}
                        </h4>
                        {typeof value === 'string' ? (
                          <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-wrap">{value}</p>
                        ) : Array.isArray(value) ? (
                          <ul className="space-y-1.5">
                            {value.map((item, i) => (
                              <li key={i} className="text-sm text-slate-300">
                                {typeof item === 'string' ? (
                                  <span className="flex items-start gap-2">
                                    <ChevronRight className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-1" />
                                    {item}
                                  </span>
                                ) : (
                                  <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-lg p-3">
                                    {Object.entries(item).map(([k, v]) => (
                                      <div key={k} className="flex gap-2 text-xs mb-1 last:mb-0">
                                        <span className="text-slate-500 font-medium min-w-[100px]">{k.replace(/_/g, ' ')}:</span>
                                        <span className="text-slate-300">{String(v)}</span>
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <pre className="text-xs text-slate-300 bg-black/20 rounded-lg p-3 overflow-x-auto">
                            {JSON.stringify(value, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <pre className="text-sm text-slate-300 bg-black/20 rounded-xl p-4 overflow-x-auto whitespace-pre-wrap">
                    {activeResult.content}
                  </pre>
                )}

                {/* Copy raw JSON */}
                <button
                  onClick={() => copyResult(activeResult.content)}
                  className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy raw JSON'}
                </button>
              </div>
            )}
          </div>

          {/* Right: History */}
          <div className="space-y-4">
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
              <h3 className="text-sm font-bold text-[var(--text-heading)] mb-4 flex items-center gap-2">
                <Clock className="w-4 h-4 text-slate-400" /> Recent Analysis
              </h3>
              {(history?.results ?? []).length === 0 ? (
                <div className="py-8 text-center">
                  <Brain className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500">No analysis history yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {(history?.results ?? []).slice(0, 15).map((entry: any) => {
                    const Icon = TASK_ICONS[entry.task] ?? Sparkles;
                    return (
                      <button
                        key={entry.id}
                        onClick={() => setActiveResult(entry)}
                        className={`w-full text-left p-3 rounded-xl border transition-all hover:bg-[var(--bg-subtle)] ${
                          activeResult?.id === entry.id
                            ? 'bg-amber-500/5 border-amber-500/15'
                            : 'bg-[var(--bg-subtle)] border-[var(--border-subtle)]'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <Icon className="w-3.5 h-3.5 text-slate-400" />
                          <span className="text-xs font-bold text-[var(--text-heading)]">{entry.task.replace(/_/g, ' ')}</span>
                          {!entry.success && <AlertTriangle className="w-3 h-3 text-red-400" />}
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-slate-500">
                          <span>{entry.provider}/{entry.model}</span>
                          <span>·</span>
                          <span>{entry.latency_ms}ms</span>
                          <span>·</span>
                          <span>{entry.tokens_used} tok</span>
                        </div>
                        <p className="text-[10px] text-slate-600 mt-1">
                          {new Date(entry.timestamp).toLocaleString()}
                        </p>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Quick stats */}
            <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
              <h3 className="text-sm font-bold text-[var(--text-heading)] mb-3">Session Stats</h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3 text-center">
                  <p className="text-lg font-bold text-amber-400">{history?.total ?? 0}</p>
                  <p className="text-[10px] text-slate-500">Total Runs</p>
                </div>
                <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3 text-center">
                  <p className="text-lg font-bold text-emerald-400">
                    {(history?.results ?? []).filter((r: any) => r.success).length}
                  </p>
                  <p className="text-[10px] text-slate-500">Successful</p>
                </div>
                <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3 text-center">
                  <p className="text-lg font-bold text-blue-400">
                    {(history?.results ?? []).reduce((sum: number, r: any) => sum + (r.tokens_used ?? 0), 0).toLocaleString()}
                  </p>
                  <p className="text-[10px] text-slate-500">Tokens Used</p>
                </div>
                <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-3 text-center">
                  <p className="text-lg font-bold text-violet-400">
                    {(history?.results ?? []).length > 0
                      ? Math.round((history?.results ?? []).reduce((sum: number, r: any) => sum + (r.latency_ms ?? 0), 0) / (history?.results ?? []).length)
                      : 0
                    }ms
                  </p>
                  <p className="text-[10px] text-slate-500">Avg Latency</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
