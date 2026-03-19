import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle, AlertTriangle, X, Key, Eye, EyeOff,
  RefreshCw, Trash2, ChevronRight, Loader2, Wifi, WifiOff,
  HelpCircle, Clock, Info
} from 'lucide-react';
import api from '../lib/api';

interface FieldDefinition {
  name: string;
  type: string;
  help: string;
  required: boolean;
}

interface ToolDef {
  id: string;
  name: string;
  category: string;
  icon: string;
  fields: string[];
  field_definitions?: FieldDefinition[];
  layer?: number;
  optional?: boolean;
}

interface Connection {
  id: string;
  name: string;
  provider: string;
  is_active: boolean;
  last_sync_at: string | null;
  last_sync_status: string;
  configured_fields: string[];
  has_credentials: boolean;
  layer?: number;
}

interface TestResult {
  status: string;
  message: string;
  latency_ms?: number;
  validation_errors?: string[];
}

interface TestHistoryEntry {
  tested_at: string;
  status: string;
  message: string;
  latency_ms: number | null;
}

const CATEGORY_ORDER = [
  'Cloud Security', 'Endpoint Security', 'Identity', 'SIEM',
  'Vulnerability', 'DevSecOps', 'Ticketing', 'Monitoring',
  'Alerting', 'Warlock', 'Evidence Management', 'Dashboard',
  'AI Reasoning', 'SIEM / APM',
];

const CATEGORY_COLORS: Record<string, string> = {
  'Cloud Security':      'from-blue-500/20 to-cyan-500/10 border-blue-500/20',
  'Endpoint Security':   'from-red-500/20 to-orange-500/10 border-red-500/20',
  'Identity':            'from-violet-500/20 to-purple-500/10 border-violet-500/20',
  'SIEM':                'from-amber-500/20 to-yellow-500/10 border-amber-500/20',
  'SIEM / APM':          'from-amber-500/20 to-yellow-500/10 border-amber-500/20',
  'Vulnerability':       'from-orange-500/20 to-red-500/10 border-orange-500/20',
  'DevSecOps':           'from-slate-500/20 to-slate-500/10 border-slate-500/20',
  'Ticketing':           'from-blue-500/20 to-indigo-500/10 border-blue-500/20',
  'Alerting':            'from-red-500/20 to-pink-500/10 border-red-500/20',
  'Warlock':        'from-emerald-500/20 to-teal-500/10 border-emerald-500/20',
  'Evidence Management': 'from-sky-500/20 to-blue-500/10 border-sky-500/20',
  'Dashboard':           'from-violet-500/20 to-indigo-500/10 border-violet-500/20',
  'AI Reasoning':        'from-amber-500/20 to-orange-500/10 border-amber-500/20',
};

function fieldLabel(field: string): string {
  return field.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function isSecret(field: string): boolean {
  return ['secret', 'token', 'password', 'key', 'json'].some(s => field.toLowerCase().includes(s));
}

function fieldInputType(fieldDef?: FieldDefinition): string {
  if (!fieldDef) return 'text';
  if (fieldDef.type === 'password') return 'password';
  if (fieldDef.type === 'url') return 'url';
  return 'text';
}

export default function ToolConfigPage() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<ToolDef | null>(null);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [showHelpField, setShowHelpField] = useState<string | null>(null);

  const { data: catalog } = useQuery<{ tools: ToolDef[] }>({
    queryKey: ['tool-catalog'],
    queryFn: async () => (await api.get('/tool-config/catalog')).data,
  });

  const { data: connections } = useQuery<Record<string, Connection>>({
    queryKey: ['tool-connections'],
    queryFn: async () => (await api.get('/tool-config/connections')).data,
  });

  const { data: testHistory } = useQuery<TestHistoryEntry[]>({
    queryKey: ['tool-test-history', selected?.id],
    queryFn: async () => (await api.get(`/tool-config/connections/${selected!.id}/history`)).data,
    enabled: !!selected,
  });

  const saveMutation = useMutation({
    mutationFn: async ({ provider, config }: { provider: string; config: Record<string, string> }) =>
      (await api.put(`/tool-config/connections/${provider}`, { config, is_active: true })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tool-connections'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (provider: string) =>
      (await api.delete(`/tool-config/connections/${provider}`)).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tool-connections'] });
      setSelected(null);
    },
  });

  const testMutation = useMutation({
    mutationFn: async (provider: string) =>
      (await api.post(`/tool-config/connections/${provider}/test`)).data,
    onSuccess: (data) => {
      setTestResult(data);
      qc.invalidateQueries({ queryKey: ['tool-test-history', selected?.id] });
    },
  });

  const tools = catalog?.tools ?? [];
  const categories = CATEGORY_ORDER.filter(c => tools.some(t => t.category === c));

  const filtered = tools.filter(t =>
    (!activeCategory || t.category === activeCategory) &&
    (!searchTerm || t.name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const openConfig = (tool: ToolDef) => {
    setSelected(tool);
    setFormValues({});
    setTestResult(null);
    setShowSecrets({});
    setShowHelpField(null);
  };

  const handleSave = async () => {
    if (!selected) return;
    await saveMutation.mutateAsync({ provider: selected.id, config: formValues });
    setSelected(null);
  };

  // Client-side pre-validation
  const validateBeforeTest = (): string[] => {
    if (!selected) return [];
    const errors: string[] = [];
    const fieldDefs = selected.field_definitions ?? [];

    for (const field of selected.fields) {
      const val = formValues[field] ?? '';
      const def = fieldDefs.find(f => f.name === field);

      if (def?.required && !val) {
        errors.push(`${fieldLabel(field)} is required`);
        continue;
      }

      if (def?.type === 'url' && val && !val.startsWith('http://') && !val.startsWith('https://')) {
        errors.push(`${fieldLabel(field)} must be a valid URL`);
      }
    }
    return errors;
  };

  const handleTest = () => {
    if (!selected) return;
    const clientErrors = validateBeforeTest();
    if (clientErrors.length > 0) {
      setTestResult({
        status: 'error',
        message: 'Client-side validation failed',
        validation_errors: clientErrors,
      });
      return;
    }
    testMutation.mutate(selected.id);
  };

  return (
    <div className="space-y-6 text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-heading)]">Tool Integrations</h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Connect your security tools via API to enable automated evidence collection and compliance monitoring.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-medium">
            {Object.values(connections ?? {}).filter(c => c.has_credentials).length} connected
          </span>
          <span className="px-2.5 py-1 rounded-full bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 font-medium">
            {tools.length} available
          </span>
        </div>
      </div>

      {/* Search + Category filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          placeholder="Search integrations..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="flex-1 bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30"
        />
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setActiveCategory(null)}
            className={`px-3 py-2 rounded-lg text-xs font-medium transition-all ${
              !activeCategory ? 'bg-blue-600/20 border border-blue-500/30 text-blue-400' : 'bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive-hover)]'
            }`}
          >
            All
          </button>
          {categories.slice(0, 6).map(c => (
            <button
              key={c}
              onClick={() => setActiveCategory(activeCategory === c ? null : c)}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${
                activeCategory === c ? 'bg-blue-600/20 border border-blue-500/30 text-blue-400' : 'bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive-hover)]'
              }`}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      {/* Tool grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filtered.map(tool => {
          const conn = connections?.[tool.id];
          const isConnected = conn?.has_credentials;
          const syncStatus = conn?.last_sync_status;
          const catColors = CATEGORY_COLORS[tool.category] ?? 'from-slate-500/20 to-slate-500/10 border-slate-500/20';

          return (
            <button
              key={tool.id}
              onClick={() => openConfig(tool)}
              className={`relative text-left bg-gradient-to-br ${catColors} border rounded-xl p-4 hover:scale-[1.02] transition-all group`}
            >
              {isConnected && (
                <div className="absolute top-3 right-3">
                  <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                    Connected
                  </span>
                </div>
              )}

              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl">{tool.icon ?? '\uD83D\uDD0C'}</span>
                {tool.optional && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 font-bold">
                    OPTIONAL
                  </span>
                )}
              </div>
              <h3 className="font-semibold text-[var(--text-heading)] text-sm leading-tight mb-1">{tool.name}</h3>
              <p className="text-[10px] text-slate-500 mb-3">
                {tool.category}{tool.layer ? ` \u00B7 Layer ${tool.layer}` : ''}
              </p>

              <div className="flex items-center justify-between">
                <div className="flex gap-1 flex-wrap">
                  {tool.fields.slice(0, 2).map(f => (
                    <span key={f} className="text-[9px] px-1.5 py-0.5 bg-[var(--bg-interactive)] rounded text-slate-500">
                      {fieldLabel(f).split(' ')[0]}
                    </span>
                  ))}
                  {tool.fields.length > 2 && (
                    <span className="text-[9px] px-1.5 py-0.5 bg-[var(--bg-interactive)] rounded text-slate-500">+{tool.fields.length - 2}</span>
                  )}
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 transition-colors" />
              </div>

              {isConnected && syncStatus === 'error' && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-amber-400">
                  <AlertTriangle className="w-3 h-3" /> Sync error
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Configuration slide-over */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setSelected(null)} />
          <div className="relative ml-auto w-full max-w-md bg-[var(--bg-surface)] border-l border-[var(--border-color)] flex flex-col h-full overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)] bg-gradient-to-r from-blue-500/5 to-violet-500/5">
              <div className="flex items-center gap-3">
                <div className="text-2xl">{selected.icon}</div>
                <div>
                  <h3 className="font-bold text-[var(--text-heading)]">{selected.name}</h3>
                  <p className="text-xs text-slate-400">{selected.category}{selected.layer ? ` \u00B7 Layer ${selected.layer}` : ''}</p>
                </div>
              </div>
              <button onClick={() => setSelected(null)} className="p-2 hover:bg-[var(--bg-interactive)] rounded-lg text-slate-400 hover:text-[var(--text-heading)] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-5">
              {/* Existing connection status */}
              {connections?.[selected.id]?.has_credentials && (
                <div className="flex items-center justify-between bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                    <Wifi className="w-4 h-4" />
                    Connected
                  </div>
                  <button
                    onClick={() => {
                      if (confirm(`Disconnect ${selected.name}?`)) deleteMutation.mutate(selected.id);
                    }}
                    className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Disconnect
                  </button>
                </div>
              )}

              {/* Credential fields */}
              <div className="space-y-4">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Key className="w-3.5 h-3.5" /> API Credentials
                </h4>
                {selected.fields.map(field => {
                  const secret = isSecret(field);
                  const shown = showSecrets[field];
                  const fieldDef = selected.field_definitions?.find(f => f.name === field);
                  const hasHelp = !!fieldDef?.help;
                  const inputType = secret && !shown ? 'password' : fieldInputType(fieldDef);

                  return (
                    <div key={field}>
                      <div className="flex items-center justify-between mb-1.5">
                        <label className="text-xs font-medium text-slate-300">
                          {fieldLabel(field)}
                          {secret && <span className="ml-1.5 text-[10px] text-slate-600">(encrypted at rest)</span>}
                        </label>
                        {hasHelp && (
                          <button
                            type="button"
                            onClick={() => setShowHelpField(showHelpField === field ? null : field)}
                            className="text-slate-500 hover:text-blue-400 transition-colors"
                            title="Show help"
                          >
                            <HelpCircle className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      {showHelpField === field && fieldDef?.help && (
                        <div className="bg-blue-500/5 border border-blue-500/15 rounded-lg px-3 py-2 mb-2">
                          <p className="text-[11px] text-blue-300 leading-relaxed flex items-start gap-2">
                            <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-blue-400" />
                            {fieldDef.help}
                          </p>
                        </div>
                      )}

                      {fieldDef?.type === 'select' ? (
                        <select
                          value={formValues[field] ?? ''}
                          onChange={e => setFormValues(p => ({ ...p, [field]: e.target.value }))}
                          className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30"
                        >
                          <option value="" className="bg-[var(--bg-surface)]">Select {fieldLabel(field).toLowerCase()}</option>
                          {field === 'region' && ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'].map(r =>
                            <option key={r} value={r} className="bg-[var(--bg-surface)]">{r}</option>
                          )}
                          {field === 'model' && ['gpt-4o', 'gpt-4o-mini', 'claude-sonnet-4-20250514', 'claude-3-5-haiku-20241022', 'gemini-1.5-pro', 'llama3.1'].map(m =>
                            <option key={m} value={m} className="bg-[var(--bg-surface)]">{m}</option>
                          )}
                        </select>
                      ) : (
                        <div className="relative">
                          <input
                            type={inputType === 'password' ? 'password' : 'text'}
                            value={formValues[field] ?? ''}
                            onChange={e => setFormValues(p => ({ ...p, [field]: e.target.value }))}
                            placeholder={secret ? '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022' : `Enter ${fieldLabel(field).toLowerCase()}`}
                            className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30 pr-10"
                          />
                          {secret && (
                            <button
                              type="button"
                              onClick={() => setShowSecrets(p => ({ ...p, [field]: !shown }))}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                            >
                              {shown ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Test result */}
              {testResult && (
                <div className={`p-4 rounded-xl border ${
                  testResult.status === 'success'
                    ? 'bg-emerald-500/10 border-emerald-500/20'
                    : 'bg-red-500/10 border-red-500/20'
                }`}>
                  <div className="flex items-start gap-3">
                    {testResult.status === 'success'
                      ? <CheckCircle className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                      : <WifiOff className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    }
                    <div className="flex-1">
                      <p className={`text-sm font-medium ${testResult.status === 'success' ? 'text-emerald-300' : 'text-red-300'}`}>
                        {testResult.status === 'success' ? 'Connection successful' : 'Connection failed'}
                      </p>
                      <p className="text-xs text-slate-400 mt-0.5">{testResult.message}</p>
                      {testResult.latency_ms && (
                        <p className="text-xs text-emerald-500 mt-1">Response time: {testResult.latency_ms}ms</p>
                      )}
                      {testResult.validation_errors && testResult.validation_errors.length > 0 && (
                        <ul className="mt-2 space-y-1">
                          {testResult.validation_errors.map((err, i) => (
                            <li key={i} className="text-[11px] text-red-400 flex items-start gap-1.5">
                              <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                              {err}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Test history */}
              {testHistory && testHistory.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2 mb-3">
                    <Clock className="w-3.5 h-3.5" /> Connection Test History
                  </h4>
                  <div className="space-y-2">
                    {testHistory.map((entry, i) => (
                      <div key={i} className="flex items-center justify-between bg-[var(--bg-subtle)] rounded-lg px-3 py-2">
                        <div className="flex items-center gap-2">
                          {entry.status === 'success'
                            ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                            : <WifiOff className="w-3.5 h-3.5 text-red-400" />
                          }
                          <span className="text-[10px] text-slate-400">{new Date(entry.tested_at).toLocaleString()}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {entry.latency_ms && <span className="text-[10px] text-slate-500">{entry.latency_ms}ms</span>}
                          <span className={`text-[10px] font-bold ${entry.status === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                            {entry.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Help text */}
              <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-4">
                <p className="text-xs text-slate-500 leading-relaxed">
                  Credentials are stored encrypted and used only for automated evidence collection during compliance assessments.
                  In demo mode, connections are simulated — no real API calls are made.
                </p>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-[var(--border-color)] flex gap-3">
              <button
                onClick={handleTest}
                disabled={testMutation.isPending}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm font-medium text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors disabled:opacity-50"
              >
                {testMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                Test
              </button>
              <button
                onClick={handleSave}
                disabled={saveMutation.isPending || Object.keys(formValues).length === 0}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-[var(--text-heading)] transition-all disabled:opacity-40 shadow-lg shadow-blue-500/20"
              >
                {saveMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                Save & Connect
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
