import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings, Building, Bell, Key,
  Plus, Trash2, Copy, Check, Eye, EyeOff,
  Save, Activity, Loader2, Brain, Wifi, WifiOff,
  AlertTriangle, Sparkles
} from 'lucide-react';
import api from '../lib/api';

const TABS = [
  { id: 'org',           label: 'Organization',  icon: Building },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'ai-reasoning',  label: 'AI Reasoning',  icon: Brain },
  { id: 'api-keys',      label: 'API Keys',       icon: Key },
  { id: 'audit',         label: 'Audit Log',      icon: Activity },
] as const;
type TabId = typeof TABS[number]['id'];

const AI_PROVIDERS = [
  { id: 'openai',    name: 'OpenAI',           models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o3-mini'] },
  { id: 'anthropic', name: 'Anthropic',        models: ['claude-opus-4-20250514', 'claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001'] },
  { id: 'gemini',    name: 'Google Gemini',    models: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.0-flash'] },
  { id: 'ollama',    name: 'Ollama (Local)',   models: ['llama3.1:70b', 'llama3.1:8b', 'mistral:7b', 'mixtral:8x7b', 'qwen2.5:32b'] },
];

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!value)}
      className={`relative w-11 h-6 rounded-full transition-colors duration-200 flex-shrink-0 focus:outline-none ${value ? 'bg-blue-600' : 'bg-[var(--bg-interactive-hover)]'}`}
      role="switch"
      aria-checked={value}
    >
      <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200 ${value ? 'translate-x-5' : ''}`} />
    </button>
  );
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('org');
  const [copied, setCopied] = useState('');
  const [showKey, setShowKey] = useState<Record<string, boolean>>({});
  const [showAiKey, setShowAiKey] = useState(false);
  const queryClient = useQueryClient();

  const { data: orgSettings, isLoading: orgLoading } = useQuery({
    queryKey: ['settings', 'org'],
    queryFn: async () => (await api.get('/settings/org')).data,
  });

  const { data: notifSettings } = useQuery({
    queryKey: ['settings', 'notifications'],
    queryFn: async () => (await api.get('/settings/notifications')).data,
  });

  const { data: apiKeys } = useQuery({
    queryKey: ['settings', 'api-keys'],
    queryFn: async () => (await api.get('/settings/api-keys')).data,
  });

  const { data: auditLog } = useQuery({
    queryKey: ['settings', 'audit-log'],
    queryFn: async () => (await api.get('/settings/audit-log')).data,
  });

  const { data: aiSettings, isLoading: aiLoading } = useQuery({
    queryKey: ['settings', 'ai-reasoning'],
    queryFn: async () => (await api.get('/ai-reasoning/settings')).data,
  });

  const updateOrgMutation = useMutation({
    mutationFn: async (d: Record<string, unknown>) => (await api.put('/settings/org', d)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'org'] }),
  });

  const updateNotifMutation = useMutation({
    mutationFn: async (d: Record<string, unknown>) => (await api.put('/settings/notifications', d)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'notifications'] }),
  });

  const updateAiMutation = useMutation({
    mutationFn: async (d: Record<string, unknown>) => (await api.put('/ai-reasoning/settings', d)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'ai-reasoning'] });
      queryClient.invalidateQueries({ queryKey: ['settings', 'org'] });
    },
  });

  const testAiMutation = useMutation({
    mutationFn: async () => (await api.post('/ai-reasoning/test-connection')).data,
  });

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(''), 2000);
  };

  const [orgForm, setOrgForm] = useState<Record<string, any>>({});
  const [aiForm, setAiForm] = useState<Record<string, any>>({});

  const currentAiProvider = AI_PROVIDERS.find(p => p.id === (aiForm.provider ?? aiSettings?.provider ?? 'openai'));

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
          <Settings className="w-5 h-5 text-slate-400" /> Settings
        </h2>
        <p className="text-slate-400 text-sm mt-0.5">Organization configuration and platform preferences</p>
      </div>

      <div className="flex flex-col md:flex-row gap-5">
        {/* Sidebar nav */}
        <div className="md:w-52 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-2 h-fit">
          {TABS.map(tab => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                  activeTab === tab.id ? 'bg-blue-500/15 text-blue-400 border border-blue-500/20' : 'text-slate-400 hover:text-[var(--text-heading)] hover:bg-[var(--bg-interactive)]'
                }`}
              >
                <Icon className="w-4 h-4" /> {tab.label}
                {tab.id === 'ai-reasoning' && aiSettings?.enabled && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                )}
              </button>
            );
          })}
        </div>

        {/* Tab content */}
        <div className="flex-1 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-6">

          {/* Organization */}
          {activeTab === 'org' && (
            <div className="space-y-5">
              <h3 className="text-base font-bold text-[var(--text-heading)]">Organization Settings</h3>
              {orgLoading ? (
                <div className="flex items-center gap-2 text-slate-500 py-8">
                  <Loader2 className="w-5 h-5 animate-spin" /> Loading…
                </div>
              ) : (
                <>
                  {[
                    { key: 'company_name',    label: 'Company Name',    type: 'text', placeholder: 'Warlock Compliance' },
                    { key: 'industry',        label: 'Industry',        type: 'text', placeholder: 'Technology' },
                    { key: 'contact_email',   label: 'Security Contact Email', type: 'email', placeholder: 'security@example.com' },
                    { key: 'compliance_scope',label: 'Compliance Scope',type: 'text', placeholder: 'Cloud infrastructure, SaaS products' },
                  ].map(field => (
                    <div key={field.key}>
                      <label className="block text-sm font-semibold text-slate-300 mb-1.5">{field.label}</label>
                      <input
                        type={field.type}
                        defaultValue={orgSettings?.[field.key] ?? ''}
                        onChange={e => setOrgForm(p => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
                      />
                    </div>
                  ))}
                  <button
                    onClick={() => updateOrgMutation.mutate({ ...orgSettings, ...orgForm })}
                    disabled={updateOrgMutation.isPending}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold transition-all shadow-lg shadow-blue-500/20 disabled:opacity-60"
                  >
                    {updateOrgMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                    Save Changes
                  </button>
                  {updateOrgMutation.isSuccess && (
                    <div className="flex items-center gap-2 text-emerald-400 text-sm">
                      <Check className="w-4 h-4" /> Saved successfully
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* Notifications */}
          {activeTab === 'notifications' && (
            <div className="space-y-5">
              <h3 className="text-base font-bold text-[var(--text-heading)]">Notification Preferences</h3>
              <div className="space-y-3">
                {[
                  { key: 'email_on_assessment_complete',  label: 'Email on assessment completion',  desc: 'Receive a summary email when a compliance run finishes' },
                  { key: 'email_on_critical_finding',     label: 'Email on critical findings',      desc: 'Immediate alert when a critical-severity control fails' },
                  { key: 'email_on_policy_violation',     label: 'Email on policy violations',      desc: 'Notify when a policy violation is detected' },
                  { key: 'slack_on_assessment_complete',  label: 'Slack on assessment completion',  desc: 'Post results to your configured Slack channel' },
                  { key: 'slack_on_critical_finding',     label: 'Slack on critical findings',      desc: 'Real-time Slack alert for critical-severity issues' },
                  { key: 'weekly_summary',                label: 'Weekly compliance digest',        desc: 'Monday summary email with compliance trend data' },
                ].map(n => (
                  <div key={n.key} className="flex items-center justify-between py-3 px-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-subtle)]">
                    <div>
                      <p className="text-sm font-semibold text-[var(--text-heading)]">{n.label}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{n.desc}</p>
                    </div>
                    <Toggle
                      value={notifSettings?.[n.key] ?? false}
                      onChange={v => updateNotifMutation.mutate({ ...notifSettings, [n.key]: v })}
                    />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI Reasoning */}
          {activeTab === 'ai-reasoning' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-[var(--text-heading)] flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-amber-400" /> AI Reasoning Layer
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">Optional LLM-powered compliance analysis</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
                    aiSettings?.enabled
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                      : 'bg-[var(--bg-interactive)] border-[var(--border-color)] text-slate-500'
                  }`}>
                    {aiSettings?.enabled ? 'ENABLED' : 'DISABLED'}
                  </span>
                </div>
              </div>

              {aiLoading ? (
                <div className="flex items-center gap-2 text-slate-500 py-8">
                  <Loader2 className="w-5 h-5 animate-spin" /> Loading…
                </div>
              ) : (
                <>
                  {/* Master toggle */}
                  <div className="flex items-center justify-between py-4 px-5 rounded-xl bg-gradient-to-r from-amber-500/5 to-orange-500/5 border border-amber-500/15">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
                        <Brain className="w-5 h-5 text-amber-400" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-[var(--text-heading)]">Enable AI Reasoning</p>
                        <p className="text-xs text-slate-500">Activate LLM-powered analysis for compliance tasks</p>
                      </div>
                    </div>
                    <Toggle
                      value={aiSettings?.enabled ?? false}
                      onChange={v => updateAiMutation.mutate({ enabled: v })}
                    />
                  </div>

                  {!aiSettings?.enabled && (
                    <div className="flex items-start gap-3 py-4 px-5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-subtle)]">
                      <AlertTriangle className="w-5 h-5 text-slate-600 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="text-sm text-slate-400">AI Reasoning is currently disabled.</p>
                        <p className="text-xs text-slate-600 mt-1">
                          When enabled, you can use LLMs to generate control narratives, gap analysis reports,
                          POA&M entries, evidence mappings, and executive risk summaries. Toggle it on above
                          and configure your preferred provider below.
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Provider config — always visible so user can configure before enabling */}
                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Provider Configuration</h4>

                    {/* Demo mode toggle */}
                    <div className="flex items-center justify-between py-3 px-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-subtle)]">
                      <div>
                        <p className="text-sm font-semibold text-[var(--text-heading)]">Demo Mode</p>
                        <p className="text-xs text-slate-500 mt-0.5">Use simulated responses instead of calling a real LLM API</p>
                      </div>
                      <Toggle
                        value={aiSettings?.demo_mode ?? true}
                        onChange={v => updateAiMutation.mutate({ demo_mode: v })}
                      />
                    </div>

                    {/* Provider selection */}
                    <div>
                      <label className="block text-sm font-semibold text-slate-300 mb-1.5">Provider</label>
                      <div className="grid grid-cols-2 gap-2">
                        {AI_PROVIDERS.map(p => {
                          const isSelected = (aiForm.provider ?? aiSettings?.provider) === p.id;
                          return (
                            <button
                              key={p.id}
                              onClick={() => {
                                setAiForm(prev => ({ ...prev, provider: p.id, model: '' }));
                                updateAiMutation.mutate({ provider: p.id });
                              }}
                              className={`text-left px-4 py-3 rounded-xl border text-sm font-medium transition-all ${
                                isSelected
                                  ? 'bg-amber-500/10 border-amber-500/25 text-amber-300'
                                  : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:bg-[var(--bg-interactive)] hover:text-[var(--text-heading)]'
                              }`}
                            >
                              <p className="font-bold">{p.name}</p>
                              <p className="text-[10px] text-slate-500 mt-0.5">
                                {p.id === 'ollama' ? 'Local / air-gapped' : `${p.models.length} models`}
                              </p>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    {/* Model selection */}
                    <div>
                      <label className="block text-sm font-semibold text-slate-300 mb-1.5">Model</label>
                      <select
                        value={aiForm.model ?? aiSettings?.model ?? ''}
                        onChange={e => {
                          setAiForm(prev => ({ ...prev, model: e.target.value }));
                          updateAiMutation.mutate({ model: e.target.value });
                        }}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
                      >
                        <option value="">Select a model…</option>
                        {currentAiProvider?.models.map(m => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                    </div>

                    {/* API Key (not for Ollama) */}
                    {(aiForm.provider ?? aiSettings?.provider) !== 'ollama' ? (
                      <div>
                        <label className="block text-sm font-semibold text-slate-300 mb-1.5">
                          API Key <span className="text-[10px] text-slate-600 ml-1">(encrypted at rest)</span>
                        </label>
                        <div className="relative">
                          <input
                            type={showAiKey ? 'text' : 'password'}
                            defaultValue=""
                            onChange={e => setAiForm(prev => ({ ...prev, api_key: e.target.value }))}
                            placeholder={aiSettings?.api_key || '••••••••••••••••'}
                            className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 pr-10"
                          />
                          <button
                            type="button"
                            onClick={() => setShowAiKey(!showAiKey)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                          >
                            {showAiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div>
                        <label className="block text-sm font-semibold text-slate-300 mb-1.5">Ollama Base URL</label>
                        <input
                          type="text"
                          defaultValue={aiSettings?.base_url ?? ''}
                          onChange={e => setAiForm(prev => ({ ...prev, base_url: e.target.value }))}
                          placeholder="http://localhost:11434"
                          className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20"
                        />
                      </div>
                    )}

                    {/* Save + Test buttons */}
                    <div className="flex gap-3 pt-2">
                      <button
                        onClick={() => {
                          if (Object.keys(aiForm).length > 0) {
                            updateAiMutation.mutate(aiForm);
                          }
                        }}
                        disabled={updateAiMutation.isPending || Object.keys(aiForm).length === 0}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-sm font-bold transition-all shadow-lg shadow-amber-500/20 disabled:opacity-40"
                      >
                        {updateAiMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                        Save Configuration
                      </button>
                      <button
                        onClick={() => testAiMutation.mutate()}
                        disabled={testAiMutation.isPending || !aiSettings?.enabled}
                        className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm font-medium text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors disabled:opacity-40"
                      >
                        {testAiMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wifi className="w-4 h-4" />}
                        Test Connection
                      </button>
                    </div>

                    {updateAiMutation.isSuccess && (
                      <div className="flex items-center gap-2 text-emerald-400 text-sm">
                        <Check className="w-4 h-4" /> Settings saved
                      </div>
                    )}

                    {/* Test result */}
                    {testAiMutation.data && (
                      <div className={`flex items-start gap-3 p-4 rounded-xl border ${
                        testAiMutation.data.status === 'success'
                          ? 'bg-emerald-500/10 border-emerald-500/20'
                          : 'bg-red-500/10 border-red-500/20'
                      }`}>
                        {testAiMutation.data.status === 'success'
                          ? <Wifi className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                          : <WifiOff className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                        }
                        <div>
                          <p className={`text-sm font-medium ${testAiMutation.data.status === 'success' ? 'text-emerald-300' : 'text-red-300'}`}>
                            {testAiMutation.data.status === 'success' ? 'Connection successful' : 'Connection failed'}
                          </p>
                          <p className="text-xs text-slate-400 mt-0.5">{testAiMutation.data.message}</p>
                          {testAiMutation.data.latency_ms && (
                            <p className="text-xs text-emerald-500 mt-1">Latency: {testAiMutation.data.latency_ms}ms</p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Info box */}
                  <div className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-xl p-4">
                    <p className="text-xs text-slate-500 leading-relaxed">
                      The AI Reasoning Layer adds optional LLM-powered analysis to your GRC workflow.
                      When enabled, it powers control narrative generation, gap analysis, POA&M drafting,
                      evidence mapping, and executive risk summaries. All AI features are opt-in and
                      gated behind this toggle. Your API key is stored encrypted and never logged.
                      Use Demo Mode to explore capabilities without consuming API credits.
                    </p>
                  </div>
                </>
              )}
            </div>
          )}

          {/* API Keys */}
          {activeTab === 'api-keys' && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-[var(--text-heading)]">API Keys</h3>
                <button className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-400 hover:bg-blue-600/30 text-xs font-bold transition-colors">
                  <Plus className="w-3.5 h-3.5" /> Generate Key
                </button>
              </div>
              <div className="space-y-3">
                {(apiKeys ?? []).length === 0 ? (
                  <div className="py-10 text-center text-slate-500">
                    <Key className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">No API keys generated</p>
                  </div>
                ) : (apiKeys ?? []).map((key: any) => (
                  <div key={key.id} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <p className="text-sm font-bold text-[var(--text-heading)]">{key.name}</p>
                        <p className="text-[11px] text-slate-500">Created {new Date(key.created_at).toLocaleDateString()}</p>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => copyToClipboard(key.key, key.id)}
                          className="p-1.5 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-slate-400 hover:text-[var(--text-heading)] transition-colors"
                        >
                          {copied === key.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => setShowKey(p => ({ ...p, [key.id]: !p[key.id] }))}
                          className="p-1.5 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-slate-400 hover:text-[var(--text-heading)] transition-colors"
                        >
                          {showKey[key.id] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                        <button className="p-1.5 rounded-lg bg-[var(--bg-interactive)] hover:bg-red-500/10 hover:border hover:border-red-500/20 text-slate-400 hover:text-red-400 transition-colors">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="font-mono text-xs text-slate-500 bg-black/20 rounded-lg px-3 py-2">
                      {showKey[key.id] ? key.key : `${key.key?.slice(0, 8) ?? 'grc_'}${'•'.repeat(32)}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Audit Log */}
          {activeTab === 'audit' && (
            <div className="space-y-4">
              <h3 className="text-base font-bold text-[var(--text-heading)]">Audit Log</h3>
              <div className="divide-y divide-[var(--border-subtle)]">
                {(auditLog ?? []).length === 0 ? (
                  <p className="py-10 text-center text-sm text-slate-500">No audit events recorded</p>
                ) : (auditLog ?? []).map((event: any) => (
                  <div key={event.id} className="py-3 flex items-start gap-3">
                    <div className="w-7 h-7 rounded-full bg-blue-500/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Activity className="w-3.5 h-3.5 text-blue-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-[var(--text-heading)] font-medium">{event.action}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{event.actor} · {new Date(event.timestamp).toLocaleString()}</p>
                    </div>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${event.outcome === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                      {event.outcome}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
