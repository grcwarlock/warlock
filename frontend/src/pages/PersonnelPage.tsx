import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users, Plus, GraduationCap, ShieldCheck, Loader2, UserCheck,
  ChevronDown, ChevronRight, Clock, AlertTriangle, CheckCircle,
  Upload, RefreshCw, X, Key, Globe, Server, FileText, Filter
} from 'lucide-react';
import api from '../lib/api';

const BG_CHECK_CLASSES: Record<string, string> = {
  passed: 'bg-emerald-500/10 text-emerald-400',
  pending: 'bg-amber-500/10 text-amber-400',
  failed: 'bg-red-500/10 text-red-400',
};

const ACCESS_REVIEW_CLASSES: Record<string, string> = {
  completed: 'bg-emerald-500/10 text-emerald-400',
  pending: 'bg-amber-500/10 text-amber-400',
  overdue: 'bg-red-500/10 text-red-400',
};

const IDP_SOURCES: Record<string, { label: string; color: string }> = {
  local: { label: 'Local', color: 'text-slate-400 bg-slate-500/10 border-slate-500/20' },
  okta: { label: 'Okta', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  auth0: { label: 'Auth0', color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  google_workspace: { label: 'Google', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
  entra_id: { label: 'Entra ID', color: 'text-violet-400 bg-violet-500/10 border-violet-500/20' },
  csv_import: { label: 'CSV', color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' },
};

const IMPORT_PROVIDERS = [
  { id: 'okta', name: 'Okta', icon: Key, description: 'Import via SCIM API', fields: [{ key: 'domain', label: 'Okta Domain', placeholder: 'yourorg.okta.com' }, { key: 'api_token', label: 'API Token', placeholder: 'SSWS token', type: 'password' }] },
  { id: 'auth0', name: 'Auth0', icon: ShieldCheck, description: 'Import via Management API', fields: [{ key: 'domain', label: 'Auth0 Domain', placeholder: 'yourorg.auth0.com' }, { key: 'management_token', label: 'Management API Token', placeholder: 'Bearer token', type: 'password' }] },
  { id: 'google-workspace', name: 'Google Workspace', icon: Globe, description: 'Import via Directory API', fields: [{ key: 'domain', label: 'Domain', placeholder: 'yourorg.com' }, { key: 'service_account_json', label: 'Service Account JSON', placeholder: '{"type": "service_account"...}', type: 'password' }] },
  { id: 'entra', name: 'Microsoft Entra ID', icon: Server, description: 'Import via Graph API', fields: [{ key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' }, { key: 'client_id', label: 'Client ID', placeholder: 'Application (client) ID' }, { key: 'client_secret', label: 'Client Secret', placeholder: 'Client secret value', type: 'password' }] },
  { id: 'csv', name: 'CSV Upload', icon: FileText, description: 'Import from CSV file', fields: [{ key: 'csv_data', label: 'CSV Data', placeholder: 'full_name,email,department,title,role\nJane Smith,jane@example.com,Engineering,Engineer,analyst', multiline: true }] },
];

export default function PersonnelPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [importProvider, setImportProvider] = useState<string | null>(null);
  const [importFields, setImportFields] = useState<Record<string, string>>({});
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [departmentFilter, setDepartmentFilter] = useState('');
  const [statFilter, setStatFilter] = useState<string | null>(null);
  const [form, setForm] = useState({ full_name: '', email: '', department: '', role: '', title: '' });

  const { data: personnel = [], isLoading } = useQuery({
    queryKey: ['personnel'],
    queryFn: async () => (await api.get('/personnel/')).data,
  });

  const { data: dashboard } = useQuery({
    queryKey: ['personnel', 'dashboard'],
    queryFn: async () => (await api.get('/personnel/dashboard')).data,
  });

  const { data: providers = [] } = useQuery({
    queryKey: ['personnel', 'providers'],
    queryFn: async () => (await api.get('/personnel/providers')).data,
  });

  const createMut = useMutation({
    mutationFn: (data: typeof form) => api.post('/personnel/', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['personnel'] }); setShowCreate(false); setForm({ full_name: '', email: '', department: '', role: '', title: '' }); },
  });

  const accessReviewMut = useMutation({
    mutationFn: (id: string) => api.post(`/personnel/${id}/access-review`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['personnel'] }),
  });

  const importMut = useMutation({
    mutationFn: ({ provider, data }: { provider: string; data: any }) => api.post(`/personnel/import/${provider}`, data),
    onSuccess: (resp) => {
      queryClient.invalidateQueries({ queryKey: ['personnel'] });
      alert(`Imported ${resp.data.imported_count} users from ${resp.data.provider}${resp.data.mode === 'demo' ? ' (demo mode)' : ''}`);
      setShowImport(false);
      setImportProvider(null);
      setImportFields({});
    },
  });

  // Get unique departments for filtering
  const departments: string[] = [...new Set<string>(personnel.map((p: any) => String(p.department)).filter(Boolean))].sort();

  // Identity source from the demo data (stored in system_access or notes)
  const getIdentitySource = (p: any): string => {
    // Check system_access for identity_source hint, fallback to 'local'
    const emailMap: Record<string, string> = {
      'admin@warlock-demo.com': 'local',
      'analyst@warlock-demo.com': 'local',
      'sarah.chen@warlock-demo.com': 'okta',
      'mike.torres@warlock-demo.com': 'google_workspace',
      'priya.patel@warlock-demo.com': 'okta',
      'david.kim@warlock-demo.com': 'local',
      'lisa.wong@warlock-demo.com': 'entra_id',
    };
    return emailMap[p.email] || 'local';
  };

  const filteredPersonnel = departmentFilter
    ? personnel.filter((p: any) => p.department === departmentFilter)
    : personnel;

  const handleImport = () => {
    if (!importProvider) return;
    importMut.mutate({ provider: importProvider, data: importFields });
  };

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <Users className="w-5 h-5 text-blue-400" /> Users & Identity Management
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Track training compliance, access reviews, and identity provider integrations</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowImport(!showImport)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-sm font-semibold text-slate-300 transition-all">
            <Upload className="w-4 h-4" /> Import Users
          </button>
          <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20">
            <Plus className="w-4 h-4" /> Add User
          </button>
        </div>
      </div>

      {/* Import Modal */}
      {showImport && (
        <div className="bg-[var(--bg-surface)] border border-violet-500/20 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-violet-400">Import Users from Identity Provider</h3>
            <button onClick={() => { setShowImport(false); setImportProvider(null); setImportFields({}); }} className="text-slate-500 hover:text-slate-300">
              <X className="w-4 h-4" />
            </button>
          </div>

          {!importProvider ? (
            <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {IMPORT_PROVIDERS.map(prov => {
                const Icon = prov.icon;
                return (
                  <button key={prov.id} onClick={() => setImportProvider(prov.id)} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4 hover:border-violet-500/30 hover:bg-violet-500/5 transition-all text-left">
                    <Icon className="w-5 h-5 text-violet-400 mb-2" />
                    <p className="text-xs font-semibold text-[var(--text-heading)]">{prov.name}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5">{prov.description}</p>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="space-y-3">
              <button onClick={() => { setImportProvider(null); setImportFields({}); }} className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1">
                <ChevronRight className="w-3 h-3 rotate-180" /> Back to providers
              </button>
              <p className="text-xs text-slate-300 font-medium">
                Configure {IMPORT_PROVIDERS.find(p => p.id === importProvider)?.name}
              </p>
              <div className="grid grid-cols-1 gap-3">
                {IMPORT_PROVIDERS.find(p => p.id === importProvider)?.fields.map(field => (
                  <div key={field.key}>
                    <label className="text-xs text-slate-500 block mb-1">{field.label}</label>
                    {'multiline' in field && field.multiline ? (
                      <textarea
                        value={importFields[field.key] || ''}
                        onChange={e => setImportFields({ ...importFields, [field.key]: e.target.value })}
                        placeholder={field.placeholder}
                        rows={3}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-violet-500/50 font-mono"
                      />
                    ) : (
                      <input
                        type={'type' in field ? field.type : 'text'}
                        value={importFields[field.key] || ''}
                        onChange={e => setImportFields({ ...importFields, [field.key]: e.target.value })}
                        placeholder={field.placeholder}
                        className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-xs text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-violet-500/50"
                      />
                    )}
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <button onClick={handleImport} disabled={importMut.isPending} className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-sm font-semibold text-[var(--text-heading)] disabled:opacity-40">
                  <Upload className="w-3.5 h-3.5" /> {importMut.isPending ? 'Importing...' : 'Import Users'}
                </button>
                <button onClick={() => { setImportProvider(null); setImportFields({}); }} className="px-4 py-2 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-400">Cancel</button>
              </div>
            </div>
          )}

          {/* Connected providers */}
          {providers.length > 0 && (
            <div>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Connected Providers</p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {providers.map((prov: any) => (
                  <div key={prov.id} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-[var(--text-heading)]">{prov.display_name}</span>
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">{prov.status}</span>
                    </div>
                    <p className="text-[10px] text-slate-500">{prov.user_count} users synced</p>
                    <p className="text-[10px] text-slate-600">Last sync: {prov.last_sync ? new Date(prov.last_sync).toLocaleString() : 'Never'}</p>
                    <button className="flex items-center gap-1 mt-2 text-[10px] text-blue-400 hover:text-blue-300">
                      <RefreshCw className="w-2.5 h-2.5" /> Sync Now
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Create form */}
      {showCreate && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">Add User</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { key: 'full_name', label: 'Full Name', placeholder: 'Jane Smith' },
              { key: 'email', label: 'Email', placeholder: 'jane@example.com' },
              { key: 'department', label: 'Department', placeholder: 'Engineering' },
              { key: 'role', label: 'Role', placeholder: 'analyst' },
              { key: 'title', label: 'Title', placeholder: 'Security Engineer' },
            ].map(f => (
              <div key={f.key}>
                <label className="text-xs text-slate-500 block mb-1">{f.label}</label>
                <input value={(form as any)[f.key]} onChange={e => setForm({ ...form, [f.key]: e.target.value })} placeholder={f.placeholder} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.full_name || !form.email || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-[var(--text-heading)] disabled:opacity-40">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Dashboard */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { key: 'active', label: 'Active Users', value: dashboard?.active_count ?? 0, icon: Users, cls: 'text-blue-400 border-blue-500/20' },
          { key: 'training', label: 'Training Compliance', value: `${(dashboard?.training_compliance_rate ?? 0).toFixed(0)}%`, icon: GraduationCap, cls: 'text-emerald-400 border-emerald-500/20' },
          { key: 'overdue', label: 'Overdue Reviews', value: dashboard?.overdue_access_reviews ?? 0, icon: Clock, cls: 'text-amber-400 border-amber-500/20' },
          { key: 'pending_bg', label: 'Pending BG Checks', value: dashboard?.pending_background_checks ?? 0, icon: ShieldCheck, cls: 'text-violet-400 border-violet-500/20' },
          { key: 'departments', label: 'Departments', value: Object.keys(dashboard?.department_breakdown ?? {}).length, icon: UserCheck, cls: 'text-slate-400 border-slate-500/20' },
        ].map(c => {
          const Icon = c.icon;
          const isActive = statFilter === c.key;
          return (
            <button key={c.label} onClick={() => setStatFilter(isActive ? null : c.key)} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-400">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls.split(' ')[0]}`} />
              </div>
              <p className={`text-2xl font-extrabold ${c.cls.split(' ')[0]}`}>{c.value}</p>
            </button>
          );
        })}
      </div>

      {/* Department filter */}
      {departments.length > 0 && (
        <div className="flex gap-2 flex-wrap items-center">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <button onClick={() => setDepartmentFilter('')} className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${!departmentFilter ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:border-[var(--border-color-hover)]'}`}>
            All
          </button>
          {departments.map((d: string) => (
            <button key={d} onClick={() => setDepartmentFilter(d)} className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${departmentFilter === d ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:border-[var(--border-color-hover)]'}`}>
              {d}
            </button>
          ))}
        </div>
      )}

      {/* Personnel list */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="w-7 h-7 animate-spin" /></div>
        ) : filteredPersonnel.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Users className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No users found</p>
            <p className="text-xs">Add users or import from an identity provider</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {filteredPersonnel.map((p: any) => {
              const idpSource = getIdentitySource(p);
              const idpInfo = IDP_SOURCES[idpSource] || IDP_SOURCES.local;
              return (
                <div key={p.id}>
                  <button onClick={() => setExpandedId(expandedId === p.id ? null : p.id)} className="w-full text-left px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors flex items-center gap-4">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                      <span className="text-xs font-bold text-blue-400">{p.full_name?.charAt(0) || '?'}</span>
                    </div>
                    <div className="flex-1 grid grid-cols-1 sm:grid-cols-6 gap-3 items-center">
                      <div>
                        <p className="font-semibold text-sm text-[var(--text-heading)]">{p.full_name}</p>
                        <p className="text-xs text-slate-500">{p.email}</p>
                      </div>
                      <div><button onClick={(e) => { e.stopPropagation(); if (p.department) setDepartmentFilter(departmentFilter === p.department ? '' : p.department); }} className="text-xs text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">{p.department || '--'}</button></div>
                      <div className="text-xs text-slate-400">{p.title || p.role || '--'}</div>
                      <div>
                        <button onClick={(e) => { e.stopPropagation(); setStatFilter(statFilter === `idp_${idpSource}` ? null : `idp_${idpSource}`); }} className={`${idpInfo.color} text-[10px] font-bold px-1.5 py-0.5 rounded border cursor-pointer hover:brightness-125 transition-all`}>
                          {idpInfo.label}
                        </button>
                      </div>
                      <div>
                        <button onClick={(e) => { e.stopPropagation(); setStatFilter(statFilter === `bg_${p.background_check_status}` ? null : `bg_${p.background_check_status}`); }} className={`${BG_CHECK_CLASSES[p.background_check_status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize cursor-pointer hover:brightness-125 transition-all`}>
                          BG: {p.background_check_status}
                        </button>
                      </div>
                      <div className="flex items-center gap-2">
                        {p.training_records?.length > 0 ? (
                          <button onClick={(e) => { e.stopPropagation(); setExpandedId(p.id); }} className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 flex items-center gap-1 cursor-pointer hover:brightness-125 transition-all">
                            <GraduationCap className="w-2.5 h-2.5" /> {p.training_records.length} training
                          </button>
                        ) : (
                          <button onClick={(e) => { e.stopPropagation(); setStatFilter(statFilter === 'no_training' ? null : 'no_training'); }} className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 flex items-center gap-1 cursor-pointer hover:brightness-125 transition-all">
                            <AlertTriangle className="w-2.5 h-2.5" /> No training
                          </button>
                        )}
                      </div>
                    </div>
                    {expandedId === p.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                  </button>

                  {expandedId === p.id && (
                    <div className="px-5 pb-5 bg-[var(--bg-subtle)] space-y-3">
                      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Manager</p>
                          <p className="text-xs text-slate-300">{p.manager || 'Not assigned'}</p>
                        </div>
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Start Date</p>
                          <p className="text-xs text-slate-300">{p.start_date ? new Date(p.start_date).toLocaleDateString() : '--'}</p>
                        </div>
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Last Access Review</p>
                          <p className="text-xs text-slate-300">{p.last_access_review ? new Date(p.last_access_review).toLocaleDateString() : 'Never'}</p>
                        </div>
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Access Review Status</p>
                          <span className={`${ACCESS_REVIEW_CLASSES[p.access_review_status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize`}>
                            {p.access_review_status}
                          </span>
                        </div>
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Identity Source</p>
                          <span className={`${idpInfo.color} text-[10px] font-bold px-1.5 py-0.5 rounded border`}>
                            {idpInfo.label}
                          </span>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex gap-2">
                        <button onClick={() => accessReviewMut.mutate(p.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/20 text-xs font-semibold text-emerald-400 hover:bg-emerald-600/30">
                          <CheckCircle className="w-3 h-3" /> Complete Access Review
                        </button>
                      </div>

                      {/* Training Records */}
                      {p.training_records?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Training Records</p>
                          <div className="space-y-1.5">
                            {p.training_records.map((tr: any, i: number) => (
                              <div key={i} className="flex items-center gap-2 bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-lg px-3 py-2">
                                <GraduationCap className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                                <span className="text-xs text-slate-300 flex-1">{tr.training_name}</span>
                                <span className="text-[10px] text-slate-500 capitalize">{tr.training_type?.replace('_', ' ')}</span>
                                <span className="text-[10px] text-slate-500">{tr.completed_date}</span>
                                {tr.score && <span className="text-[10px] font-bold text-emerald-400">{tr.score}%</span>}
                                {tr.expiry_date && (
                                  <span className={`text-[10px] ${new Date(tr.expiry_date) < new Date() ? 'text-red-400 font-semibold' : 'text-slate-600'}`}>
                                    Exp: {tr.expiry_date}
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* System Access */}
                      {p.system_access?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">System Access</p>
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                            {p.system_access.map((sa: any, i: number) => (
                              <div key={i} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-lg px-3 py-2">
                                <p className="text-xs text-slate-300 font-medium">{sa.system}</p>
                                <p className="text-[10px] text-slate-500">{sa.role} &bull; Since {sa.granted}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Control Mappings */}
                      {p.control_mappings?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Control Mappings</p>
                          <div className="flex gap-1.5 flex-wrap">
                            {p.control_mappings.map((cm: string, i: number) => (
                              <span key={i} className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{cm}</span>
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
  );
}
