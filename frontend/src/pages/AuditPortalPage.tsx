import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ClipboardCheck, Plus, MessageSquare, CheckCircle, Loader2,
  AlertCircle, FileSearch, User, Send
} from 'lucide-react';
import api from '../lib/api';

const COMMENT_TYPE_CLASSES: Record<string, string> = {
  comment: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
  request: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  finding: 'bg-red-500/10 text-red-400 border-red-500/20',
  resolution: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
};

const COMMENT_TYPE_ICONS: Record<string, any> = {
  comment: MessageSquare,
  request: AlertCircle,
  finding: FileSearch,
  resolution: CheckCircle,
};

export default function AuditPortalPage() {
  const queryClient = useQueryClient();
  const [auditId, setAuditId] = useState('audit-2026-q1');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    audit_id: 'audit-2026-q1', resource_type: 'evidence', resource_id: '',
    author: '', author_role: 'auditor', comment_type: 'comment', content: '',
  });

  const { data: engagement } = useQuery({
    queryKey: ['audit', 'engagement', auditId],
    queryFn: async () => (await api.get(`/audit/engagements/${auditId}`)).data,
  });

  const { data: comments = [], isLoading } = useQuery({
    queryKey: ['audit', 'comments', auditId],
    queryFn: async () => (await api.get('/audit/comments', { params: { audit_id: auditId } })).data,
  });

  const createMut = useMutation({
    mutationFn: (data: any) => api.post('/audit/comments', data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['audit'] }); setShowCreate(false); setForm({ ...form, content: '', resource_id: '' }); },
  });

  const resolveMut = useMutation({
    mutationFn: (id: string) => api.post(`/audit/comments/${id}/resolve?resolved_by=analyst`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['audit'] }),
  });

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <ClipboardCheck className="w-5 h-5 text-blue-400" /> Audit Collaboration Portal
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Auditor comments, evidence requests, and findings in one place</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500">Engagement:</label>
            <select value={auditId} onChange={e => setAuditId(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
              <option value="audit-2026-q1">2026 Q1 Annual Audit</option>
              <option value="audit-2025-soc2">2025 SOC 2 Type II</option>
              <option value="audit-2025-iso">2025 ISO 27001</option>
            </select>
          </div>
          <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20">
            <Plus className="w-4 h-4" /> Add Comment
          </button>
        </div>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">New Audit Comment / Request</h3>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div>
              <label className="text-xs text-slate-500 block mb-1">Author</label>
              <input value={form.author} onChange={e => setForm({ ...form, author: e.target.value })} placeholder="John Auditor" className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Role</label>
              <select value={form.author_role} onChange={e => setForm({ ...form, author_role: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                <option value="auditor">Auditor</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Type</label>
              <select value={form.comment_type} onChange={e => setForm({ ...form, comment_type: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                <option value="comment">Comment</option>
                <option value="request">Evidence Request</option>
                <option value="finding">Finding</option>
                <option value="resolution">Resolution</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Resource Type</label>
              <select value={form.resource_type} onChange={e => setForm({ ...form, resource_type: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                <option value="evidence">Evidence</option>
                <option value="control">Control</option>
                <option value="assessment">Assessment</option>
                <option value="poam">POAM Item</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">Resource ID / Control ID</label>
            <input value={form.resource_id} onChange={e => setForm({ ...form, resource_id: e.target.value })} placeholder="AC-2, SC-7, evidence-id..." className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">Content</label>
            <textarea value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} rows={3} placeholder="Please provide evidence of MFA enforcement for all privileged accounts…" className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate({ ...form, audit_id: auditId })} disabled={!form.author || !form.content || createMut.isPending} className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-[var(--text-heading)] disabled:opacity-40">
              <Send className="w-3.5 h-3.5" /> {createMut.isPending ? 'Submitting…' : 'Submit'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Engagement summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Comments', value: engagement?.total_comments ?? 0, cls: 'text-blue-400 border-blue-500/20', filterType: '' },
          { label: 'Open Requests', value: engagement?.open_requests ?? 0, cls: 'text-amber-400 border-amber-500/20', filterType: 'request' },
          { label: 'Resolved', value: engagement?.resolved_requests ?? 0, cls: 'text-emerald-400 border-emerald-500/20', filterType: 'resolution' },
          { label: 'Findings', value: engagement?.findings_count ?? 0, cls: 'text-red-400 border-red-500/20', filterType: 'finding' },
        ].map(c => (
          <button key={c.label} onClick={() => { /* scrolls to comment type filter */ const el = document.querySelector(`[data-comment-type="${c.filterType}"]`); el?.scrollIntoView({ behavior: 'smooth' }); }} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all`}>
            <span className="text-xs text-slate-400">{c.label}</span>
            <p className={`text-3xl font-extrabold ${c.cls.split(' ')[0]} mt-1`}>{c.value}</p>
          </button>
        ))}
      </div>

      {/* Comments list */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="w-7 h-7 animate-spin" /></div>
        ) : comments.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <ClipboardCheck className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No audit comments yet</p>
            <p className="text-xs">Auditors can add comments, requests, and findings here</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {comments.map((c: any) => {
              const TypeIcon = COMMENT_TYPE_ICONS[c.comment_type] || MessageSquare;
              return (
                <div key={c.id} className="px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors">
                  <div className="flex items-start gap-3">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${c.author_role === 'auditor' ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-blue-500/10 border border-blue-500/20'}`}>
                      <User className={`w-3.5 h-3.5 ${c.author_role === 'auditor' ? 'text-amber-400' : 'text-blue-400'}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-semibold text-[var(--text-heading)]">{c.author}</span>
                        <button data-comment-type={c.comment_type} className={`${COMMENT_TYPE_CLASSES[c.comment_type] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border flex items-center gap-1 cursor-pointer hover:brightness-125 transition-all`}>
                          <TypeIcon className="w-2.5 h-2.5" /> {c.comment_type}
                        </button>
                        <span className="text-[10px] text-slate-600 capitalize">{c.author_role}</span>
                        {c.is_resolved && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                            <CheckCircle className="w-2.5 h-2.5" /> Resolved
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mb-2">
                        <button onClick={() => navigator.clipboard.writeText(c.resource_id)} className="text-[10px] text-slate-500 hover:text-slate-300 cursor-pointer transition-colors" title="Click to copy resource ID">
                          {c.resource_type}: <span className="text-blue-400 font-semibold">{c.resource_id}</span>
                        </button>
                        <span className="text-[10px] text-slate-600">{c.created_at ? new Date(c.created_at).toLocaleString() : ''}</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{c.content}</p>
                      {!c.is_resolved && (c.comment_type === 'request' || c.comment_type === 'finding') && (
                        <button onClick={() => resolveMut.mutate(c.id)} className="mt-2 flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-600/20 border border-emerald-500/20 text-[10px] font-semibold text-emerald-400 hover:bg-emerald-600/30">
                          <CheckCircle className="w-3 h-3" /> Mark Resolved
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
