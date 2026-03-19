import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ListTodo, Plus, CheckCircle, Loader2, AlertTriangle,
  ChevronDown, ChevronRight, MessageSquare, User, Filter, X
} from 'lucide-react';
import api from '../lib/api';

const PRIORITY_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/20',
};

const STATUS_CLASSES: Record<string, string> = {
  open: 'bg-red-500/10 text-red-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  review: 'bg-violet-500/10 text-violet-400',
  completed: 'bg-emerald-500/10 text-emerald-400',
  deferred: 'bg-slate-500/10 text-slate-400',
};

const TASK_TYPES = ['remediation', 'review', 'evidence', 'approval', 'vendor_assessment'];

const DEMO_USERS = [
  'Jason Wilson', 'Sam Rivera', 'Sarah Chen', 'Mike Torres',
  'Priya Patel', 'David Kim', 'Lisa Wong',
];

export default function TasksPage() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('');
  const [assigneeFilter, setAssigneeFilter] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [form, setForm] = useState({ title: '', description: '', task_type: 'remediation', assigned_to: '', priority: 'medium', due_date: '' });
  const [commentForm, setCommentForm] = useState({ author: 'Jason Wilson', content: '' });

  const { data: tasks = [], isLoading } = useQuery({
    queryKey: ['tasks', statusFilter],
    queryFn: async () => (await api.get('/tasks/', { params: statusFilter ? { status: statusFilter } : {} })).data,
  });

  const { data: dashboard } = useQuery({
    queryKey: ['tasks', 'dashboard'],
    queryFn: async () => (await api.get('/tasks/dashboard')).data,
  });

  const createMut = useMutation({
    mutationFn: (data: typeof form) => api.post('/tasks/', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] });
      setShowCreate(false);
      setForm({ title: '', description: '', task_type: 'remediation', assigned_to: '', priority: 'medium', due_date: '' });
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, ...data }: { id: string; status?: string }) => api.put(`/tasks/${id}`, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }),
  });

  const commentMut = useMutation({
    mutationFn: ({ id, ...data }: { id: string; author: string; content: string }) => api.post(`/tasks/${id}/comments`, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['tasks'] }); setCommentForm({ author: 'Jason Wilson', content: '' }); },
  });

  // Client-side filtering for priority and assignee
  const filteredTasks = tasks.filter((t: any) => {
    if (priorityFilter && t.priority !== priorityFilter) return false;
    if (assigneeFilter && t.assigned_to !== assigneeFilter) return false;
    return true;
  });

  const hasActiveFilters = priorityFilter || assigneeFilter;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <ListTodo className="w-5 h-5 text-blue-400" /> Task & Workflow Management
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Assign remediation, reviews, and approvals with due dates & tracking</p>
        </div>
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20">
          <Plus className="w-4 h-4" /> New Task
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-[var(--bg-surface)] border border-blue-500/20 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-blue-400">Create Task</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="sm:col-span-2">
              <label className="text-xs text-slate-500 block mb-1">Title</label>
              <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} placeholder="Remediate AC-2 MFA findings" className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Assign To</label>
              <select value={form.assigned_to} onChange={e => setForm({ ...form, assigned_to: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                <option value="">Select assignee...</option>
                {DEMO_USERS.map(u => <option key={u} value={u}>{u}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-500 block mb-1">Type</label>
              <select value={form.task_type} onChange={e => setForm({ ...form, task_type: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                {TASK_TYPES.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Priority</label>
              <select value={form.priority} onChange={e => setForm({ ...form, priority: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
                {['critical', 'high', 'medium', 'low'].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 block mb-1">Due Date</label>
              <input type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50" />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-500 block mb-1">Description</label>
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} placeholder="Detailed instructions..." className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" />
          </div>
          <div className="flex gap-2">
            <button onClick={() => createMut.mutate(form)} disabled={!form.title || !form.assigned_to || createMut.isPending} className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-semibold text-[var(--text-heading)] disabled:opacity-40">
              {createMut.isPending ? 'Creating...' : 'Create Task'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg bg-[var(--bg-interactive)] hover:bg-[var(--bg-interactive-hover)] text-sm text-slate-400">Cancel</button>
          </div>
        </div>
      )}

      {/* Dashboard summary */}
      <div className="grid grid-cols-5 gap-4">
        {[
          { label: 'Open', value: dashboard?.by_status?.open ?? 0, cls: 'text-red-400 border-red-500/20', filterVal: 'open' },
          { label: 'In Progress', value: dashboard?.by_status?.in_progress ?? 0, cls: 'text-amber-400 border-amber-500/20', filterVal: 'in_progress' },
          { label: 'In Review', value: dashboard?.by_status?.review ?? 0, cls: 'text-violet-400 border-violet-500/20', filterVal: 'review' },
          { label: 'Completed', value: dashboard?.by_status?.completed ?? 0, cls: 'text-emerald-400 border-emerald-500/20', filterVal: 'completed' },
          { label: 'Overdue', value: dashboard?.overdue ?? 0, cls: 'text-red-400 border-red-500/20', filterVal: 'open' },
        ].map(c => (
          <button key={c.label} onClick={() => setStatusFilter(statusFilter === c.filterVal ? '' : c.filterVal)} className={`bg-[var(--bg-surface)] border ${c.cls} rounded-2xl p-4 cursor-pointer hover:bg-[var(--bg-interactive)] transition-all text-left ${statusFilter === c.filterVal ? 'ring-1 ring-[var(--border-color-hover)]' : ''}`}>
            <span className="text-xs text-slate-400">{c.label}</span>
            <p className={`text-2xl font-extrabold ${c.cls.split(' ')[0]} mt-1`}>{c.value}</p>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        {['', 'open', 'in_progress', 'review', 'completed', 'deferred'].map(s => (
          <button key={s} onClick={() => setStatusFilter(s)} className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${statusFilter === s ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:border-[var(--border-color-hover)]'}`}>
            {s === '' ? 'All' : s.replace('_', ' ')}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => setShowFilters(!showFilters)} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-colors border ${showFilters || hasActiveFilters ? 'bg-violet-500/20 border-violet-500/30 text-violet-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-400 hover:border-[var(--border-color-hover)]'}`}>
            <Filter className="w-3 h-3" /> Filters {hasActiveFilters ? '(active)' : ''}
          </button>
          {hasActiveFilters && (
            <button onClick={() => { setPriorityFilter(''); setAssigneeFilter(''); }} className="text-xs text-slate-500 hover:text-slate-300">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {showFilters && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4 flex gap-4 flex-wrap">
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Priority</label>
            <select value={priorityFilter} onChange={e => setPriorityFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
              <option value="">All priorities</option>
              {['critical', 'high', 'medium', 'low'].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Assignee</label>
            <select value={assigneeFilter} onChange={e => setAssigneeFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50">
              <option value="">All assignees</option>
              {DEMO_USERS.map(u => <option key={u} value={u}>{u}</option>)}
            </select>
          </div>
        </div>
      )}

      {/* Task list */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500"><Loader2 className="w-7 h-7 animate-spin" /></div>
        ) : filteredTasks.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <ListTodo className="w-10 h-10 text-slate-600" />
            <p className="text-sm font-semibold">No tasks found</p>
            {hasActiveFilters && <p className="text-xs">Try adjusting your filters</p>}
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {filteredTasks.map((t: any) => (
              <div key={t.id}>
                <button onClick={() => setExpandedId(expandedId === t.id ? null : t.id)} className="w-full text-left px-5 py-4 hover:bg-[var(--bg-subtle)] transition-colors flex items-center gap-4">
                  <div className="flex-1 grid grid-cols-1 sm:grid-cols-6 gap-3 items-center">
                    <div className="sm:col-span-2">
                      <p className="font-semibold text-sm text-[var(--text-heading)]">{t.title}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-slate-500 capitalize">{t.task_type.replace('_', ' ')}</span>
                        {t.reference_id && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">{t.reference_id}</span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5" onClick={(e) => { e.stopPropagation(); setAssigneeFilter(assigneeFilter === t.assigned_to ? '' : t.assigned_to); setShowFilters(true); }}>
                      <User className="w-3 h-3 text-slate-500" />
                      <span className="text-xs text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">{t.assigned_to}</span>
                    </div>
                    <div onClick={(e) => { e.stopPropagation(); setPriorityFilter(priorityFilter === t.priority ? '' : t.priority); setShowFilters(true); }}>
                      <span className={`${PRIORITY_CLASSES[t.priority] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border capitalize cursor-pointer hover:brightness-125 transition-all`}>{t.priority}</span>
                    </div>
                    <div className="text-xs text-slate-400">
                      {t.due_date ? (
                        <span className={new Date(t.due_date) < new Date() && t.status !== 'completed' ? 'text-red-400 font-semibold' : ''}>
                          {new Date(t.due_date) < new Date() && t.status !== 'completed' && <AlertTriangle className="w-3 h-3 inline mr-1" />}
                          Due {new Date(t.due_date).toLocaleDateString()}
                        </span>
                      ) : 'No due date'}
                    </div>
                    <div onClick={(e) => { e.stopPropagation(); setStatusFilter(statusFilter === t.status ? '' : t.status); }}>
                      <span className={`${STATUS_CLASSES[t.status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize cursor-pointer hover:brightness-125 transition-all`}>{t.status.replace('_', ' ')}</span>
                    </div>
                  </div>
                  {expandedId === t.id ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                </button>

                {expandedId === t.id && (
                  <div className="px-5 pb-5 bg-[var(--bg-subtle)] space-y-3">
                    {t.description && <p className="text-xs text-slate-300 leading-relaxed bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-3">{t.description}</p>}

                    {/* Status transitions */}
                    <div>
                      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1.5">Update Status</p>
                      <div className="flex gap-2 flex-wrap">
                        {['open', 'in_progress', 'review', 'completed', 'deferred'].map(s => (
                          <button key={s} onClick={() => updateMut.mutate({ id: t.id, status: s })} className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-colors ${t.status === s ? 'bg-blue-500/20 border-blue-500/30 text-blue-400' : 'bg-[var(--bg-subtle)] border-[var(--border-color)] text-slate-500 hover:border-[var(--border-color-hover)]'}`}>
                            {s === 'completed' && <CheckCircle className="w-3 h-3 inline mr-1" />}
                            {s.replace('_', ' ')}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Task metadata */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-2.5">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider">Assigned By</p>
                        <p className="text-xs text-slate-300 mt-0.5">{t.assigned_by || 'system'}</p>
                      </div>
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-2.5">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider">Type</p>
                        <p className="text-xs text-slate-300 mt-0.5 capitalize">{t.task_type.replace('_', ' ')}</p>
                      </div>
                      {t.reference_id && (
                        <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-2.5">
                          <p className="text-[10px] text-slate-500 uppercase tracking-wider">Related Control</p>
                          <p className="text-xs text-blue-400 mt-0.5 font-semibold">{t.reference_id}</p>
                        </div>
                      )}
                      <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-2.5">
                        <p className="text-[10px] text-slate-500 uppercase tracking-wider">Created</p>
                        <p className="text-xs text-slate-300 mt-0.5">{t.created_at ? new Date(t.created_at).toLocaleDateString() : '-'}</p>
                      </div>
                    </div>

                    {/* Comments */}
                    {t.comments?.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Comments ({t.comments.length})</p>
                        {t.comments.map((c: any, i: number) => (
                          <div key={i} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-lg p-2.5 flex gap-2">
                            <MessageSquare className="w-3 h-3 text-slate-600 mt-0.5 flex-shrink-0" />
                            <div>
                              <p className="text-xs text-slate-300">{c.content}</p>
                              <p className="text-[10px] text-slate-600 mt-1">{c.author} &bull; {c.timestamp ? new Date(c.timestamp).toLocaleString() : ''}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <select value={commentForm.author} onChange={e => setCommentForm({ ...commentForm, author: e.target.value })} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2 py-1.5 text-xs text-[var(--text-heading)] focus:outline-none focus:border-blue-500/50 w-36">
                        {DEMO_USERS.map(u => <option key={u} value={u}>{u}</option>)}
                      </select>
                      <input value={commentForm.content} onChange={e => setCommentForm({ ...commentForm, content: e.target.value })} placeholder="Add a comment..." className="flex-1 bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50" onKeyDown={e => { if (e.key === 'Enter' && commentForm.content) { commentMut.mutate({ id: t.id, ...commentForm }); } }} />
                      <button onClick={() => { if (commentForm.content) commentMut.mutate({ id: t.id, ...commentForm }); }} disabled={!commentForm.content || commentMut.isPending} className="px-3 py-1.5 rounded-lg bg-blue-600/20 border border-blue-500/20 text-xs font-semibold text-blue-400 disabled:opacity-40 hover:bg-blue-600/30">
                        <MessageSquare className="w-3 h-3" />
                      </button>
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
