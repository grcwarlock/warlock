import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ClipboardList, Clock, CheckCircle, XCircle,
  ChevronDown, ChevronRight, Filter, Plus, X, Loader2, User,
  MessageSquare
} from 'lucide-react';
import api from '../lib/api';

interface Comment {
  id: string;
  author: string;
  text: string;
  created_at: string;
}

interface Issue {
  id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  framework: string;
  control_id: string;
  assignee_email: string;
  assignee_name: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  due_date: string;
  comments: Comment[];
}

interface IssueStats {
  total: number;
  open: number;
  in_progress: number;
  resolved: number;
  closed: number;
  by_priority: Record<string, number>;
  by_framework: Record<string, number>;
  by_assignee: Record<string, number>;
}

interface TeamUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

const PRIORITY_CLASSES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/20',
  high:     'bg-orange-500/15 text-orange-400 border-orange-500/20',
  medium:   'bg-amber-500/15 text-amber-400 border-amber-500/20',
  low:      'bg-blue-500/15 text-blue-400 border-blue-500/20',
};

const STATUS_CLASSES: Record<string, string> = {
  open:        'bg-red-500/10 text-red-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  resolved:    'bg-emerald-500/10 text-emerald-400',
  closed:      'bg-slate-500/10 text-slate-400',
};

const FRAMEWORK_LABELS: Record<string, string> = {
  nist_800_53: 'NIST 800-53',
  soc2: 'SOC 2',
  iso_27001: 'ISO 27001',
  hipaa: 'HIPAA',
  cmmc_l2: 'CMMC L2',
};

export default function IssuesPage() {
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('');
  const [frameworkFilter, setFrameworkFilter] = useState('');
  const [assigneeFilter, setAssigneeFilter] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [assignDropdownId, setAssignDropdownId] = useState<string | null>(null);

  // Form state for create
  const [newIssue, setNewIssue] = useState({
    title: '', description: '', priority: 'medium', framework: '', control_id: '',
    assignee_email: '', assignee_name: '', due_date: '',
  });

  const { data: stats } = useQuery<IssueStats>({
    queryKey: ['issues', 'stats'],
    queryFn: async () => (await api.get('/issues/stats')).data,
  });

  const buildParams = () => {
    const p = new URLSearchParams();
    if (statusFilter) p.set('status', statusFilter);
    if (priorityFilter) p.set('priority', priorityFilter);
    if (frameworkFilter) p.set('framework', frameworkFilter);
    if (assigneeFilter) p.set('assignee', assigneeFilter);
    return p.toString();
  };

  const { data: issues, isLoading } = useQuery<Issue[]>({
    queryKey: ['issues', statusFilter, priorityFilter, frameworkFilter, assigneeFilter],
    queryFn: async () => {
      const params = buildParams();
      return (await api.get(`/issues${params ? '?' + params : ''}`)).data;
    },
  });

  const { data: users } = useQuery<TeamUser[]>({
    queryKey: ['auth', 'users'],
    queryFn: async () => (await api.get('/auth/users')).data,
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Record<string, string> }) =>
      (await api.put(`/issues/${id}`, data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['issues'] });
    },
  });

  const createMutation = useMutation({
    mutationFn: async (data: Record<string, string>) =>
      (await api.post('/issues', data)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['issues'] });
      setShowCreateModal(false);
      setNewIssue({ title: '', description: '', priority: 'medium', framework: '', control_id: '', assignee_email: '', assignee_name: '', due_date: '' });
    },
  });

  const changeStatus = (id: string, newStatus: string) => {
    updateMutation.mutate({ id, data: { status: newStatus } });
  };

  const assignUser = (issueId: string, user: TeamUser) => {
    updateMutation.mutate({ id: issueId, data: { assignee_email: user.email, assignee_name: user.full_name } });
    setAssignDropdownId(null);
  };

  const clearFilters = () => {
    setStatusFilter('');
    setPriorityFilter('');
    setFrameworkFilter('');
    setAssigneeFilter('');
  };

  const hasFilters = statusFilter || priorityFilter || frameworkFilter || assigneeFilter;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[var(--text-heading)] flex items-center gap-2">
            <ClipboardList className="w-5 h-5 text-blue-400" /> Issue Tracker
          </h2>
          <p className="text-slate-400 text-sm mt-0.5">Track and manage compliance remediation work items</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-bold text-[var(--text-heading)] transition-all shadow-lg shadow-blue-500/20"
        >
          <Plus className="w-4 h-4" /> Create Issue
        </button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Issues', value: stats?.total ?? 0, cls: 'text-slate-300', border: 'border-[var(--border-color)]', icon: ClipboardList, filterVal: '' },
          { label: 'Open', value: stats?.open ?? 0, cls: 'text-red-400', border: 'border-red-500/20', icon: XCircle, filterVal: 'open' },
          { label: 'In Progress', value: stats?.in_progress ?? 0, cls: 'text-amber-400', border: 'border-amber-500/20', icon: Clock, filterVal: 'in_progress' },
          { label: 'Resolved', value: stats?.resolved ?? 0, cls: 'text-emerald-400', border: 'border-emerald-500/20', icon: CheckCircle, filterVal: 'resolved' },
        ].map(c => {
          const Icon = c.icon;
          const isActive = statusFilter === c.filterVal && c.filterVal !== '';
          return (
            <button key={c.label} onClick={() => setStatusFilter(statusFilter === c.filterVal ? '' : c.filterVal)} className={`bg-[var(--bg-surface)] border ${c.border} rounded-2xl p-4 text-left cursor-pointer hover:bg-[var(--bg-interactive)] transition-all ${isActive ? 'ring-1 ring-[var(--border-color-hover)] scale-[1.02]' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-500">{c.label}</span>
                <Icon className={`w-4 h-4 ${c.cls}`} />
              </div>
              <p className={`text-2xl font-extrabold ${c.cls}`}>{c.value}</p>
            </button>
          );
        })}
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl px-4 py-3">
        <Filter className="w-3.5 h-3.5 text-slate-500" />
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500/40">
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
        <select value={priorityFilter} onChange={e => setPriorityFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500/40">
          <option value="">All Priorities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={frameworkFilter} onChange={e => setFrameworkFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500/40">
          <option value="">All Frameworks</option>
          <option value="nist_800_53">NIST 800-53</option>
          <option value="soc2">SOC 2</option>
          <option value="iso_27001">ISO 27001</option>
          <option value="hipaa">HIPAA</option>
          <option value="cmmc_l2">CMMC L2</option>
        </select>
        <select value={assigneeFilter} onChange={e => setAssigneeFilter(e.target.value)} className="bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500/40">
          <option value="">All Assignees</option>
          {(users ?? []).map(u => (
            <option key={u.id} value={u.full_name}>{u.full_name}</option>
          ))}
        </select>
        {hasFilters && (
          <button onClick={clearFilters} className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 ml-auto transition-colors">
            <X className="w-3 h-3" /> Clear
          </button>
        )}
      </div>

      {/* Issues list */}
      <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl overflow-hidden">
        {isLoading ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <Loader2 className="w-7 h-7 animate-spin" />
            <p className="text-sm">Loading issues...</p>
          </div>
        ) : !issues || issues.length === 0 ? (
          <div className="py-16 flex flex-col items-center gap-3 text-slate-500">
            <CheckCircle className="w-10 h-10 text-emerald-500/40" />
            <p className="text-sm font-semibold">No issues found</p>
            <p className="text-xs">Create an issue or adjust filters</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {/* Table header */}
            <div className="hidden sm:grid grid-cols-[1fr_100px_100px_140px_100px_100px] gap-4 px-5 py-2.5 text-[10px] font-bold text-slate-600 uppercase tracking-wider bg-[var(--bg-subtle)]">
              <span>Title</span>
              <span>Priority</span>
              <span>Framework</span>
              <span>Assignee</span>
              <span>Status</span>
              <span>Due Date</span>
            </div>

            {issues.map((issue) => {
              const isExpanded = expandedId === issue.id;
              return (
                <div key={issue.id}>
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : issue.id)}
                    className="w-full text-left px-5 py-3.5 hover:bg-[var(--bg-subtle)] transition-colors"
                  >
                    <div className="sm:grid grid-cols-[1fr_100px_100px_140px_100px_100px] gap-4 items-center">
                      <div className="flex items-center gap-2 min-w-0">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />}
                        <span className="font-mono text-[10px] font-bold bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 px-1.5 py-0.5 rounded flex-shrink-0">{issue.control_id}</span>
                        <span className="text-sm text-[var(--text-heading)] font-medium truncate">{issue.title}</span>
                      </div>
                      <div>
                        <button onClick={(e) => { e.stopPropagation(); setPriorityFilter(priorityFilter === issue.priority ? '' : issue.priority); }} className={`${PRIORITY_CLASSES[issue.priority] ?? ''} text-[10px] font-bold px-1.5 py-0.5 rounded border capitalize cursor-pointer hover:brightness-125 transition-all`}>
                          {issue.priority}
                        </button>
                      </div>
                      <div><button onClick={(e) => { e.stopPropagation(); setFrameworkFilter(frameworkFilter === issue.framework ? '' : issue.framework); }} className="text-xs text-slate-400 hover:text-blue-400 cursor-pointer transition-colors">{FRAMEWORK_LABELS[issue.framework] ?? issue.framework}</button></div>
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
                          <User className="w-3 h-3 text-blue-400" />
                        </div>
                        <button onClick={(e) => { e.stopPropagation(); setAssigneeFilter(assigneeFilter === issue.assignee_name ? '' : issue.assignee_name); }} className="text-xs text-slate-300 truncate hover:text-blue-400 cursor-pointer transition-colors">{issue.assignee_name || 'Unassigned'}</button>
                      </div>
                      <div>
                        <button onClick={(e) => { e.stopPropagation(); setStatusFilter(statusFilter === issue.status ? '' : issue.status); }} className={`${STATUS_CLASSES[issue.status] ?? ''} text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize cursor-pointer hover:brightness-125 transition-all`}>
                          {issue.status.replace('_', ' ')}
                        </button>
                      </div>
                      <div className="text-xs text-slate-500">
                        {issue.due_date ? new Date(issue.due_date).toLocaleDateString() : '--'}
                      </div>
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="px-5 pb-5 bg-[var(--bg-subtle)] space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {issue.description && (
                          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-4">
                            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Description</p>
                            <p className="text-xs text-slate-300 leading-relaxed">{issue.description}</p>
                          </div>
                        )}
                        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-4 space-y-3">
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Details</p>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div><span className="text-slate-600">Framework: </span><span className="text-slate-300">{FRAMEWORK_LABELS[issue.framework] ?? issue.framework}</span></div>
                            <div><span className="text-slate-600">Control: </span><span className="text-slate-300 font-mono">{issue.control_id}</span></div>
                            <div><span className="text-slate-600">Created: </span><span className="text-slate-300">{new Date(issue.created_at).toLocaleDateString()}</span></div>
                            <div><span className="text-slate-600">Updated: </span><span className="text-slate-300">{new Date(issue.updated_at).toLocaleDateString()}</span></div>
                          </div>
                        </div>
                      </div>

                      {/* Comments */}
                      {issue.comments.length > 0 && (
                        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl p-4">
                          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            <MessageSquare className="w-3.5 h-3.5 text-blue-400" /> Comments ({issue.comments.length})
                          </p>
                          <div className="space-y-2">
                            {issue.comments.map(c => (
                              <div key={c.id} className="bg-[var(--bg-subtle)] border border-[var(--border-subtle)] rounded-lg px-3 py-2">
                                <div className="flex items-center gap-2 mb-1">
                                  <span className="text-xs font-semibold text-slate-300">{c.author}</span>
                                  <span className="text-[10px] text-slate-600">{new Date(c.created_at).toLocaleString()}</span>
                                </div>
                                <p className="text-xs text-slate-400">{c.text}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Action buttons */}
                      <div className="flex items-center gap-2 flex-wrap">
                        {issue.status === 'open' && (
                          <button onClick={() => changeStatus(issue.id, 'in_progress')} className="px-3 py-1.5 text-xs font-semibold bg-amber-500/10 border border-amber-500/20 text-amber-400 rounded-lg hover:bg-amber-500/20 transition-colors">
                            Start Progress
                          </button>
                        )}
                        {issue.status === 'in_progress' && (
                          <button onClick={() => changeStatus(issue.id, 'resolved')} className="px-3 py-1.5 text-xs font-semibold bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-colors">
                            Mark Resolved
                          </button>
                        )}
                        {issue.status === 'resolved' && (
                          <button onClick={() => changeStatus(issue.id, 'closed')} className="px-3 py-1.5 text-xs font-semibold bg-slate-500/10 border border-slate-500/20 text-slate-400 rounded-lg hover:bg-slate-500/20 transition-colors">
                            Close Issue
                          </button>
                        )}
                        {(issue.status === 'resolved' || issue.status === 'closed') && (
                          <button onClick={() => changeStatus(issue.id, 'open')} className="px-3 py-1.5 text-xs font-semibold bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg hover:bg-red-500/20 transition-colors">
                            Reopen
                          </button>
                        )}
                        <div className="relative">
                          <button
                            onClick={() => setAssignDropdownId(assignDropdownId === issue.id ? null : issue.id)}
                            className="px-3 py-1.5 text-xs font-semibold bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/20 transition-colors flex items-center gap-1"
                          >
                            <User className="w-3 h-3" /> Assign
                          </button>
                          {assignDropdownId === issue.id && (
                            <div className="absolute top-full left-0 mt-1 w-56 bg-[var(--bg-elevated)] border border-[var(--border-color)] rounded-xl shadow-2xl shadow-black/60 z-50 py-1 max-h-48 overflow-auto">
                              {(users ?? []).map(u => (
                                <button
                                  key={u.id}
                                  onClick={() => assignUser(issue.id, u)}
                                  className="w-full text-left px-3 py-2 text-xs text-slate-300 hover:bg-[var(--bg-interactive)] flex items-center gap-2 transition-colors"
                                >
                                  <div className="w-5 h-5 rounded-full bg-gradient-to-br from-blue-600/30 to-violet-600/20 border border-blue-500/30 flex items-center justify-center">
                                    <User className="w-2.5 h-2.5 text-blue-400" />
                                  </div>
                                  <div>
                                    <div className="font-medium">{u.full_name}</div>
                                    <div className="text-[10px] text-slate-500">{u.email}</div>
                                  </div>
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Create Issue Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setShowCreateModal(false)}>
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="px-5 py-4 border-b border-[var(--border-color)] flex items-center justify-between">
              <h3 className="text-sm font-bold text-[var(--text-heading)] flex items-center gap-2">
                <Plus className="w-4 h-4 text-blue-400" /> Create Issue
              </h3>
              <button onClick={() => setShowCreateModal(false)} className="p-1.5 hover:bg-[var(--bg-interactive-hover)] rounded-lg transition-colors">
                <X className="w-4 h-4 text-slate-500" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Title</label>
                <input
                  value={newIssue.title}
                  onChange={e => setNewIssue(p => ({ ...p, title: e.target.value }))}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/40"
                  placeholder="Issue title..."
                />
              </div>
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Description</label>
                <textarea
                  value={newIssue.description}
                  onChange={e => setNewIssue(p => ({ ...p, description: e.target.value }))}
                  rows={3}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/40 resize-none"
                  placeholder="Describe the issue..."
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Priority</label>
                  <select value={newIssue.priority} onChange={e => setNewIssue(p => ({ ...p, priority: e.target.value }))} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500/40">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Framework</label>
                  <select value={newIssue.framework} onChange={e => setNewIssue(p => ({ ...p, framework: e.target.value }))} className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500/40">
                    <option value="">Select...</option>
                    <option value="nist_800_53">NIST 800-53</option>
                    <option value="soc2">SOC 2</option>
                    <option value="iso_27001">ISO 27001</option>
                    <option value="hipaa">HIPAA</option>
                    <option value="cmmc_l2">CMMC L2</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Control ID</label>
                  <input
                    value={newIssue.control_id}
                    onChange={e => setNewIssue(p => ({ ...p, control_id: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--text-heading)] focus:outline-none focus:border-blue-500/40"
                    placeholder="e.g. AC-2"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Due Date</label>
                  <input
                    type="date"
                    value={newIssue.due_date}
                    onChange={e => setNewIssue(p => ({ ...p, due_date: e.target.value }))}
                    className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500/40"
                  />
                </div>
              </div>
              <div>
                <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Assignee</label>
                <select
                  value={newIssue.assignee_email}
                  onChange={e => {
                    const u = (users ?? []).find(u => u.email === e.target.value);
                    setNewIssue(p => ({ ...p, assignee_email: e.target.value, assignee_name: u?.full_name ?? '' }));
                  }}
                  className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-blue-500/40"
                >
                  <option value="">Unassigned</option>
                  {(users ?? []).map(u => (
                    <option key={u.id} value={u.email}>{u.full_name} ({u.email})</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="px-5 py-4 border-t border-[var(--border-color)] flex justify-end gap-2">
              <button onClick={() => setShowCreateModal(false)} className="px-4 py-2 text-xs font-semibold bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] text-slate-300 rounded-xl transition-colors">
                Cancel
              </button>
              <button
                onClick={() => createMutation.mutate(newIssue)}
                disabled={!newIssue.title || createMutation.isPending}
                className="px-4 py-2 text-xs font-bold bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-[var(--text-heading)] rounded-xl transition-all disabled:opacity-40"
              >
                {createMutation.isPending ? 'Creating...' : 'Create Issue'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
