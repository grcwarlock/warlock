import { useQuery } from '@tanstack/react-query';
import { Shield, CheckCircle, AlertTriangle, XCircle, Activity, Server, Clock, ChevronRight, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import api from '../lib/api';

interface FrameworkSummary {
  framework: string;
  display_name: string;
  total_controls: number;
  passing: number;
  medium: number;
  critical: number;
  pass_rate: number;
  last_run: string | null;
}

interface DashboardSummary {
  total_controls: number;
  passing: number;
  medium: number;
  critical: number;
  overall_pass_rate: number;
  total_evidence: number;
  open_violations: number;
  vendor_count: number;
  high_risk_vendors: number;
  frameworks: FrameworkSummary[];
  integrations: {
    id: string; name: string; provider: string; source_type: string;
    is_active: boolean; last_sync_at: string | null; last_sync_status: string;
  }[];
  recent_activity: {
    type: string; framework: string; display_name: string;
    status: string; pass_rate: number | null; timestamp: string;
  }[];
  last_updated: string;
}

export default function DashboardPage() {
  const { data, isLoading, error } = useQuery<DashboardSummary>({
    queryKey: ['dashboard', 'summary'],
    queryFn: async () => (await api.get('/dashboard/summary')).data,
    refetchInterval: 30000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-500">
        <AlertTriangle className="w-12 h-12 text-red-400 mb-4" />
        <h2 className="text-xl font-semibold text-slate-300">Failed to load dashboard</h2>
        <p className="mt-2 text-sm">Check your connection and try again.</p>
      </div>
    );
  }

  const overallRate = data.total_controls > 0
    ? Math.round((data.passing / data.total_controls) * 100) : 0;

  return (
    <div className="space-y-5 page-enter text-[var(--text-heading)]">
      {/* Top stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Controls', value: data.total_controls, sub: 'Across all frameworks', icon: Shield, to: '/frameworks', cls: 'text-blue-400', border: 'border-blue-500/20', bg: 'bg-blue-500/10' },
          { label: 'Passing', value: data.passing, sub: `${overallRate}% compliance`, icon: CheckCircle, to: '/frameworks', cls: 'text-emerald-400', border: 'border-emerald-500/20', bg: 'bg-emerald-500/10' },
          { label: 'Medium Risk', value: data.medium, sub: 'Need attention', icon: AlertTriangle, to: '/frameworks?filter=medium', cls: 'text-amber-400', border: 'border-amber-500/20', bg: 'bg-amber-500/10' },
          { label: 'Critical', value: data.critical, sub: 'Immediate action', icon: XCircle, to: '/frameworks?filter=critical', cls: 'text-red-400', border: 'border-red-500/20', bg: 'bg-red-500/10' },
        ].map(card => {
          const Icon = card.icon;
          return (
            <Link key={card.label} to={card.to} className={`bg-[var(--bg-surface)] border ${card.border} rounded-2xl p-5 hover:bg-[var(--bg-interactive)] transition-all group`}>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{card.label}</h3>
                <div className={`p-2 ${card.bg} rounded-xl`}>
                  <Icon className={`w-4 h-4 ${card.cls}`} />
                </div>
              </div>
              <div className={`text-3xl font-bold ${card.cls}`}>{card.value.toLocaleString()}</div>
              <p className={`text-xs mt-1 font-medium flex items-center gap-1 ${card.cls}`}>
                {card.sub} <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
              </p>
            </Link>
          );
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Framework compliance */}
        <div className="xl:col-span-2 space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Framework Compliance</h2>
            <Link to="/frameworks" className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1 transition-colors">
              View all <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="space-y-3">
            {data.frameworks.map(fw => (
              <Link
                key={fw.framework}
                to={`/frameworks?fw=${fw.framework}`}
                className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5 hover:border-[var(--border-color-hover)] hover:bg-[var(--bg-subtle)] transition-all group block"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
                  <div className="flex items-center gap-3">
                    <div className={`w-1.5 h-10 rounded-full flex-shrink-0 ${
                      fw.pass_rate >= 80 ? 'bg-emerald-500' :
                      fw.pass_rate >= 60 ? 'bg-amber-500' : 'bg-red-500'
                    }`} />
                    <div>
                      <h3 className="font-bold text-[var(--text-heading)] text-sm group-hover:text-blue-400 transition-colors">{fw.display_name}</h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        {fw.last_run ? `Assessed ${new Date(fw.last_run).toLocaleDateString()}` : 'Never assessed'}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />{fw.passing} Pass
                    </span>
                    {fw.medium > 0 && (
                      <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />{fw.medium} Med
                      </span>
                    )}
                    {fw.critical > 0 && (
                      <span className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-red-500/15 text-red-400 border border-red-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-500" />{fw.critical} Crit
                      </span>
                    )}
                    <span className={`text-sm font-extrabold ml-1 ${
                      fw.pass_rate >= 80 ? 'text-emerald-400' :
                      fw.pass_rate >= 60 ? 'text-amber-400' : 'text-red-400'
                    }`}>{fw.pass_rate.toFixed(1)}%</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all" />
                  </div>
                </div>
                <div className="h-1.5 w-full bg-[var(--bg-interactive)] rounded-full overflow-hidden flex">
                  {fw.total_controls > 0 && (
                    <>
                      <div className="h-full bg-emerald-500" style={{ width: `${(fw.passing / fw.total_controls) * 100}%` }} />
                      <div className="h-full bg-amber-400" style={{ width: `${(fw.medium / fw.total_controls) * 100}%` }} />
                      <div className="h-full bg-red-500" style={{ width: `${(fw.critical / fw.total_controls) * 100}%` }} />
                    </>
                  )}
                </div>
                <div className="flex justify-between mt-1.5 text-[10px] text-slate-600">
                  <span>{fw.passing} passing</span>
                  <span>{fw.total_controls} total</span>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Right sidebar */}
        <div className="space-y-4">
          {/* Recent Activity */}
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[var(--border-subtle)]">
              <Activity className="w-4 h-4 text-slate-500" />
              <h2 className="font-bold text-[var(--text-heading)] text-sm">Recent Activity</h2>
            </div>
            <div className="space-y-1">
              {data.recent_activity.length > 0 ? data.recent_activity.map((activity, i) => (
                <Link
                  key={i}
                  to={`/frameworks?fw=${activity.framework}`}
                  className="flex gap-3 hover:bg-[var(--bg-subtle)] -mx-2 px-2 py-2 rounded-xl transition-colors group"
                >
                  <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${
                    activity.status === 'completed' ? 'bg-emerald-500' :
                    activity.status === 'failed' ? 'bg-red-500' : 'bg-blue-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-300">
                      Assessment — <span className="font-semibold text-[var(--text-heading)]">{activity.display_name}</span>
                    </p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-slate-600 flex items-center gap-1">
                        <Clock className="w-3 h-3" />{new Date(activity.timestamp).toLocaleDateString()}
                      </span>
                      {activity.pass_rate != null && (
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          activity.pass_rate >= 80 ? 'bg-emerald-500/15 text-emerald-400' :
                          activity.pass_rate >= 60 ? 'bg-amber-500/15 text-amber-400' :
                          'bg-red-500/15 text-red-400'
                        }`}>{activity.pass_rate}%</span>
                      )}
                    </div>
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-slate-700 group-hover:text-blue-400 transition-colors flex-shrink-0 mt-1" />
                </Link>
              )) : (
                <p className="text-xs text-slate-600 text-center py-4">No recent activity</p>
              )}
            </div>
          </div>

          {/* Integrations */}
          <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-5">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[var(--border-subtle)]">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-500" />
                <h2 className="font-bold text-[var(--text-heading)] text-sm">Integrations</h2>
              </div>
              <Link to="/integrations" className="text-[10px] text-blue-400 hover:text-blue-300 font-medium transition-colors">Manage →</Link>
            </div>
            <div className="space-y-1">
              {data.integrations.length > 0 ? data.integrations.map(integration => (
                <Link
                  key={integration.id}
                  to="/integrations"
                  className="flex items-center justify-between py-1.5 px-2 hover:bg-[var(--bg-subtle)] rounded-xl transition-colors"
                >
                  <div className="flex items-center gap-2.5">
                    <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                      integration.last_sync_status === 'success' ? 'bg-emerald-500' :
                      integration.last_sync_status === 'error' ? 'bg-red-500' : 'bg-amber-500'
                    }`} />
                    <div>
                      <p className="text-xs font-medium text-slate-300 leading-tight">{integration.name}</p>
                      <p className="text-[10px] text-slate-600">{integration.provider}</p>
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-600">
                    {integration.last_sync_at ? new Date(integration.last_sync_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Never'}
                  </span>
                </Link>
              )) : (
                <p className="text-xs text-slate-600 text-center py-4">No integrations connected</p>
              )}
            </div>
          </div>

          {/* Mini stat cards */}
          <div className="grid grid-cols-2 gap-3">
            <Link to="/vendors" className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4 hover:border-[var(--border-color-hover)] hover:bg-[var(--bg-subtle)] transition-all">
              <div className="text-2xl font-extrabold text-[var(--text-heading)]">{data.vendor_count}</div>
              <div className="text-xs text-slate-500 mt-0.5">Vendors</div>
              {data.high_risk_vendors > 0 && (
                <div className="text-xs text-amber-400 font-medium mt-1">{data.high_risk_vendors} high risk</div>
              )}
            </Link>
            <Link to="/evidence" className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-4 hover:border-[var(--border-color-hover)] hover:bg-[var(--bg-subtle)] transition-all">
              <div className="text-2xl font-extrabold text-[var(--text-heading)]">{data.total_evidence.toLocaleString()}</div>
              <div className="text-xs text-slate-500 mt-0.5">Evidence</div>
              <div className="text-xs text-blue-400 font-medium mt-1">View all →</div>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
