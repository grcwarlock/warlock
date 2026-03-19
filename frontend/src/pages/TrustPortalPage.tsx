import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Shield, CheckCircle, Clock, Award, FileText,
  Mail, Building, User, Globe, ExternalLink,
  TrendingUp, Lock, ArrowRight, Sparkles
} from 'lucide-react';
import api from '../lib/api';

export default function TrustPortalPage() {
  const [form, setForm] = useState({ name: '', email: '', company: '', reason: '' });
  const [submitted, setSubmitted] = useState(false);
  const [requestingReport, setRequestingReport] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['trust-public'],
    queryFn: async () => (await api.get('/trust/public')).data,
  });

  const submitMutation = useMutation({
    mutationFn: async (payload: typeof form & { report_id: string }) =>
      (await api.post('/trust/access-request', payload)).data,
    onSuccess: () => { setSubmitted(true); setRequestingReport(null); },
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[var(--bg-base)] flex items-center justify-center">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  const config = data?.config ?? {};
  const certifications = data?.certifications ?? [];
  const frameworkStatus: any[] = data?.framework_status ?? [];
  const reports: any[] = data?.available_reports ?? [];

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-heading)]">
      {/* Background blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-20 w-[600px] h-[600px] bg-blue-600/8 rounded-full blur-[120px]" />
        <div className="absolute top-1/3 right-0 w-[400px] h-[400px] bg-emerald-600/8 rounded-full blur-[100px]" />
        <div className="absolute bottom-0 left-1/3 w-[500px] h-[400px] bg-violet-600/8 rounded-full blur-[100px]" />
      </div>

      {/* Nav */}
      <nav className="relative z-10 flex items-center justify-between px-6 md:px-16 py-5 border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center shadow-lg shadow-blue-500/25">
            <Shield className="w-4 h-4 text-[var(--text-heading)]" />
          </div>
          <div>
            <span className="text-base font-bold bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">Warlock</span>
            <span className="ml-2 text-xs text-slate-500">/ Trust Hub</span>
          </div>
        </div>
        <a href="/" className="text-xs text-slate-400 hover:text-[var(--text-heading)] flex items-center gap-1 transition-colors">
          <ExternalLink className="w-3.5 h-3.5" /> Back to Site
        </a>
      </nav>

      {/* Hero */}
      <section className="relative z-10 text-center px-6 pt-20 pb-16 max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium mb-8">
          <Sparkles className="w-3.5 h-3.5" />
          {config.published ? 'Security Portal — Live & Verified' : 'Security Portal — Preview'}
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-5 leading-tight">
          Warlock<br />
          <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">Trust Hub</span>
        </h1>
        <p className="text-slate-400 text-lg max-w-xl mx-auto leading-relaxed">
          {config.description || 'Real-time compliance posture, certifications, and security documentation. Everything your security team needs — in one place.'}
        </p>
      </section>

      {/* Live framework status */}
      <section className="relative z-10 px-6 max-w-5xl mx-auto mb-16">
        <div className="flex items-center gap-2 mb-5">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Live Compliance Status</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {frameworkStatus.length > 0 ? frameworkStatus.map((fw: any) => (
            <div key={fw.framework} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-4 hover:bg-[var(--bg-interactive-hover)] transition-all">
              <div className="flex items-center justify-between mb-3">
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                  fw.pass_rate >= 80 ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                  fw.pass_rate >= 60 ? 'bg-amber-500/15 text-amber-400 border-amber-500/20' :
                  'bg-red-500/15 text-red-400 border-red-500/20'
                }`}>
                  {fw.pass_rate?.toFixed(0) ?? '--'}%
                </span>
                {fw.trend === 'up' && <TrendingUp className="w-3.5 h-3.5 text-emerald-400" />}
              </div>
              <h3 className="font-semibold text-[var(--text-heading)] text-sm leading-tight mb-0.5">{fw.display_name}</h3>
              <p className="text-[10px] text-slate-500">{fw.passing}/{fw.total_controls} controls</p>
              <div className="mt-3 h-1 bg-[var(--bg-interactive)] rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${fw.pass_rate >= 80 ? 'bg-emerald-500' : fw.pass_rate >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                  style={{ width: `${fw.pass_rate ?? 0}%` }}
                />
              </div>
            </div>
          )) : (
            <div className="col-span-5 text-center py-8 text-slate-500 text-sm">No framework data available</div>
          )}
        </div>
      </section>

      {/* Certifications */}
      {certifications.length > 0 && (
        <section className="relative z-10 px-6 max-w-5xl mx-auto mb-16">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5">Certifications & Audits</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {certifications.map((cert: any) => (
              <div key={cert.id} className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl p-5 hover:bg-[var(--bg-interactive-hover)] transition-all">
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500/20 to-violet-500/10 border border-blue-500/20 flex items-center justify-center">
                    <Award className="w-5 h-5 text-blue-400" />
                  </div>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                    cert.status === 'active' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/20' :
                    cert.status === 'in_progress' ? 'bg-blue-500/15 text-blue-400 border-blue-500/20' :
                    'bg-amber-500/15 text-amber-400 border-amber-500/20'
                  } capitalize`}>{cert.status?.replace('_', ' ')}</span>
                </div>
                <h3 className="font-bold text-[var(--text-heading)] mb-1">{cert.name}</h3>
                <p className="text-xs text-slate-500 mb-2">{cert.issuer}</p>
                {cert.valid_until && (
                  <p className="text-xs text-slate-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Valid until {new Date(cert.valid_until).toLocaleDateString()}
                  </p>
                )}
                {cert.report_available && (
                  <button
                    onClick={() => setRequestingReport(cert.id)}
                    className="mt-3 w-full flex items-center justify-center gap-1.5 py-2 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-xs font-medium text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors"
                  >
                    <FileText className="w-3.5 h-3.5" /> Request Report
                  </button>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Available reports */}
      {reports.length > 0 && (
        <section className="relative z-10 px-6 max-w-5xl mx-auto mb-16">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-5">Security Documentation</h2>
          <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-xl overflow-hidden">
            {reports.map((report: any, i: number) => (
              <div key={report.id} className={`flex items-center justify-between px-5 py-4 hover:bg-[var(--bg-interactive)] transition-colors ${i < reports.length - 1 ? 'border-b border-[var(--border-subtle)]' : ''}`}>
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-blue-500/15 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                    <Lock className="w-4 h-4 text-blue-400" />
                  </div>
                  <div>
                    <p className="font-medium text-[var(--text-heading)] text-sm">{report.title}</p>
                    <p className="text-xs text-slate-500">{report.description}</p>
                  </div>
                </div>
                <button
                  onClick={() => setRequestingReport(report.id)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--bg-interactive)] border border-[var(--border-color)] text-xs font-medium text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors flex-shrink-0"
                >
                  Request Access <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Access Request Form */}
      {requestingReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setRequestingReport(null)} />
          <div className="relative bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-2xl p-8 w-full max-w-md shadow-2xl">
            {submitted ? (
              <div className="text-center py-4">
                <div className="w-12 h-12 rounded-full bg-emerald-500/15 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4">
                  <CheckCircle className="w-6 h-6 text-emerald-400" />
                </div>
                <h3 className="font-bold text-[var(--text-heading)] text-lg mb-2">Request Submitted</h3>
                <p className="text-slate-400 text-sm">We'll send the report to {form.email} within 1 business day.</p>
                <button onClick={() => { setSubmitted(false); setRequestingReport(null); }} className="mt-5 px-5 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors">
                  Close
                </button>
              </div>
            ) : (
              <>
                <h3 className="font-bold text-[var(--text-heading)] text-lg mb-1">Request Security Report</h3>
                <p className="text-slate-400 text-sm mb-6">Fill in your details and we'll send you the report.</p>
                <div className="space-y-4">
                  {[
                    { key: 'name', label: 'Full Name', icon: User, placeholder: 'Jane Smith' },
                    { key: 'email', label: 'Work Email', icon: Mail, placeholder: 'jane@company.com' },
                    { key: 'company', label: 'Company', icon: Building, placeholder: 'Warlock Compliance' },
                  ].map(({ key, label, icon: Icon, placeholder }) => (
                    <div key={key}>
                      <label className="block text-xs font-medium text-slate-400 mb-1.5">{label}</label>
                      <div className="relative">
                        <Icon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
                        <input
                          type={key === 'email' ? 'email' : 'text'}
                          value={(form as any)[key]}
                          onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
                          placeholder={placeholder}
                          className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl pl-10 pr-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30"
                        />
                      </div>
                    </div>
                  ))}
                  <div>
                    <label className="block text-xs font-medium text-slate-400 mb-1.5">Reason for Request</label>
                    <textarea
                      value={form.reason}
                      onChange={e => setForm(p => ({ ...p, reason: e.target.value }))}
                      rows={3}
                      placeholder="Security assessment, vendor evaluation, compliance due diligence…"
                      className="w-full bg-[var(--bg-interactive)] border border-[var(--border-color)] rounded-xl px-4 py-2.5 text-sm text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/30 resize-none"
                    />
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button onClick={() => setRequestingReport(null)} className="flex-1 py-2.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] text-sm font-medium text-slate-300 hover:bg-[var(--bg-interactive-hover)] transition-colors">
                    Cancel
                  </button>
                  <button
                    onClick={() => submitMutation.mutate({ ...form, report_id: requestingReport })}
                    disabled={!form.name || !form.email || !form.company}
                    className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 text-sm font-semibold text-[var(--text-heading)] transition-all disabled:opacity-40 shadow-lg shadow-blue-500/20"
                  >
                    Submit Request
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="relative z-10 border-t border-[var(--border-subtle)] px-6 py-8 mt-10">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded-md bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-[var(--text-heading)]" />
            </div>
            <span className="text-sm font-semibold bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">
              Warlock
            </span>
          </div>
          <p className="text-xs text-slate-600 flex items-center gap-1">
            <Globe className="w-3.5 h-3.5" />
            {config.contact_email || 'security@company.com'}
          </p>
          <p className="text-xs text-slate-600">
            Data refreshed continuously · Powered by Warlock
          </p>
        </div>
      </footer>
    </div>
  );
}
