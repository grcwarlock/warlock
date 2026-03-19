import { useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield, Zap, Eye, FileCheck, Database, Globe,
  ChevronRight, CheckCircle, ArrowRight, BarChart3,
  Layers, Users, Sparkles, TrendingUp, Lock, ExternalLink
} from 'lucide-react';

const FRAMEWORKS = [
  { id: 'iso_27001', label: 'ISO 27001', slug: 'iso-27001' },
  { id: 'soc2',    label: 'SOC 2',     slug: 'soc-2' },
  { id: 'nist_800_53', label: 'NIST 800-53', slug: 'nist-800-53' },
  { id: 'hipaa',   label: 'HIPAA',     slug: 'hipaa' },
  { id: 'cmmc_l2', label: 'CMMC L2',   slug: 'cmmc-l2' },
];

const FEATURES = [
  {
    icon: BarChart3,
    color: 'from-blue-500 to-cyan-400',
    glow: 'rgba(59,130,246,0.25)',
    title: 'Real-Time Compliance Monitoring',
    desc: 'See every control across NIST 800-53, SOC 2, ISO 27001, HIPAA, and CMMC L2 on one screen — green, yellow, or red. Click any failing control and get exact remediation steps, linked evidence, and ticket creation in under 30 seconds.',
    link: '/features/compliance-monitoring',
    linkLabel: 'Learn more',
    badge: '655 controls',
  },
  {
    icon: Zap,
    color: 'from-violet-500 to-purple-400',
    glow: 'rgba(139,92,246,0.25)',
    title: '38 Native Integrations',
    desc: 'Wire up AWS, CrowdStrike, Okta, Splunk, Tenable, and 33 more tools with an API key. Findings flow in automatically — mapped to the right control families across every framework simultaneously. No CSV exports, no screenshots, no manual uploads.',
    link: '/features/integrations',
    linkLabel: 'Learn more',
    badge: '38 tools',
  },
  {
    icon: FileCheck,
    color: 'from-emerald-500 to-teal-400',
    glow: 'rgba(16,185,129,0.25)',
    title: 'Automated POAM & Audit Exports',
    desc: 'Every failing control automatically generates a Plan of Action & Milestones entry with risk rating, timeline, and remediation owner. Export a complete audit package — NIST, SOC 2, or HIPAA formatted — in a single click. No more last-minute scrambles before auditor day.',
    link: '/features/poam-audit-exports',
    linkLabel: 'Learn more',
    badge: 'Audit-ready',
  },
  {
    icon: Database,
    color: 'from-amber-500 to-orange-400',
    glow: 'rgba(245,158,11,0.25)',
    title: 'Data Silo Scanning',
    desc: 'Automatically surface PII, PHI, API secrets, and sensitive data scattered across S3 buckets, GitHub repos, SharePoint sites, and databases. Every finding is mapped directly to the control it violates — so you know exactly what to fix and why it matters.',
    link: '/features/data-silo-scanning',
    linkLabel: 'Learn more',
    badge: 'PII & PHI detection',
  },
  {
    icon: Globe,
    color: 'from-pink-500 to-rose-400',
    glow: 'rgba(236,72,153,0.25)',
    title: 'Customer Trust Hub',
    desc: 'Publish a live, public-facing security portal in minutes. Show real-time pass rates, certification status, and audit summaries — no NDA required. When a prospect or enterprise customer asks "do you have a SOC 2?", send them a link instead of a PDF.',
    link: '/features/trust-hub',
    linkLabel: 'Learn more',
    badge: 'Public · No login',
  },
  {
    icon: Eye,
    color: 'from-sky-500 to-indigo-400',
    glow: 'rgba(14,165,233,0.25)',
    title: 'Third-Party Risk Management',
    desc: 'Score every vendor in your supply chain against your own compliance requirements. Send automated security questionnaires, track response status, flag gaps, and monitor posture changes over time. Know your fourth-party risk before your auditor does.',
    link: '/features/vendor-risk-management',
    linkLabel: 'Learn more',
    badge: 'Supply chain',
  },
];

const STATS = [
  { value: '655', label: 'Controls', sub: 'Across all 5 frameworks' },
  { value: '38', label: 'Integrations', sub: 'AWS · CrowdStrike · Okta · Splunk · more' },
  { value: '5', label: 'Frameworks', sub: 'NIST · SOC 2 · ISO · HIPAA · CMMC' },
  { value: '100%', label: 'Audit-ready', sub: 'Evidence collected continuously' },
];

const HOW_IT_WORKS = [
  { step: '01', title: 'Connect your tools', desc: 'Add an API key for AWS, CrowdStrike, Okta, or any of 35 other integrations. Findings start mapping to controls immediately — zero configuration required.', icon: Zap },
  { step: '02', title: 'Controls get assessed automatically', desc: 'Every connected tool continuously checks the controls it owns. A CrowdStrike finding maps to SI-3. A missing MFA maps to IA-2. No spreadsheet, no manual work.', icon: BarChart3 },
  { step: '03', title: 'Fix what matters first', desc: 'Failing controls surface with severity, impacted assets, exact remediation steps, and a one-click ticket to Jira or ServiceNow. Your team knows exactly what to do next.', icon: CheckCircle },
  { step: '04', title: 'Walk into any audit confident', desc: 'Export a POAM, full audit evidence package, or SOC 2 bridge letter in one click. Share your live Trust Hub with customers before they even ask.', icon: FileCheck },
];

function useScrollSpy(ids: string[]) {
  const activeRef = useRef<string>('');
  useEffect(() => {
    const obs = new IntersectionObserver(
      entries => { entries.forEach(e => { if (e.isIntersecting) activeRef.current = e.target.id; }); },
      { threshold: 0.3 }
    );
    ids.forEach(id => { const el = document.getElementById(id); if (el) obs.observe(el); });
    return () => obs.disconnect();
  }, [ids]);
}

export default function LandingPage() {
  const navigate = useNavigate();
  useScrollSpy(['hero', 'features', 'how-it-works', 'frameworks', 'trust']);

  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-heading)] overflow-x-hidden">
      {/* Background blobs — hidden on mobile to avoid iOS Safari GPU stall */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none hidden md:block" aria-hidden="true">
        <div className="absolute -top-40 -left-40 w-[600px] h-[600px] bg-blue-600/8 rounded-full blur-[120px]" />
        <div className="absolute top-1/3 -right-40 w-[500px] h-[500px] bg-violet-600/8 rounded-full blur-[100px]" />
        <div className="absolute bottom-0 left-1/4 w-[500px] h-[400px] bg-cyan-600/6 rounded-full blur-[100px]" />
      </div>

      {/* Nav */}
      <nav className="relative z-20 flex items-center justify-between px-5 md:px-16 py-4 border-b border-[var(--border-subtle)] sticky top-0 bg-[var(--bg-base)]/80 backdrop-blur-sm md:backdrop-blur-[12px]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center shadow-lg shadow-blue-500/30 flex-shrink-0">
            <Shield className="w-4 h-4 text-[var(--text-heading)]" />
          </div>
          <span className="text-base font-bold tracking-tight">
            <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent" style={{ WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Warlock</span>
          </span>
        </div>

        <div className="hidden md:flex items-center gap-7 text-sm text-slate-400">
          <button onClick={() => scrollTo('features')} className="hover:text-[var(--text-heading)] transition-colors cursor-pointer">Features</button>
          <button onClick={() => scrollTo('how-it-works')} className="hover:text-[var(--text-heading)] transition-colors cursor-pointer">How it works</button>
          <button onClick={() => scrollTo('frameworks')} className="hover:text-[var(--text-heading)] transition-colors cursor-pointer">Frameworks</button>
          <Link to="/trust" className="hover:text-[var(--text-heading)] transition-colors">Trust Hub</Link>
          <Link to="/auditor-login" className="hover:text-[var(--text-heading)] transition-colors">Auditor Portal</Link>
        </div>

        <div className="flex items-center gap-2.5">
          <Link to="/login" className="hidden sm:block text-sm text-slate-300 hover:text-[var(--text-heading)] transition-colors px-4 py-2 rounded-lg hover:bg-[var(--bg-interactive)]">
            Sign in
          </Link>
          <Link to="/login" className="text-sm font-semibold px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 transition-all shadow-lg shadow-blue-500/20 flex items-center gap-1.5 whitespace-nowrap">
            View Demo <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section id="hero" className="relative z-10 text-center px-5 pt-20 pb-24 md:pt-28 md:pb-32 max-w-5xl mx-auto page-enter">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold mb-8 cursor-default">
          <Sparkles className="w-3.5 h-3.5" />
          GRC Engineering Platform — Now with AI-assisted Remediation
        </div>

        <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.05] mb-6">
          Automated Compliance<br />
          <span className="bg-gradient-to-r from-blue-400 via-violet-400 to-cyan-400 bg-clip-text text-transparent" style={{ WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Regulation-as-Code
          </span>
        </h1>

        <p className="text-slate-400 text-lg md:text-xl max-w-2xl mx-auto leading-relaxed mb-10">
          The full-stack Compliance engineering platform. Automate evidence collection, policy enforcement, and risk analysis — end to end.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-10">
          <Link to="/login" className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 font-bold text-base shadow-xl shadow-blue-500/25 transition-all hover:scale-[1.02]">
            Launch Demo <ArrowRight className="w-4 h-4" />
          </Link>
          <button onClick={() => scrollTo('features')} className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-7 py-3.5 rounded-xl bg-[var(--bg-interactive)] border border-[var(--border-color)] hover:bg-[var(--bg-interactive-hover)] font-semibold text-sm transition-all">
            See Features <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center justify-center gap-2 text-xs text-slate-500">
          <Lock className="w-3.5 h-3.5" />
          Request demo access from your account team
        </div>
      </section>

      {/* Stats strip */}
      <section className="relative z-10 border-y border-[var(--border-subtle)] bg-[var(--bg-subtle)] py-8">
        <div className="max-w-4xl mx-auto px-5 grid grid-cols-2 md:grid-cols-4 gap-6 md:gap-0 md:divide-x divide-[var(--border-color)]">
          {STATS.map(s => (
            <div key={s.label} className="text-center px-4">
              <div className="text-2xl md:text-3xl font-extrabold text-[var(--text-heading)] mb-1">{s.value}</div>
              <div className="text-sm font-semibold text-slate-300">{s.label}</div>
              <div className="text-xs text-slate-500 mt-0.5">{s.sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="relative z-10 px-5 py-20 md:py-28 max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-400 text-xs font-semibold mb-4 uppercase tracking-wider">
            Full-stack GRC — built for engineering teams
          </div>
          <h2 className="text-3xl md:text-4xl font-extrabold text-[var(--text-heading)] mb-4">
            Everything compliance.<br />
            <span className="text-slate-400 font-normal text-2xl md:text-3xl">Nothing manual.</span>
          </h2>
          <p className="text-slate-500 text-base max-w-2xl mx-auto mt-2">
            The full-stack Compliance engineering platform. Click any feature to learn more.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map((f) => {
            const Icon = f.icon;
            return (
              <div
                key={f.title}
                className="group relative bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-2xl p-6 hover:bg-[var(--bg-interactive-hover)] hover:border-[var(--border-color-hover)] transition-all cursor-pointer overflow-hidden"
                onClick={() => navigate(f.link)}
                role="button"
                tabIndex={0}
                onKeyDown={e => e.key === 'Enter' && navigate(f.link)}
                aria-label={`Explore ${f.title}`}
              >
                {/* Glow */}
                <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none rounded-2xl"
                  style={{ background: `radial-gradient(circle at top left, ${f.glow}, transparent 70%)` }} />

                <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${f.color} flex items-center justify-center mb-4 shadow-lg flex-shrink-0`}>
                  <Icon className="w-5 h-5 text-[var(--text-heading)]" />
                </div>

                <div className="flex items-start justify-between gap-2 mb-2">
                  <h3 className="font-bold text-[var(--text-heading)] text-base leading-tight">{f.title}</h3>
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-[var(--bg-interactive)] border border-[var(--border-color)] text-slate-400 whitespace-nowrap flex-shrink-0">{f.badge}</span>
                </div>

                <p className="text-slate-400 text-sm leading-relaxed mb-4">{f.desc}</p>

                <div className="flex items-center gap-1 text-xs font-semibold text-blue-400 group-hover:text-blue-300 transition-colors">
                  {f.linkLabel} <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* How it works */}
      <section id="how-it-works" className="relative z-10 px-5 py-20 bg-[var(--bg-subtle)] border-y border-[var(--border-subtle)]">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl md:text-4xl font-extrabold text-[var(--text-heading)] mb-3">Up and running in minutes</h2>
            <p className="text-slate-400 text-lg">Not months. Not quarters. Minutes.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {HOW_IT_WORKS.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={step.step} className="relative">
                  {i < HOW_IT_WORKS.length - 1 && (
                    <div className="hidden lg:block absolute top-8 left-[calc(100%+0px)] w-full h-px bg-gradient-to-r from-[var(--bg-interactive-hover)] to-transparent z-10" />
                  )}
                  <div className="bg-[var(--bg-subtle)] border border-[var(--border-color)] rounded-2xl p-5 hover:bg-[var(--bg-interactive-hover)] transition-all">
                    <div className="text-xs font-bold text-slate-600 mb-3 tracking-widest">{step.step}</div>
                    <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/20 flex items-center justify-center mb-3">
                      <Icon className="w-4.5 h-4.5 text-blue-400" style={{ width: 18, height: 18 }} />
                    </div>
                    <h3 className="font-bold text-[var(--text-heading)] text-sm mb-2">{step.title}</h3>
                    <p className="text-slate-500 text-xs leading-relaxed">{step.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Frameworks */}
      <section id="frameworks" className="relative z-10 px-5 py-20 max-w-4xl mx-auto text-center">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-6">Compliance Frameworks Covered</p>
        <div className="flex flex-wrap justify-center gap-3 mb-6">
          {FRAMEWORKS.map(fw => (
            <button
              key={fw.id}
              onClick={() => navigate(`/features/${fw.slug}`)}
              className="px-5 py-2.5 rounded-xl border border-[var(--border-color)] bg-[var(--bg-subtle)] text-sm font-semibold text-slate-300 hover:border-blue-500/40 hover:bg-blue-500/10 hover:text-blue-300 transition-all"
            >
              {fw.label}
            </button>
          ))}
        </div>
        <p className="text-slate-500 text-sm">All frameworks mapped to unified controls. Overlap detected, duplicates eliminated.</p>
      </section>

      {/* Trust Hub CTA */}
      <section id="trust" className="relative z-10 px-5 pb-20 max-w-4xl mx-auto">
        <div className="relative bg-gradient-to-br from-blue-600/15 to-violet-600/10 border border-blue-500/20 rounded-3xl p-8 md:p-12 overflow-hidden text-center">
          <div className="absolute inset-0 opacity-30 pointer-events-none">
            <div className="absolute -top-20 -right-20 w-64 h-64 bg-violet-600/20 rounded-full blur-3xl" />
            <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-blue-600/20 rounded-full blur-3xl" />
          </div>
          <div className="relative">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-blue-500/30">
              <Shield className="w-6 h-6 text-[var(--text-heading)]" />
            </div>
            <h2 className="text-2xl md:text-3xl font-extrabold text-[var(--text-heading)] mb-3">Build trust before customers ask</h2>
            <p className="text-slate-400 text-base max-w-xl mx-auto mb-8">
              Publish a real-time security portal showing live compliance scores, certifications, and audit reports. Your SOC 2 report is one request away.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/trust" className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-[var(--bg-interactive-hover)] border border-[var(--border-color-hover)] hover:bg-[var(--bg-interactive-hover)] font-semibold text-sm transition-all">
                <ExternalLink className="w-4 h-4" /> View Trust Portal
              </Link>
              <Link to="/login" className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 font-bold text-sm transition-all shadow-lg shadow-blue-500/20">
                Launch Demo <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Social proof / final CTA */}
      <section className="relative z-10 px-5 pb-24 max-w-4xl mx-auto text-center">
        <div className="flex flex-wrap justify-center gap-6 mb-12">
          {[
            { icon: TrendingUp, text: 'Real-time control monitoring', color: 'text-emerald-400' },
            { icon: Lock, text: 'SOC 2 & ISO 27001 ready', color: 'text-blue-400' },
            { icon: Users, text: 'Team collaboration built-in', color: 'text-violet-400' },
            { icon: Layers, text: 'Multi-framework unified view', color: 'text-cyan-400' },
          ].map(item => {
            const Icon = item.icon;
            return (
              <div key={item.text} className="flex items-center gap-2 text-sm text-slate-400">
                <Icon className={`w-4 h-4 ${item.color}`} />
                {item.text}
              </div>
            );
          })}
        </div>
        <h2 className="text-3xl md:text-4xl font-extrabold text-[var(--text-heading)] mb-4">Ready to automate your GRC?</h2>
        <p className="text-slate-400 mb-8">Log in with the demo credentials and explore every feature.</p>
        <Link to="/login" className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 hover:from-blue-500 hover:to-violet-500 font-bold text-base shadow-xl shadow-blue-500/25 transition-all hover:scale-[1.02]">
          Start Free Demo <ArrowRight className="w-5 h-5" />
        </Link>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-[var(--border-subtle)] px-5 py-8">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-5">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-[var(--text-heading)]" />
            </div>
            <span className="font-bold text-sm">
              <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent" style={{ WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Warlock</span>
            </span>
          </div>
          <div className="flex flex-wrap gap-5 text-xs text-slate-500">
            <button onClick={() => scrollTo('features')} className="hover:text-slate-300 transition-colors">Features</button>
            <button onClick={() => scrollTo('frameworks')} className="hover:text-slate-300 transition-colors">Frameworks</button>
            <Link to="/trust" className="hover:text-slate-300 transition-colors">Trust Hub</Link>
            <Link to="/login" className="hover:text-slate-300 transition-colors">Sign In</Link>
          </div>
          <p className="text-xs text-slate-600">© 2026 Warlock. The full-stack Compliance engineering platform.</p>
        </div>
      </footer>
    </div>
  );
}
