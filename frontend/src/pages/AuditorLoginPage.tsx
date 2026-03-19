import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, ClipboardCheck, Eye, EyeOff, ArrowLeft } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function AuditorLoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password);
      navigate('/auditor');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else {
        setError('Login failed. Please check your email and password.');
      }
    } finally {
      setLoading(false);
    }
  };

  const fillDemo = () => {
    setEmail('auditor@warlock-demo.com');
    setPassword('AuditDemo2026!');
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md">
        <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-[var(--text-heading)] transition-colors mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to home
        </Link>

        <div className="bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl shadow-2xl overflow-hidden">
          <div className="bg-gradient-to-r from-emerald-600/20 to-teal-600/20 border-b border-[var(--border-color)] px-8 py-5">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl flex items-center justify-center shadow-lg shadow-emerald-500/20">
                <ClipboardCheck className="w-6 h-6 text-[var(--text-heading)]" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-[var(--text-heading)]">Auditor Portal</h2>
                <p className="text-[var(--text-muted)] text-sm">Compliance evidence access</p>
              </div>
            </div>
          </div>

          <div className="p-8">
            <div className="mb-6 p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-lg">
              <p className="text-emerald-400 text-sm font-medium mb-2">Demo Auditor Credentials</p>
              <div className="space-y-1 text-sm">
                <p className="text-[var(--text-body)]">
                  Email: <code className="bg-[var(--bg-elevated)] px-1.5 py-0.5 rounded text-emerald-400">auditor@warlock-demo.com</code>
                </p>
                <p className="text-[var(--text-body)]">
                  Password: <code className="bg-[var(--bg-elevated)] px-1.5 py-0.5 rounded text-emerald-400">AuditDemo2026!</code>
                </p>
              </div>
              <button
                onClick={fillDemo}
                className="mt-3 text-xs font-medium text-emerald-400 hover:text-emerald-300 underline underline-offset-2 transition-colors"
              >
                Auto-fill demo credentials
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm text-center">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-[var(--text-body)] mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[var(--bg-elevated)] border border-[var(--border-color)] rounded-lg px-4 py-2.5 text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                  placeholder="auditor@firm.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-[var(--text-body)] mb-1">Password</label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[var(--bg-elevated)] border border-[var(--border-color)] rounded-lg px-4 py-2.5 pr-10 text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-[var(--text-heading)]"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-[var(--text-heading)] font-medium rounded-lg px-4 py-2.5 transition-all focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-emerald-500/20"
              >
                {loading ? 'Signing in...' : 'Access Evidence Portal'}
              </button>
            </form>

            <div className="mt-6 pt-6 border-t border-[var(--border-color)]">
              <p className="text-xs text-slate-500 text-center">
                This portal provides read-only access to compliance evidence packages.
                For full platform access, <Link to="/login" className="text-blue-400 hover:text-blue-300">sign in here</Link>.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-center gap-2 text-xs text-slate-600">
          <Shield className="w-3.5 h-3.5" />
          <span>All sessions are logged for audit compliance</span>
        </div>
      </div>
    </div>
  );
}
