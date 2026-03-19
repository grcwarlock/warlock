import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, ClipboardCheck } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (typeof detail === 'string') {
        setError(detail);
      } else {
        setError('Login failed. Please check your credentials.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md bg-[var(--bg-surface)] border border-[var(--border-color)] rounded-xl shadow-2xl overflow-hidden">
        
        <div className="p-8">
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-500 to-violet-600 rounded-2xl flex items-center justify-center mb-4 shadow-2xl shadow-blue-500/30">
              <Shield className="w-8 h-8 text-[var(--text-heading)]" />
            </div>
            <h2 className="text-2xl font-bold text-[var(--text-heading)] tracking-tight">
              <span className="bg-gradient-to-r from-blue-400 to-violet-400 bg-clip-text text-transparent">Warlock</span>
            </h2>
            <p className="text-[var(--text-muted)] mt-1">Sign in to your account</p>
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
                className="w-full bg-[var(--bg-elevated)] border border-[var(--border-color)] rounded-lg px-4 py-2.5 text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all"
                placeholder="you@company.com"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-[var(--text-body)] mb-1">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-[var(--bg-elevated)] border border-[var(--border-color)] rounded-lg px-4 py-2.5 text-[var(--text-heading)] placeholder-[var(--text-muted)] focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all"
                placeholder="••••••••"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary-600 hover:bg-primary-500 text-[var(--text-heading)] font-medium rounded-lg px-4 py-2.5 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed mt-2"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-[var(--border-color)]">
            <Link
              to="/auditor-login"
              className="flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg border border-emerald-500/30 bg-emerald-500/5 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300 text-sm font-medium transition-all"
            >
              <ClipboardCheck className="w-4 h-4" />
              External Auditor? Access the Auditor Portal
            </Link>
          </div>

        </div>
      </div>
    </div>
  );
}
