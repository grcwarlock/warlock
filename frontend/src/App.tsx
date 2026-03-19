import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './contexts/AuthContext';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/Layout';

const LandingPage = lazy(() => import('./pages/LandingPage'));
const LoginPage = lazy(() => import('./pages/LoginPage'));
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const FrameworksPage = lazy(() => import('./pages/FrameworksPage'));
const AssessmentsPage = lazy(() => import('./pages/AssessmentsPage'));
const EvidencePage = lazy(() => import('./pages/EvidencePage'));
const RiskPage = lazy(() => import('./pages/RiskPage'));
const VendorsPage = lazy(() => import('./pages/VendorsPage'));
const IntegrationsPage = lazy(() => import('./pages/IntegrationsPage'));
const POAMPage = lazy(() => import('./pages/POAMPage'));
const DataSilosPage = lazy(() => import('./pages/DataSilosPage'));
const TrustHubPage = lazy(() => import('./pages/TrustHubPage'));
const TrustPortalPage = lazy(() => import('./pages/TrustPortalPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const ToolConfigPage = lazy(() => import('./pages/ToolConfigPage'));
const MonitoringPage = lazy(() => import('./pages/MonitoringPage'));
const QuestionnairesPage = lazy(() => import('./pages/QuestionnairesPage'));
const TasksPage = lazy(() => import('./pages/TasksPage'));
const PersonnelPage = lazy(() => import('./pages/PersonnelPage'));
const AuditorPortalPage = lazy(() => import('./pages/AuditorPortalPage'));
const SSPPage = lazy(() => import('./pages/SSPPage'));
const RiskGraphPage = lazy(() => import('./pages/RiskGraphPage'));
const AIReasoningPage = lazy(() => import('./pages/AIReasoningPage'));
const IssuesPage = lazy(() => import('./pages/IssuesPage'));
const OSCALExportPage = lazy(() => import('./pages/OSCALExportPage'));
const FeaturePage = lazy(() => import('./pages/FeaturePage'));
const AuditorLoginPage = lazy(() => import('./pages/AuditorLoginPage'));

function LoadingFallback() {
  return (
    <div className="min-h-screen bg-[var(--bg-base)] flex items-center justify-center">
      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-violet-600 animate-pulse" />
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <LoadingFallback />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<Navigate to="/login" replace />} />
          <Route path="/trust" element={<TrustPortalPage />} />
          <Route path="/auditor" element={<AuditorPortalPage />} />
          <Route path="/auditor-login" element={<AuditorLoginPage />} />
          <Route path="/features/:slug" element={<FeaturePage />} />

          <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/frameworks" element={<FrameworksPage />} />
            <Route path="/assessments" element={<AssessmentsPage />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/vendors" element={<VendorsPage />} />
            <Route path="/integrations" element={<IntegrationsPage />} />
            <Route path="/poam" element={<POAMPage />} />
            <Route path="/data-silos" element={<DataSilosPage />} />
            <Route path="/trust-hub" element={<TrustHubPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/tool-config" element={<ToolConfigPage />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            <Route path="/questionnaires" element={<QuestionnairesPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/personnel" element={<PersonnelPage />} />

            <Route path="/ssp" element={<SSPPage />} />
            <Route path="/exports/oscal" element={<OSCALExportPage />} />
            <Route path="/risk-graph" element={<RiskGraphPage />} />
            <Route path="/ai-reasoning" element={<AIReasoningPage />} />
            <Route path="/issues" element={<IssuesPage />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
