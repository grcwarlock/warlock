import { Routes, Route, Navigate } from "react-router-dom";
import AppShell from "@/components/layout/AppShell";

import Dashboard from "@/pages/Dashboard";
import InfrastructureOverview from "@/pages/infrastructure/InfrastructureOverview";
import ProviderDetail from "@/pages/infrastructure/ProviderDetail";
import ServiceDetail from "@/pages/infrastructure/ServiceDetail";
import ResourceDetail from "@/pages/infrastructure/ResourceDetail";
import ComplianceOverview from "@/pages/compliance/ComplianceOverview";
import FrameworkDetail from "@/pages/compliance/FrameworkDetail";
import ControlDetail from "@/pages/compliance/ControlDetail";
import FindingsTable from "@/pages/findings/FindingsTable";
import FindingDetail from "@/pages/findings/FindingDetail";
import RemediationOverview from "@/pages/remediation/RemediationOverview";
import POAMDetail from "@/pages/remediation/POAMDetail";
import IncidentsList from "@/pages/incidents/IncidentsList";
import IncidentDetail from "@/pages/incidents/IncidentDetail";
import RiskOverview from "@/pages/risk/RiskOverview";
import AuditOverview from "@/pages/audit/AuditOverview";
import SettingsOverview from "@/pages/settings/SettingsOverview";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />

        {/* Infrastructure drill-down: source_type → provider → service → resource */}
        <Route path="infrastructure" element={<InfrastructureOverview />} />
        <Route path="infrastructure/:sourceType/:provider" element={<ProviderDetail />} />
        <Route path="infrastructure/:sourceType/:provider/:resourceType" element={<ServiceDetail />} />
        <Route path="infrastructure/:sourceType/:provider/:resourceType/:resourceId" element={<ResourceDetail />} />

        {/* Compliance drill-down: framework → controls → control detail */}
        <Route path="compliance" element={<ComplianceOverview />} />
        <Route path="compliance/:frameworkId" element={<FrameworkDetail />} />
        <Route path="compliance/:frameworkId/:controlId" element={<ControlDetail />} />

        {/* Findings */}
        <Route path="findings" element={<FindingsTable />} />
        <Route path="findings/:findingId" element={<FindingDetail />} />

        {/* Remediation */}
        <Route path="remediation" element={<RemediationOverview />} />
        <Route path="remediation/:poamId" element={<POAMDetail />} />

        {/* Operations */}
        <Route path="incidents" element={<IncidentsList />} />
        <Route path="incidents/:incidentId" element={<IncidentDetail />} />
        <Route path="risk" element={<RiskOverview />} />
        <Route path="audit" element={<AuditOverview />} />
        <Route path="settings" element={<SettingsOverview />} />
      </Route>

      {/* Legacy redirect */}
      <Route path="/pipeline/*" element={<Navigate to="/infrastructure" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
