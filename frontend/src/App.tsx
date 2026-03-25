import { Routes, Route, Navigate } from "react-router-dom";
import AppShell from "@/components/layout/AppShell";

import Dashboard from "@/pages/Dashboard";
import PipelineOverview from "@/pages/pipeline/PipelineOverview";
import ProviderDetail from "@/pages/pipeline/ProviderDetail";
import EventTypeFindings from "@/pages/pipeline/EventTypeFindings";
import PipelineFindingDetail from "@/pages/pipeline/FindingDetail";
import ComplianceOverview from "@/pages/compliance/ComplianceOverview";
import FrameworkDetail from "@/pages/compliance/FrameworkDetail";
import ControlDetail from "@/pages/compliance/ControlDetail";
import FindingsTable from "@/pages/findings/FindingsTable";
import RemediationOverview from "@/pages/remediation/RemediationOverview";
import POAMDetail from "@/pages/remediation/POAMDetail";
import IncidentsList from "@/pages/incidents/IncidentsList";
import IncidentDetail from "@/pages/incidents/IncidentDetail";
import RiskOverview from "@/pages/risk/RiskOverview";
import AuditOverview from "@/pages/audit/AuditOverview";
import SettingsOverview from "@/pages/settings/SettingsOverview";
import Login from "@/pages/Login";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="pipeline" element={<PipelineOverview />} />
        <Route path="pipeline/:provider" element={<ProviderDetail />} />
        <Route
          path="pipeline/:provider/:eventType"
          element={<EventTypeFindings />}
        />
        <Route
          path="pipeline/:provider/:eventType/:findingId"
          element={<PipelineFindingDetail />}
        />
        <Route path="compliance" element={<ComplianceOverview />} />
        <Route path="compliance/:frameworkId" element={<FrameworkDetail />} />
        <Route
          path="compliance/:frameworkId/:controlId"
          element={<ControlDetail />}
        />
        <Route path="findings" element={<FindingsTable />} />
        <Route
          path="findings/:findingId"
          element={<PipelineFindingDetail />}
        />
        <Route path="remediation" element={<RemediationOverview />} />
        <Route path="remediation/:poamId" element={<POAMDetail />} />
        <Route path="incidents" element={<IncidentsList />} />
        <Route path="incidents/:incidentId" element={<IncidentDetail />} />
        <Route path="risk" element={<RiskOverview />} />
        <Route path="audit" element={<AuditOverview />} />
        <Route path="settings" element={<SettingsOverview />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
