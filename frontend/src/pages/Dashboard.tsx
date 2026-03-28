import { useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Hash,
  Shield,
  ShieldCheck,
  TrendingDown,
  Server,
  Layers,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { KPICard } from "@/components/shared/KPICard";
import { CardSkeleton, TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  useDashboardSummary,
  useCoverage,
  useDrift,
  usePipelineStatus,
  useTopology,
  useVerifyAuditTrail,
} from "@/hooks/useApi";
import type { CoverageData, DriftEvent } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function pctColor(rate: number): string {
  if (rate > 50) return "text-green-400";
  if (rate >= 25) return "text-amber-400";
  return "text-red-400";
}

function pctBg(rate: number): string {
  if (rate > 50) return "bg-green-500/10 border-green-500/20";
  if (rate >= 25) return "bg-amber-500/10 border-amber-500/20";
  return "bg-red-500/10 border-red-500/20";
}

function formatFrameworkId(name: string): string {
  return name.toLowerCase().replace(/[\s.]+/g, "_");
}

// ---------------------------------------------------------------------------
// KRI definitions (matches backend _KRI_REGISTRY)
// ---------------------------------------------------------------------------

interface KRIItem {
  id: string;
  label: string;
  thresholds: { green: number; amber: number };
  unit: string;
  invert?: boolean; // lower is better
}

const KRI_REGISTRY: KRIItem[] = [
  { id: "critical_finding_rate", label: "Critical Finding Rate", thresholds: { green: 5, amber: 15 }, unit: "%", invert: true },
  { id: "connector_error_rate", label: "Connector Error Rate", thresholds: { green: 2, amber: 10 }, unit: "%", invert: true },
  { id: "compliance_pass_rate", label: "Compliance Pass Rate", thresholds: { green: 80, amber: 50 }, unit: "%" },
  { id: "overdue_poam_count", label: "Overdue POA&Ms", thresholds: { green: 3, amber: 10 }, unit: "", invert: true },
  { id: "data_freshness_hours", label: "Data Freshness", thresholds: { green: 24, amber: 72 }, unit: "h", invert: true },
];

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function PipelineStatusBar() {
  const { data: pipeline, isLoading } = usePipelineStatus();
  const { data: summary } = useDashboardSummary();
  const { data: chainStatus, refetch: verifyChain } = useVerifyAuditTrail();

  // Trigger chain verification once pipeline data is loaded
  useEffect(() => {
    if (!isLoading) {
      verifyChain();
    }
  }, [isLoading, verifyChain]);

  if (isLoading) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-2.5">
        <div className="flex items-center gap-4">
          <div className="h-2.5 w-2.5 rounded-full bg-zinc-700 animate-pulse" />
          <span className="text-xs text-zinc-600">Loading pipeline status...</span>
        </div>
      </div>
    );
  }

  const lastRun = pipeline?.last_run;
  const connectorList = summary?.connectors ?? [];
  const totalConnectors = connectorList.length;
  const successConnectors = connectorList.filter((c) => c.status === "success").length;
  const isHealthy = !pipeline?.running && lastRun?.status === "success";

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-2.5">
      <div className="flex items-center gap-6 text-xs text-zinc-400 flex-wrap">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "h-2.5 w-2.5 rounded-full",
              isHealthy ? "bg-green-400 animate-pulse" : "bg-amber-400"
            )}
          />
          <span className="text-zinc-300 font-medium">
            {pipeline?.running ? "Pipeline running..." : "Pipeline idle"}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <Clock className="h-3 w-3 text-zinc-500" />
          <span>Last run: {relativeTime(lastRun?.completed_at ?? lastRun?.started_at)}</span>
        </div>

        {lastRun?.duration_seconds != null && (
          <div className="flex items-center gap-1.5">
            <Activity className="h-3 w-3 text-zinc-500" />
            <span>Duration: {lastRun.duration_seconds}s</span>
          </div>
        )}

        <div className="flex items-center gap-1.5">
          <Shield className="h-3 w-3 text-zinc-500" />
          <span>
            Connectors: {successConnectors}/{totalConnectors}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <Hash className="h-3 w-3 text-zinc-500" />
          {chainStatus ? (
            <span className={chainStatus.valid ? "text-green-400" : "text-red-400"}>
              Hash chain: {chainStatus.valid ? "verified" : `broken (${chainStatus.errors.length} errors)`}
            </span>
          ) : (
            <span className="text-zinc-500">Hash chain: checking...</span>
          )}
        </div>

        {pipeline?.lake && (
          <div className="flex items-center gap-1.5">
            <Layers className="h-3 w-3 text-zinc-500" />
            <span
              className={
                pipeline.lake.startsWith("ok")
                  ? "text-green-400"
                  : pipeline.lake === "disabled"
                    ? "text-zinc-500"
                    : "text-red-400"
              }
            >
              Lake: {pipeline.lake}
            </span>
          </div>
        )}

        {summary?.data_source && (
          <div className="flex items-center gap-1.5">
            <Server className="h-3 w-3 text-zinc-500" />
            <span
              className={
                summary.data_source === "lake" ? "text-indigo-400" : "text-zinc-500"
              }
            >
              Source: {summary.data_source}
            </span>
          </div>
        )}

        {pipeline?.totals && (
          <div className="ml-auto flex items-center gap-4 text-zinc-500">
            <span>{pipeline.totals.raw_events.toLocaleString()} events</span>
            <span>{pipeline.totals.findings.toLocaleString()} findings</span>
            <span>{pipeline.totals.control_results.toLocaleString()} results</span>
          </div>
        )}
      </div>
    </div>
  );
}

function KPIRow() {
  const { data: summary, isLoading } = useDashboardSummary();
  const { data: coverageList } = useCoverage();

  const coverageArr = useMemo(
    () => (Array.isArray(coverageList) ? coverageList : []),
    [coverageList],
  );

  const avgRate = useMemo(() => {
    if (coverageArr.length === 0) return summary?.posture_score ?? 0;
    const totalRate = coverageArr.reduce((acc: number, c: CoverageData) => acc + (c.rate ?? 0), 0);
    return Math.min(totalRate / coverageArr.length, 100);
  }, [coverageArr, summary?.posture_score]);

  if (isLoading) {
    return (
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <CardSkeleton key={i} />
        ))}
      </div>
    );
  }

  if (!summary) return null;

  const issues = summary.open_issues;
  const totalFindings =
    (issues.critical ?? 0) + (issues.high ?? 0) + (issues.medium ?? 0) + (issues.low ?? 0);

  const activePOAMs = totalFindings;
  const overduePOAMs = issues.critical + issues.high;

  const frameworks = summary.frameworks ?? [];
  const totalControls = frameworks.reduce((acc, fw) => acc + fw.total_controls, 0);
  const frameworkCount = frameworks.length;

  const severityBreakdown = `C:${issues.critical} H:${issues.high} M:${issues.medium} L:${issues.low}`;

  const improvingCount = frameworks.filter((f) => f.trend === "improving").length;
  const degradingCount = frameworks.filter((f) => f.trend === "degrading").length;

  return (
    <div className="grid grid-cols-4 gap-4">
      <KPICard
        label="Open Issues"
        value={totalFindings.toLocaleString()}
        trend={{ text: severityBreakdown, direction: issues.critical > 0 ? "down" : "neutral" }}
        href="/findings"
        valueColor={issues.critical > 0 ? "text-red-400" : "text-zinc-100"}
      />
      <KPICard
        label="Compliance Rate"
        value={`${avgRate.toFixed(1)}%`}
        trend={{
          text: improvingCount > 0
            ? `${improvingCount} frameworks improving`
            : "stable",
          direction: improvingCount > 0 ? "up" : degradingCount > 0 ? "down" : "neutral",
        }}
        href="/compliance"
        valueColor={pctColor(avgRate)}
      />
      <KPICard
        label="Active POA&Ms"
        value={activePOAMs.toLocaleString()}
        trend={{
          text: overduePOAMs > 0 ? `${overduePOAMs} critical/high` : "none critical",
          direction: overduePOAMs > 0 ? "down" : "up",
        }}
        href="/remediation"
        valueColor={overduePOAMs > 0 ? "text-amber-400" : "text-zinc-100"}
      />
      <KPICard
        label="Controls Assessed"
        value={totalControls.toLocaleString()}
        trend={{ text: `across ${frameworkCount} frameworks`, direction: "neutral" }}
        href="/compliance"
      />
    </div>
  );
}

function FrameworkHeatmap() {
  const { data: coverageList, isLoading, isError } = useCoverage();

  if (isLoading) {
    return (
      <div className="col-span-2 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <div className="grid grid-cols-3 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  const items: CoverageData[] = Array.isArray(coverageList) ? coverageList : [];

  if (isError || items.length === 0) {
    return (
      <div className="col-span-2 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <EmptyState
          icon={ShieldCheck}
          title="No coverage data"
          description="Run the pipeline to generate compliance coverage data."
        />
      </div>
    );
  }

  return (
    <div className="col-span-2 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
        Framework Coverage
      </h2>
      <div className="grid grid-cols-3 gap-2.5">
        {items.map((fw) => (
          <Link
            key={fw.framework}
            to={`/compliance/${formatFrameworkId(fw.framework)}`}
            className={cn(
              "rounded-lg border p-3 transition-all hover:scale-[1.02] hover:brightness-110",
              pctBg(fw.rate)
            )}
          >
            <div className="text-[10px] uppercase tracking-wide text-zinc-400 truncate">
              {fw.framework}
            </div>
            <div className={cn("text-2xl font-bold mt-0.5", pctColor(fw.rate))}>
              {fw.rate.toFixed(0)}%
            </div>
            <div className="text-[10px] text-zinc-500 mt-0.5">
              {fw.compliant}/{fw.total} controls
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function KRIPanel() {
  const { data: summary, isLoading } = useDashboardSummary();
  const { data: coverageList } = useCoverage();

  const coverageArr = useMemo(
    () => (Array.isArray(coverageList) ? coverageList : []),
    [coverageList],
  );

  const kriValues = useMemo(() => {
    const connectors = summary?.connectors ?? [];
    const totalConnectors = connectors.length;
    const errorConnectors = connectors.filter((c) => c.error_count > 0).length;
    const issues = summary?.open_issues ?? { critical: 0, high: 0, medium: 0, low: 0 };
    const totalIssues = issues.critical + issues.high + issues.medium + issues.low;

    const avgRate =
      coverageArr.length > 0
        ? coverageArr.reduce((acc: number, c: CoverageData) => acc + c.rate, 0) / coverageArr.length
        : summary?.posture_score ?? 0;

    // Derive data freshness from pipeline last_assessment
    let freshnessHours = 12;
    if (summary?.last_assessment) {
      const hoursAgo = (Date.now() - new Date(summary.last_assessment).getTime()) / 3_600_000;
      freshnessHours = Math.round(hoursAgo);
    }

    return {
      critical_finding_rate: totalIssues > 0 ? (issues.critical / totalIssues) * 100 : 0,
      connector_error_rate: totalConnectors > 0 ? (errorConnectors / totalConnectors) * 100 : 0,
      compliance_pass_rate: avgRate,
      overdue_poam_count: issues.critical + issues.high,
      data_freshness_hours: freshnessHours,
    } as Record<string, number>;
  }, [summary, coverageArr]);

  if (isLoading) {
    return (
      <div className="col-span-1 rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="h-2.5 w-2.5 rounded-full bg-zinc-700 animate-pulse" />
            <div className="h-3 flex-1 bg-zinc-800 rounded animate-pulse" />
          </div>
        ))}
      </div>
    );
  }

  function kriColor(item: KRIItem, value: number): string {
    if (item.invert) {
      if (value <= item.thresholds.green) return "bg-green-400";
      if (value <= item.thresholds.amber) return "bg-amber-400";
      return "bg-red-400";
    }
    if (value >= item.thresholds.green) return "bg-green-400";
    if (value >= item.thresholds.amber) return "bg-amber-400";
    return "bg-red-400";
  }

  return (
    <div className="col-span-1 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
        Key Risk Indicators
      </h2>
      <div className="space-y-3">
        {KRI_REGISTRY.map((kri) => {
          const val = kriValues[kri.id] ?? 0;
          return (
            <div key={kri.id} className="flex items-center gap-3">
              <div className={cn("h-2.5 w-2.5 rounded-full shrink-0", kriColor(kri, val))} />
              <div className="flex-1 min-w-0">
                <div className="text-xs text-zinc-300 truncate">{kri.label}</div>
              </div>
              <div className="text-xs font-mono text-zinc-400 tabular-nums">
                {kri.unit === "%" ? `${val.toFixed(1)}%` : `${val}${kri.unit}`}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Source-type icon mapping for the infrastructure preview cards. */
const SOURCE_TYPE_ICONS: Record<string, typeof Server> = {
  cloud: Server,
  scanner: ShieldCheck,
  identity: Shield,
  code: Layers,
};

function InfrastructurePreview() {
  const { data: topology, isLoading } = useTopology();

  if (isLoading) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <div className="flex gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  const sourceTypes = topology?.source_types ?? [];

  if (sourceTypes.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <EmptyState
          icon={Server}
          title="No infrastructure data"
          description="Run the pipeline to discover infrastructure source types."
        />
      </div>
    );
  }

  const totalFindings = topology?.total_findings ?? 0;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
          Infrastructure Overview
        </h2>
        <Link
          to="/infrastructure"
          className="text-[11px] text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          {totalFindings.toLocaleString()} total findings &rarr;
        </Link>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2.5">
        {sourceTypes.map((st) => {
          const IconComponent = SOURCE_TYPE_ICONS[st.name.toLowerCase()] ?? Layers;
          const providerCount = st.providers.length;
          return (
            <Link
              key={st.name}
              to="/infrastructure"
              className="rounded-lg border border-zinc-800 bg-zinc-800/40 p-3 hover:border-zinc-700 hover:bg-zinc-800/60 transition-all group"
            >
              <div className="flex items-center gap-2 mb-1.5">
                <IconComponent className="h-3.5 w-3.5 text-zinc-500 group-hover:text-zinc-400 transition-colors" />
                <span className="text-[10px] uppercase tracking-wide text-zinc-400 truncate">
                  {st.name}
                </span>
              </div>
              <div className="text-xl font-bold text-zinc-100 tabular-nums">
                {st.finding_count.toLocaleString()}
              </div>
              <div className="text-[10px] text-zinc-500 mt-0.5">
                {providerCount} provider{providerCount !== 1 ? "s" : ""}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

function DriftEventsTable() {
  const { data: driftList, isLoading, isError } = useDrift(undefined, 90);

  if (isLoading) {
    return <TableSkeleton rows={6} />;
  }

  const events: DriftEvent[] = Array.isArray(driftList) ? driftList.slice(0, 10) : [];

  if (isError || events.length === 0) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <EmptyState
          icon={TrendingDown}
          title="No drift events"
          description="No compliance drift detected in the last 90 days."
        />
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <h2 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
        Recent Drift Events
      </h2>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-zinc-800 text-zinc-500">
              <th className="text-left py-2 pr-3 font-medium">Control</th>
              <th className="text-left py-2 pr-3 font-medium">Direction</th>
              <th className="text-left py-2 pr-3 font-medium">Status Change</th>
              <th className="text-right py-2 font-medium">When</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt) => {
              const isDegraded =
                evt.drift_direction === "DEGRADED" || evt.drift_direction === "degraded";
              return (
                <tr
                  key={evt.id}
                  className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors"
                >
                  <td className="py-2 pr-3">
                    <Link
                      to={`/compliance/${formatFrameworkId(evt.framework)}/${evt.control_id}`}
                      className="hover:text-indigo-400 transition-colors"
                    >
                      <div className="font-mono text-zinc-200">{evt.control_id}</div>
                      <div className="text-[10px] text-zinc-500">{evt.framework}</div>
                    </Link>
                  </td>
                  <td className="py-2 pr-3">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase",
                        isDegraded
                          ? "bg-red-500/10 text-red-400 border-red-500/20"
                          : "bg-green-500/10 text-green-400 border-green-500/20"
                      )}
                    >
                      {isDegraded ? (
                        <AlertTriangle className="h-2.5 w-2.5" />
                      ) : (
                        <CheckCircle2 className="h-2.5 w-2.5" />
                      )}
                      {evt.drift_direction}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-zinc-400">
                    {evt.previous_status} &rarr; {evt.new_status}
                  </td>
                  <td className="py-2 text-right text-zinc-500 whitespace-nowrap">
                    {relativeTime(evt.detected_at)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------

export default function Dashboard() {
  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Compliance Posture</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Executive overview of your organization's GRC posture
        </p>
      </div>

      {/* Section 1: Pipeline Status Bar */}
      <PipelineStatusBar />

      {/* Section 2: KPI Cards */}
      <KPIRow />

      {/* Section 3: Framework Coverage Heatmap + KRI Panel */}
      <div className="grid grid-cols-3 gap-4">
        <FrameworkHeatmap />
        <KRIPanel />
      </div>

      {/* Section 4: Infrastructure Preview */}
      <InfrastructurePreview />

      {/* Section 5: Recent Drift Events */}
      <DriftEventsTable />
    </div>
  );
}
