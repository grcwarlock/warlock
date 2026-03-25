import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Layers,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFindings, useConnectorStatus } from "@/hooks/useApi";
import type { Finding } from "@/api/types";

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

interface ServiceGroup {
  eventType: string;
  findings: Finding[];
  severityCounts: Record<string, number>;
}

function groupByEventType(findings: Finding[]): ServiceGroup[] {
  const map: Record<string, Finding[]> = {};
  for (const f of findings) {
    const key = f.observation_type || "unknown";
    if (!map[key]) map[key] = [];
    map[key].push(f);
  }

  return Object.entries(map)
    .map(([eventType, items]) => {
      const severityCounts: Record<string, number> = {};
      for (const f of items) {
        const s = f.severity || "info";
        severityCounts[s] = (severityCounts[s] || 0) + 1;
      }
      return { eventType, findings: items, severityCounts };
    })
    .sort((a, b) => b.findings.length - a.findings.length);
}

function worstSeverity(counts: Record<string, number>): string {
  if (counts.critical) return "critical";
  if (counts.high) return "high";
  if (counts.medium) return "medium";
  if (counts.low) return "low";
  return "info";
}

function severityBorderColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-l-red-500";
    case "high":
      return "border-l-orange-500";
    case "medium":
      return "border-l-amber-500";
    case "low":
      return "border-l-blue-500";
    default:
      return "border-l-zinc-700";
  }
}

function statusDot(status: string | null): string {
  switch (status) {
    case "success":
      return "bg-green-400";
    case "running":
      return "bg-blue-400 animate-pulse";
    case "error":
    case "failed":
      return "bg-red-400";
    default:
      return "bg-zinc-600";
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ServiceCard({
  provider,
  group,
}: {
  provider: string;
  group: ServiceGroup;
}) {
  const worst = worstSeverity(group.severityCounts);

  return (
    <Link
      to={`/pipeline/${encodeURIComponent(provider)}/${encodeURIComponent(group.eventType)}`}
      className={cn(
        "rounded-lg border border-zinc-800 border-l-2 bg-zinc-900 p-4",
        "hover:border-zinc-700 hover:bg-zinc-800/60 transition-all",
        "flex flex-col gap-3",
        severityBorderColor(worst)
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 min-w-0">
          <Layers className="h-4 w-4 text-zinc-500 shrink-0" />
          <span className="text-sm font-medium text-zinc-200 truncate">
            {group.eventType}
          </span>
        </div>
        <span className="text-xs text-zinc-500 shrink-0 ml-2">
          {group.findings.length} findings
        </span>
      </div>

      {/* Severity breakdown */}
      <div className="flex items-center gap-2 flex-wrap">
        {Object.entries(group.severityCounts)
          .sort(([a], [b]) => {
            const order = ["critical", "high", "medium", "low", "info"];
            return order.indexOf(a) - order.indexOf(b);
          })
          .map(([severity, count]) => (
            <div key={severity} className="flex items-center gap-1">
              <SeverityBadge severity={severity} />
              <span className="text-[10px] text-zinc-500">{count}</span>
            </div>
          ))}
      </div>

      {/* Most recent finding */}
      {group.findings.length > 0 && (
        <div className="text-[10px] text-zinc-500">
          Latest: {relativeTime(group.findings[0].observed_at)}
        </div>
      )}
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function ProviderDetail() {
  const { provider } = useParams<{ provider: string }>();
  const decodedProvider = provider ? decodeURIComponent(provider) : "";

  const { data: connectorStatus } = useConnectorStatus(decodedProvider);

  const {
    data: findingsResponse,
    isLoading,
    isError,
  } = useFindings({
    source: decodedProvider,
    limit: 1000,
  });

  const findings: Finding[] = useMemo(() => {
    if (!findingsResponse) return [];
    if (Array.isArray(findingsResponse)) return findingsResponse;
    if ("items" in findingsResponse) return findingsResponse.items;
    return [];
  }, [findingsResponse]);

  const services = useMemo(() => groupByEventType(findings), [findings]);

  const totalCritical = findings.filter((f) => f.severity === "critical").length;
  const totalHigh = findings.filter((f) => f.severity === "high").length;

  // Connector status data (may be Connector type)
  const connStatus = connectorStatus as Record<string, unknown> | undefined;
  const lastStatus = (connStatus?.last_status as string) ?? null;

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      {/* Breadcrumb + header */}
      <div>
        <Link
          to="/pipeline"
          className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors mb-3"
        >
          <ArrowLeft className="h-3 w-3" />
          Back to Pipeline
        </Link>
        <div className="flex items-center gap-3">
          <div className={cn("h-3 w-3 rounded-full shrink-0", statusDot(lastStatus))} />
          <h1 className="text-xl font-semibold text-zinc-100">{decodedProvider}</h1>
        </div>
        <p className="text-sm text-zinc-500 mt-0.5">
          {findings.length} findings across {services.length} event types
        </p>
      </div>

      {/* Summary stats */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-2.5">
        <div className="flex items-center gap-6 text-xs text-zinc-400 flex-wrap">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-3 w-3 text-zinc-500" />
            <span>{findings.length} total findings</span>
          </div>
          <span>{services.length} event types</span>
          {totalCritical > 0 && (
            <span className="text-red-400 flex items-center gap-1">
              <XCircle className="h-3 w-3" />
              {totalCritical} critical
            </span>
          )}
          {totalHigh > 0 && (
            <span className="text-orange-400 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              {totalHigh} high
            </span>
          )}
        </div>
      </div>

      {/* Content */}
      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      )}

      {isError && (
        <EmptyState
          icon={AlertTriangle}
          title="Failed to load findings"
          description={`Could not fetch findings for provider "${decodedProvider}".`}
        />
      )}

      {!isLoading && !isError && services.length === 0 && (
        <EmptyState
          icon={Layers}
          title="No findings"
          description={`No findings collected for "${decodedProvider}" yet. Run the pipeline to collect data.`}
        />
      )}

      {!isLoading && !isError && services.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {services.map((group) => (
            <ServiceCard
              key={group.eventType}
              provider={decodedProvider}
              group={group}
            />
          ))}
        </div>
      )}
    </div>
  );
}
