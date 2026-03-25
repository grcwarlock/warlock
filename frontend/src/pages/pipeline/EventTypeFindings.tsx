import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, FileText, AlertTriangle, Server } from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFindings } from "@/hooks/useApi";
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

interface ResourceGroup {
  resourceId: string;
  resourceType: string | null;
  findings: Finding[];
  worstSeverity: string;
}

function groupByResource(findings: Finding[]): ResourceGroup[] {
  const map: Record<string, Finding[]> = {};
  for (const f of findings) {
    const key = f.resource_id || "unknown";
    if (!map[key]) map[key] = [];
    map[key].push(f);
  }

  const severityOrder = ["critical", "high", "medium", "low", "info"];

  return Object.entries(map)
    .map(([resourceId, items]) => {
      let worst = "info";
      for (const f of items) {
        const s = f.severity || "info";
        if (severityOrder.indexOf(s) < severityOrder.indexOf(worst)) {
          worst = s;
        }
      }
      return {
        resourceId,
        resourceType: items[0]?.resource_type ?? null,
        findings: items,
        worstSeverity: worst,
      };
    })
    .sort((a, b) => {
      const aIdx = severityOrder.indexOf(a.worstSeverity);
      const bIdx = severityOrder.indexOf(b.worstSeverity);
      if (aIdx !== bIdx) return aIdx - bIdx;
      return b.findings.length - a.findings.length;
    });
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

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ResourceCard({ group }: { group: ResourceGroup }) {
  return (
    <div
      className={cn(
        "rounded-lg border border-zinc-800 border-l-2 bg-zinc-900 p-4",
        severityBorderColor(group.worstSeverity)
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <Server className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
          <span className="text-sm font-mono text-zinc-200 truncate">
            {group.resourceId}
          </span>
        </div>
        {group.resourceType && (
          <span className="text-[10px] text-zinc-500 uppercase tracking-wider shrink-0 ml-2">
            {group.resourceType}
          </span>
        )}
      </div>

      {/* Findings list */}
      <div className="space-y-1.5 mt-3">
        {group.findings.map((f) => (
          <Link
            key={f.id}
            to={`/pipeline/finding/${encodeURIComponent(f.id)}`}
            className={cn(
              "flex items-center gap-2 rounded-md px-2 py-1.5",
              "bg-zinc-800/40 hover:bg-zinc-800 transition-colors"
            )}
          >
            <SeverityBadge severity={f.severity} />
            <span className="text-xs text-zinc-300 truncate flex-1">
              {f.title}
            </span>
            <span className="text-[10px] text-zinc-500 shrink-0">
              {relativeTime(f.observed_at)}
            </span>
          </Link>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function EventTypeFindings() {
  const { provider, eventType } = useParams<{
    provider: string;
    eventType: string;
  }>();
  const decodedProvider = provider ? decodeURIComponent(provider) : "";
  const decodedEventType = eventType ? decodeURIComponent(eventType) : "";

  const {
    data: findingsResponse,
    isLoading,
    isError,
  } = useFindings({
    source: decodedProvider,
    observation_type: decodedEventType,
    limit: 1000,
  });

  const findings: Finding[] = useMemo(() => {
    if (!findingsResponse) return [];
    if (Array.isArray(findingsResponse)) return findingsResponse;
    if ("items" in findingsResponse) return findingsResponse.items;
    return [];
  }, [findingsResponse]);

  const resources = useMemo(() => groupByResource(findings), [findings]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of findings) {
      const s = f.severity || "info";
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [findings]);

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      {/* Breadcrumb + header */}
      <div>
        <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-3">
          <Link to="/pipeline" className="hover:text-zinc-300 transition-colors">
            Pipeline
          </Link>
          <span>/</span>
          <Link
            to={`/pipeline/${encodeURIComponent(decodedProvider)}`}
            className="hover:text-zinc-300 transition-colors"
          >
            {decodedProvider}
          </Link>
          <span>/</span>
          <span className="text-zinc-400">{decodedEventType}</span>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to={`/pipeline/${encodeURIComponent(decodedProvider)}`}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <h1 className="text-xl font-semibold text-zinc-100">{decodedEventType}</h1>
        </div>
        <p className="text-sm text-zinc-500 mt-0.5">
          {findings.length} findings across {resources.length} resources from {decodedProvider}
        </p>
      </div>

      {/* Summary stats */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-2.5">
        <div className="flex items-center gap-4 text-xs text-zinc-400 flex-wrap">
          <div className="flex items-center gap-2">
            <FileText className="h-3 w-3 text-zinc-500" />
            <span>{findings.length} findings</span>
          </div>
          <span>{resources.length} resources</span>
          {Object.entries(severityCounts)
            .sort(([a], [b]) => {
              const order = ["critical", "high", "medium", "low", "info"];
              return order.indexOf(a) - order.indexOf(b);
            })
            .map(([severity, count]) => (
              <div key={severity} className="flex items-center gap-1">
                <SeverityBadge severity={severity} />
                <span className="text-[10px]">{count}</span>
              </div>
            ))}
        </div>
      </div>

      {/* Content */}
      {isLoading && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      )}

      {isError && (
        <EmptyState
          icon={AlertTriangle}
          title="Failed to load findings"
          description={`Could not fetch findings for ${decodedProvider} / ${decodedEventType}.`}
        />
      )}

      {!isLoading && !isError && resources.length === 0 && (
        <EmptyState
          icon={FileText}
          title="No findings"
          description={`No findings found for event type "${decodedEventType}".`}
        />
      )}

      {!isLoading && !isError && resources.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {resources.map((group) => (
            <ResourceCard key={group.resourceId} group={group} />
          ))}
        </div>
      )}
    </div>
  );
}
