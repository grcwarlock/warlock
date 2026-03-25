import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ChevronRight,
  AlertTriangle,
  FileSearch,
  Shield,
  Box,
  ExternalLink,
} from "lucide-react";

import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useTopology, useFindings } from "@/hooks/useApi";
import type { Finding, TopologyResource } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatResourceType(rt: string): string {
  return rt.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "n/a";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// ---------------------------------------------------------------------------
// Observation type badge
// ---------------------------------------------------------------------------

const OBS_STYLES: Record<string, string> = {
  sast: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  dast: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  finding: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  vulnerability: "bg-red-500/10 text-red-400 border-red-500/20",
  misconfiguration: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  compliance_check: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  inventory: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
};

function ObservationBadge({ type }: { type: string }) {
  const normalized = type.toLowerCase().replace(/[\s-]+/g, "_");
  const style = OBS_STYLES[normalized] ?? OBS_STYLES.finding;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        style
      )}
    >
      {type.replace(/_/g, " ")}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Controls list for a finding
// ---------------------------------------------------------------------------

function FindingControls({ finding }: { finding: Finding }) {
  // Extract control references from detail if available
  const detail = finding.detail as Record<string, unknown> | null;
  const controls: string[] = [];

  if (detail && Array.isArray(detail.controls)) {
    for (const c of detail.controls) {
      if (typeof c === "string") controls.push(c);
      else if (c && typeof c === "object" && "control_id" in c)
        controls.push(String((c as Record<string, unknown>).control_id));
    }
  }

  if (controls.length === 0) return <span className="text-zinc-600">--</span>;

  return (
    <div className="flex flex-wrap gap-1">
      {controls.slice(0, 4).map((ctrl) => (
        <Link
          key={ctrl}
          to={`/compliance/${encodeURIComponent(finding.source)}/${encodeURIComponent(ctrl)}`}
          className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-blue-400 hover:text-blue-300 hover:border-zinc-600 transition-colors"
        >
          {ctrl}
        </Link>
      ))}
      {controls.length > 4 && (
        <span className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-500">
          +{controls.length - 4}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ResourceDetail() {
  const {
    sourceType,
    provider: providerName,
    resourceType,
    resourceId,
  } = useParams<{
    sourceType: string;
    provider: string;
    resourceType: string;
    resourceId: string;
  }>();

  // Fetch topology for resource metadata
  const { data: topoData, isLoading: topoLoading } = useTopology(
    sourceType,
    providerName
  );

  // Fetch findings for this provider + resource_type
  const {
    data: findingsData,
    isLoading: findingsLoading,
    isError: findingsError,
  } = useFindings({
    provider: providerName,
    resource_type: resourceType,
    limit: 500,
  });

  // Extract resource metadata from topology
  const resourceMeta: TopologyResource | null = useMemo(() => {
    if (!topoData?.source_types) return null;
    for (const st of topoData.source_types) {
      if (st.name === sourceType) {
        for (const p of st.providers) {
          if (p.name === providerName) {
            for (const svc of p.services) {
              if (svc.resource_type === resourceType) {
                return (
                  svc.resources.find((r) => r.resource_id === resourceId) ??
                  null
                );
              }
            }
          }
        }
      }
    }
    return null;
  }, [topoData, sourceType, providerName, resourceType, resourceId]);

  // Filter findings to this specific resource
  const resourceFindings = useMemo(() => {
    if (!findingsData) return [];
    const items = Array.isArray(findingsData)
      ? findingsData
      : (findingsData as { items?: Finding[] }).items ?? [];
    return items
      .filter((f: Finding) => f.resource_id === resourceId)
      .sort((a: Finding, b: Finding) => {
        const av = SEVERITY_ORDER[a.severity] ?? 4;
        const bv = SEVERITY_ORDER[b.severity] ?? 4;
        return av - bv;
      });
  }, [findingsData, resourceId]);

  const isLoading = topoLoading || findingsLoading;

  const servicePath = `/infrastructure/${encodeURIComponent(sourceType ?? "")}/${encodeURIComponent(providerName ?? "")}/${encodeURIComponent(resourceType ?? "")}`;
  const providerPath = `/infrastructure/${encodeURIComponent(sourceType ?? "")}/${encodeURIComponent(providerName ?? "")}`;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link
            to={servicePath}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="h-5 w-64 bg-zinc-800 rounded animate-pulse" />
            <div className="h-3 w-40 bg-zinc-800 rounded animate-pulse mt-1" />
          </div>
        </div>
        <TableSkeleton rows={8} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Link
            to={servicePath}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <h1 className="text-lg font-semibold text-zinc-100 font-mono break-all">
              {resourceId}
            </h1>
            <div className="flex items-center gap-1.5 text-sm text-zinc-500 mt-0.5">
              <Link
                to="/infrastructure"
                className="hover:text-zinc-300 transition-colors"
              >
                Infrastructure
              </Link>
              <ChevronRight className="h-3 w-3" />
              <Link
                to={providerPath}
                className="hover:text-zinc-300 transition-colors"
              >
                {providerName}
              </Link>
              <ChevronRight className="h-3 w-3" />
              <Link
                to={servicePath}
                className="hover:text-zinc-300 transition-colors"
              >
                {formatResourceType(resourceType ?? "")}
              </Link>
              <ChevronRight className="h-3 w-3" />
              <span className="text-zinc-300 font-mono text-xs truncate max-w-[200px]">
                {resourceId}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Resource info cards */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Box className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-[10px] uppercase tracking-wide text-zinc-500">
              Resource Type
            </span>
          </div>
          <div className="text-sm font-medium text-zinc-200">
            {formatResourceType(resourceType ?? "")}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <Shield className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-[10px] uppercase tracking-wide text-zinc-500">
              Provider
            </span>
          </div>
          <div className="text-sm font-medium text-zinc-200">
            {providerName}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <FileSearch className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-[10px] uppercase tracking-wide text-zinc-500">
              Findings
            </span>
          </div>
          <div className="text-xl font-bold text-zinc-100">
            {resourceMeta
              ? formatCount(resourceMeta.finding_count)
              : resourceFindings.length}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex items-center gap-2 mb-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-zinc-500" />
            <span className="text-[10px] uppercase tracking-wide text-zinc-500">
              Worst Severity
            </span>
          </div>
          {resourceMeta ? (
            <SeverityBadge severity={resourceMeta.worst_severity} className="mt-1" />
          ) : resourceFindings.length > 0 ? (
            <SeverityBadge severity={resourceFindings[0].severity} className="mt-1" />
          ) : (
            <span className="text-sm text-zinc-500">--</span>
          )}
        </div>
      </div>

      {/* Controls affected */}
      {resourceMeta && resourceMeta.controls_affected.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
            Controls Affected ({resourceMeta.controls_affected.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {resourceMeta.controls_affected.map((ctrl) => (
              <Link
                key={ctrl}
                to={`/compliance/${encodeURIComponent(sourceType ?? "")}/${encodeURIComponent(ctrl)}`}
                className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-1 text-xs font-mono text-blue-400 hover:text-blue-300 hover:border-zinc-600 transition-colors"
              >
                {ctrl}
                <ExternalLink className="h-2.5 w-2.5 text-zinc-600" />
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Findings table */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800">
          <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
            Findings ({resourceFindings.length})
          </div>
        </div>

        {findingsError ? (
          <EmptyState
            icon={AlertTriangle}
            title="Failed to load findings"
            description="Could not retrieve findings for this resource."
            className="py-12"
          />
        ) : resourceFindings.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No findings"
            description="No findings found for this resource."
            className="py-12"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500 w-[40%]">Title</TableHead>
                <TableHead className="text-zinc-500">Severity</TableHead>
                <TableHead className="text-zinc-500">Type</TableHead>
                <TableHead className="text-zinc-500">Observed</TableHead>
                <TableHead className="text-zinc-500">Controls</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {resourceFindings.map((finding: Finding) => (
                <TableRow
                  key={finding.id}
                  className="border-zinc-800 hover:bg-zinc-800/50"
                >
                  <TableCell>
                    <Link
                      to={`/findings/${encodeURIComponent(finding.id)}`}
                      className="text-sm text-blue-400 hover:text-blue-300 transition-colors line-clamp-2"
                    >
                      {finding.title}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={finding.severity} />
                  </TableCell>
                  <TableCell>
                    <ObservationBadge type={finding.observation_type} />
                  </TableCell>
                  <TableCell>
                    <span className="text-xs text-zinc-400">
                      {relativeTime(finding.observed_at)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <FindingControls finding={finding} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}
