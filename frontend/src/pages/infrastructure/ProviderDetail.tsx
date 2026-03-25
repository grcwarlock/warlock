import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ChevronRight,
  Layers,
  AlertTriangle,
  Server,
  FileSearch,
  Box,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useTopology } from "@/hooks/useApi";
import type { TopologyService } from "@/api/types";

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

function worstSeverityFromService(svc: TopologyService): string {
  let worst = "info";
  let worstRank = 4;
  for (const r of svc.resources) {
    const rank = SEVERITY_ORDER[r.worst_severity] ?? 4;
    if (rank < worstRank) {
      worstRank = rank;
      worst = r.worst_severity;
    }
  }
  return worst;
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatSourceTypeName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatResourceType(rt: string): string {
  return rt
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Severity bar visualization
// ---------------------------------------------------------------------------

function SeverityBar({ service }: { service: TopologyService }) {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const r of service.resources) {
    const sev = r.worst_severity || "info";
    counts[sev] = (counts[sev] || 0) + r.finding_count;
  }

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
    info: "bg-zinc-600",
  };

  return (
    <div className="flex h-1.5 w-full rounded-full overflow-hidden bg-zinc-800">
      {["critical", "high", "medium", "low", "info"].map((sev) => {
        const pct = (counts[sev] / total) * 100;
        if (pct === 0) return null;
        return (
          <div
            key={sev}
            className={cn("h-full", colors[sev])}
            style={{ width: `${pct}%` }}
          />
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Service card
// ---------------------------------------------------------------------------

function ServiceCard({
  service,
  sourceType,
  providerName,
}: {
  service: TopologyService;
  sourceType: string;
  providerName: string;
}) {
  const worstSev = worstSeverityFromService(service);
  const uniqueControls = new Set(
    service.resources.flatMap((r) => r.controls_affected)
  );

  return (
    <Link
      to={`/infrastructure/${encodeURIComponent(sourceType)}/${encodeURIComponent(providerName)}/${encodeURIComponent(service.resource_type)}`}
      className="group rounded-xl border border-zinc-800 bg-zinc-900 p-4 transition-all hover:border-zinc-700 hover:bg-zinc-800/50 block"
    >
      <div className="flex items-start justify-between mb-2">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500 mb-1">
            {service.event_type}
          </div>
          <div className="text-sm font-medium text-zinc-100 group-hover:text-white transition-colors">
            {formatResourceType(service.resource_type)}
          </div>
        </div>
        <ChevronRight className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition-colors shrink-0 mt-1" />
      </div>

      <SeverityBar service={service} />

      <div className="grid grid-cols-3 gap-3 mt-3">
        <div>
          <div className="text-base font-bold text-zinc-100">
            {formatCount(service.finding_count)}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Findings
          </div>
        </div>
        <div>
          <div className="text-base font-bold text-zinc-100">
            {service.resources.length}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Resources
          </div>
        </div>
        <div>
          <div className="text-base font-bold text-zinc-100">
            {uniqueControls.size}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Controls
          </div>
        </div>
      </div>

      {worstSev !== "info" && (
        <div className="mt-3 pt-3 border-t border-zinc-800">
          <SeverityBadge severity={worstSev} />
        </div>
      )}
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ProviderDetail() {
  const { sourceType, provider: providerName } = useParams<{
    sourceType: string;
    provider: string;
  }>();
  const { data, isLoading, isError } = useTopology(sourceType, providerName);

  const providerData = useMemo(() => {
    if (!data?.source_types) return null;
    for (const st of data.source_types) {
      if (st.name === sourceType) {
        const found = st.providers.find((p) => p.name === providerName);
        if (found) return found;
      }
    }
    return null;
  }, [data, sourceType, providerName]);

  const sortedServices = useMemo(() => {
    if (!providerData) return [];
    return [...providerData.services].sort(
      (a, b) => b.finding_count - a.finding_count
    );
  }, [providerData]);

  const totalResources = useMemo(() => {
    if (!providerData) return 0;
    return providerData.services.reduce(
      (sum, s) => sum + s.resources.length,
      0
    );
  }, [providerData]);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link
            to="/infrastructure"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="h-5 w-40 bg-zinc-800 rounded animate-pulse" />
            <div className="h-3 w-24 bg-zinc-800 rounded animate-pulse mt-1" />
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      </div>
    );
  }

  if (isError || !providerData) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link
            to="/infrastructure"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <h1 className="text-lg font-semibold text-zinc-100">
            {providerName ?? "Provider"}
          </h1>
        </div>
        <EmptyState
          icon={AlertTriangle}
          title="Provider not found"
          description="This provider has no topology data. Check your pipeline configuration."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Link
            to="/infrastructure"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-zinc-100">
                {providerName}
              </h1>
            </div>
            <div className="flex items-center gap-1.5 text-sm text-zinc-500 mt-0.5">
              <Link
                to="/infrastructure"
                className="hover:text-zinc-300 transition-colors"
              >
                Infrastructure
              </Link>
              <ChevronRight className="h-3 w-3" />
              <span className="text-zinc-400">
                {formatSourceTypeName(sourceType ?? "")}
              </span>
              <ChevronRight className="h-3 w-3" />
              <span className="text-zinc-300">{providerName}</span>
            </div>
          </div>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 mb-2">
            <FileSearch className="h-4 w-4 text-zinc-500" />
            <span className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Findings
            </span>
          </div>
          <div className="text-2xl font-bold text-zinc-100">
            {formatCount(providerData.finding_count)}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="h-4 w-4 text-zinc-500" />
            <span className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Services
            </span>
          </div>
          <div className="text-2xl font-bold text-zinc-100">
            {providerData.services.length}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Box className="h-4 w-4 text-zinc-500" />
            <span className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Resources
            </span>
          </div>
          <div className="text-2xl font-bold text-zinc-100">
            {formatCount(totalResources)}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Server className="h-4 w-4 text-zinc-500" />
            <span className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Source Type
            </span>
          </div>
          <div className="text-base font-medium text-zinc-100 mt-1">
            {formatSourceTypeName(sourceType ?? "")}
          </div>
        </div>
      </div>

      {/* Service cards grid */}
      <div>
        <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3 px-1">
          Services ({sortedServices.length})
        </div>
        {sortedServices.length === 0 ? (
          <EmptyState
            icon={Layers}
            title="No services found"
            description="This provider has no services with findings."
          />
        ) : (
          <div className="grid grid-cols-3 gap-3">
            {sortedServices.map((svc) => (
              <ServiceCard
                key={`${svc.event_type}-${svc.resource_type}`}
                service={svc}
                sourceType={sourceType ?? ""}
                providerName={providerName ?? ""}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
