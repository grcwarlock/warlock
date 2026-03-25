import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  Cloud,
  Search,
  Shield,
  Eye,
  Key,
  Code2,
  MonitorCheck,
  Server,
  Network,
  ChevronRight,
  Layers,
  AlertTriangle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useTopology } from "@/hooks/useApi";
import type { TopologySourceType, TopologyProvider } from "@/api/types";

// ---------------------------------------------------------------------------
// Icon mapping for source types
// ---------------------------------------------------------------------------

const SOURCE_TYPE_ICONS: Record<string, LucideIcon> = {
  cloud: Cloud,
  cloud_config: Cloud,
  scanner: Search,
  vulnerability: Shield,
  edr: MonitorCheck,
  iam: Key,
  code: Code2,
  code_scan: Code2,
  container: Server,
  network: Network,
  compliance: Eye,
};

function getSourceIcon(name: string): LucideIcon {
  const normalized = name.toLowerCase().replace(/[\s-]+/g, "_");
  return SOURCE_TYPE_ICONS[normalized] ?? Layers;
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function worstSeverityFromProviders(providers: TopologyProvider[]): string {
  let worst = "info";
  let worstRank = 4;

  for (const p of providers) {
    for (const svc of p.services) {
      for (const r of svc.resources) {
        const rank = SEVERITY_ORDER[r.worst_severity] ?? 4;
        if (rank < worstRank) {
          worstRank = rank;
          worst = r.worst_severity;
        }
      }
    }
  }
  return worst;
}

function worstSeverityFromSingle(provider: TopologyProvider): string {
  let worst = "info";
  let worstRank = 4;

  for (const svc of provider.services) {
    for (const r of svc.resources) {
      const rank = SEVERITY_ORDER[r.worst_severity] ?? 4;
      if (rank < worstRank) {
        worstRank = rank;
        worst = r.worst_severity;
      }
    }
  }
  return worst;
}

// ---------------------------------------------------------------------------
// Format helpers
// ---------------------------------------------------------------------------

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatSourceTypeName(name: string): string {
  return name
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Source type card
// ---------------------------------------------------------------------------

function SourceTypeCard({
  sourceType,
  isSelected,
  onClick,
}: {
  sourceType: TopologySourceType;
  isSelected: boolean;
  onClick: () => void;
}) {
  const Icon = getSourceIcon(sourceType.name);
  const worstSev = worstSeverityFromProviders(sourceType.providers);

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full rounded-xl border p-4 text-left transition-all",
        isSelected
          ? "border-blue-500/40 bg-blue-500/5 ring-1 ring-blue-500/20"
          : "border-zinc-800 bg-zinc-900 hover:border-zinc-700 hover:bg-zinc-800/50"
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className={cn(
            "flex h-9 w-9 items-center justify-center rounded-lg",
            isSelected ? "bg-blue-500/10" : "bg-zinc-800"
          )}
        >
          <Icon
            className={cn(
              "h-4.5 w-4.5",
              isSelected ? "text-blue-400" : "text-zinc-400"
            )}
          />
        </div>
        {worstSev !== "info" && (
          <SeverityBadge severity={worstSev} />
        )}
      </div>

      <div className="text-sm font-medium text-zinc-100 mb-1">
        {formatSourceTypeName(sourceType.name)}
      </div>

      <div className="flex items-center gap-3 text-[11px] text-zinc-500">
        <span>
          <span className="text-zinc-300 font-medium">
            {formatCount(sourceType.finding_count)}
          </span>{" "}
          findings
        </span>
        <span className="text-zinc-700">|</span>
        <span>
          <span className="text-zinc-300 font-medium">
            {sourceType.providers.length}
          </span>{" "}
          {sourceType.providers.length === 1 ? "provider" : "providers"}
        </span>
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Provider card (in right column)
// ---------------------------------------------------------------------------

function ProviderCard({
  provider,
  sourceTypeName,
}: {
  provider: TopologyProvider;
  sourceTypeName: string;
}) {
  const worstSev = worstSeverityFromSingle(provider);
  const serviceCount = provider.services.length;
  const resourceCount = provider.services.reduce(
    (sum, s) => sum + s.resources.length,
    0
  );

  return (
    <Link
      to={`/infrastructure/${encodeURIComponent(sourceTypeName)}/${encodeURIComponent(provider.name)}`}
      className="group rounded-xl border border-zinc-800 bg-zinc-900 p-4 transition-all hover:border-zinc-700 hover:bg-zinc-800/50 block"
    >
      <div className="flex items-start justify-between mb-3">
        <div className="text-sm font-medium text-zinc-100 group-hover:text-white transition-colors">
          {provider.name}
        </div>
        <ChevronRight className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition-colors shrink-0 mt-0.5" />
      </div>

      <div className="flex items-center gap-2 mb-3">
        {worstSev !== "info" && <SeverityBadge severity={worstSev} />}
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div>
          <div className="text-lg font-bold text-zinc-100">
            {formatCount(provider.finding_count)}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Findings
          </div>
        </div>
        <div>
          <div className="text-lg font-bold text-zinc-100">{serviceCount}</div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Services
          </div>
        </div>
        <div>
          <div className="text-lg font-bold text-zinc-100">
            {formatCount(resourceCount)}
          </div>
          <div className="text-[10px] uppercase tracking-wide text-zinc-500">
            Resources
          </div>
        </div>
      </div>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function InfrastructureOverview() {
  const { data, isLoading, isError } = useTopology();
  const [selectedSourceType, setSelectedSourceType] = useState<string | null>(null);

  const sourceTypes = data?.source_types ?? [];
  const totalFindings = data?.total_findings ?? 0;

  // Auto-select first source type when data loads
  const activeSourceType = useMemo(() => {
    if (selectedSourceType) {
      return sourceTypes.find((st) => st.name === selectedSourceType) ?? null;
    }
    return sourceTypes.length > 0 ? sourceTypes[0] : null;
  }, [sourceTypes, selectedSourceType]);

  const sortedSourceTypes = useMemo(() => {
    return [...sourceTypes].sort((a, b) => b.finding_count - a.finding_count);
  }, [sourceTypes]);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Infrastructure</h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            Resource topology across all connected sources
          </p>
        </div>
        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-4 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} />
            ))}
          </div>
          <div className="col-span-8 grid grid-cols-2 gap-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <CardSkeleton key={i} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (isError || sourceTypes.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Infrastructure</h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            Resource topology across all connected sources
          </p>
        </div>
        <EmptyState
          icon={AlertTriangle}
          title="No infrastructure data available"
          description="Run a pipeline collection to populate the resource topology."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">Infrastructure</h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            Resource topology across all connected sources
          </p>
        </div>
        <div className="flex items-center gap-4 text-sm text-zinc-400">
          <span>
            <span className="text-zinc-100 font-medium">
              {formatCount(totalFindings)}
            </span>{" "}
            total findings
          </span>
          <span className="text-zinc-700">|</span>
          <span>
            <span className="text-zinc-100 font-medium">
              {sourceTypes.length}
            </span>{" "}
            source types
          </span>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-12 gap-6">
        {/* Left column: source type list */}
        <div className="col-span-4 space-y-2">
          <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-2 px-1">
            Source Types
          </div>
          {sortedSourceTypes.map((st) => (
            <SourceTypeCard
              key={st.name}
              sourceType={st}
              isSelected={activeSourceType?.name === st.name}
              onClick={() => setSelectedSourceType(st.name)}
            />
          ))}
        </div>

        {/* Right column: providers for selected source type */}
        <div className="col-span-8">
          {activeSourceType ? (
            <>
              <div className="flex items-center justify-between mb-3 px-1">
                <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
                  {formatSourceTypeName(activeSourceType.name)} Providers
                </div>
                <div className="text-[11px] text-zinc-500">
                  {activeSourceType.providers.length}{" "}
                  {activeSourceType.providers.length === 1
                    ? "provider"
                    : "providers"}
                  {" / "}
                  {formatCount(activeSourceType.finding_count)} findings
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {[...activeSourceType.providers]
                  .sort((a, b) => b.finding_count - a.finding_count)
                  .map((provider) => (
                    <ProviderCard
                      key={provider.name}
                      provider={provider}
                      sourceTypeName={activeSourceType.name}
                    />
                  ))}
              </div>
            </>
          ) : (
            <EmptyState
              icon={Layers}
              title="Select a source type"
              description="Choose a source type from the left to view its providers."
            />
          )}
        </div>
      </div>
    </div>
  );
}
