import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Play, Search, Plug, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useConnectors, usePipelineStatus, useTriggerCollect } from "@/hooks/useApi";
import type { Connector } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function statusIcon(status: string | null) {
  switch (status) {
    case "success":
      return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
    case "error":
    case "failed":
      return <XCircle className="h-3.5 w-3.5 text-red-400" />;
    case "running":
      return <Play className="h-3.5 w-3.5 text-blue-400" />;
    default:
      return <AlertTriangle className="h-3.5 w-3.5 text-zinc-500" />;
  }
}

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

function groupBySourceType(connectors: Connector[]): Record<string, Connector[]> {
  const groups: Record<string, Connector[]> = {};
  for (const c of connectors) {
    const key = c.source_type || "other";
    if (!groups[key]) groups[key] = [];
    groups[key].push(c);
  }
  return groups;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function PipelineHeader() {
  const { data: pipeline } = usePipelineStatus();
  const triggerCollect = useTriggerCollect();

  const isRunning = pipeline?.running ?? false;

  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Pipeline</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          {pipeline?.totals
            ? `${pipeline.totals.raw_events.toLocaleString()} events, ${pipeline.totals.findings.toLocaleString()} findings, ${pipeline.totals.control_results.toLocaleString()} results`
            : "Connector overview and pipeline control"}
        </p>
      </div>
      <Button
        variant="default"
        size="default"
        disabled={isRunning || triggerCollect.isPending}
        onClick={() => triggerCollect.mutate(undefined)}
      >
        <Play className="h-4 w-4" />
        {isRunning ? "Running..." : "Run Pipeline"}
      </Button>
    </div>
  );
}

function ConnectorCard({ connector }: { connector: Connector }) {
  return (
    <Link
      to={`/pipeline/${encodeURIComponent(connector.provider)}`}
      className={cn(
        "rounded-lg border border-zinc-800 bg-zinc-900 p-3",
        "hover:border-zinc-700 hover:bg-zinc-800/60 transition-all",
        "flex flex-col gap-2"
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 min-w-0">
          <div className={cn("h-2.5 w-2.5 rounded-full shrink-0", statusDot(connector.last_status))} />
          <span className="text-sm font-medium text-zinc-200 truncate">
            {connector.provider}
          </span>
        </div>
        {statusIcon(connector.last_status)}
      </div>
      <div className="flex items-center justify-between text-[10px] text-zinc-500">
        <span className="uppercase tracking-wider">{connector.source_type}</span>
        <span>{relativeTime(connector.last_run)}</span>
      </div>
    </Link>
  );
}

function ConnectorGroup({
  sourceType,
  connectors,
}: {
  sourceType: string;
  connectors: Connector[];
}) {
  const successCount = connectors.filter((c) => c.last_status === "success").length;
  const errorCount = connectors.filter(
    (c) => c.last_status === "error" || c.last_status === "failed"
  ).length;

  return (
    <div>
      <div className="flex items-center gap-3 mb-2">
        <h2 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 font-medium">
          {sourceType}
        </h2>
        <span className="text-[10px] text-zinc-600">
          {connectors.length} connectors
        </span>
        {successCount > 0 && (
          <span className="text-[10px] text-green-500">{successCount} ok</span>
        )}
        {errorCount > 0 && (
          <span className="text-[10px] text-red-400">{errorCount} failed</span>
        )}
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
        {connectors.map((c) => (
          <ConnectorCard key={c.provider} connector={c} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function PipelineOverview() {
  const { data: connectors, isLoading, isError } = useConnectors();
  const [search, setSearch] = useState("");

  const allConnectors: Connector[] = useMemo(() => {
    if (!connectors) return [];
    return Array.isArray(connectors) ? connectors : [];
  }, [connectors]);

  const filtered = useMemo(() => {
    if (!search.trim()) return allConnectors;
    const q = search.toLowerCase();
    return allConnectors.filter(
      (c) =>
        c.provider.toLowerCase().includes(q) ||
        c.source_type.toLowerCase().includes(q)
    );
  }, [allConnectors, search]);

  const grouped = useMemo(() => {
    const groups = groupBySourceType(filtered);
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [filtered]);

  const totalEnabled = allConnectors.filter((c) => c.enabled).length;
  const totalSuccess = allConnectors.filter((c) => c.last_status === "success").length;
  const totalError = allConnectors.filter(
    (c) => c.last_status === "error" || c.last_status === "failed"
  ).length;

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <PipelineHeader />

      {/* Stats bar */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-4 py-2.5">
        <div className="flex items-center gap-6 text-xs text-zinc-400 flex-wrap">
          <div className="flex items-center gap-2">
            <Plug className="h-3 w-3 text-zinc-500" />
            <span className="text-zinc-300 font-medium">
              {allConnectors.length} connectors
            </span>
          </div>
          <span>{totalEnabled} enabled</span>
          <span className="text-green-400">{totalSuccess} succeeded</span>
          {totalError > 0 && (
            <span className="text-red-400">{totalError} failed</span>
          )}
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
        <Input
          placeholder="Search connectors..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-8"
        />
      </div>

      {/* Content */}
      {isLoading && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
          {Array.from({ length: 15 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      )}

      {isError && (
        <EmptyState
          icon={AlertTriangle}
          title="Failed to load connectors"
          description="Could not fetch connector data from the API."
        />
      )}

      {!isLoading && !isError && filtered.length === 0 && (
        <EmptyState
          icon={Plug}
          title={search ? "No matching connectors" : "No connectors configured"}
          description={
            search
              ? `No connectors match "${search}". Try a different search.`
              : "Run the pipeline to discover available connectors."
          }
        />
      )}

      {!isLoading && !isError && grouped.length > 0 && (
        <div className="space-y-6">
          {grouped.map(([sourceType, conns]) => (
            <ConnectorGroup
              key={sourceType}
              sourceType={sourceType}
              connectors={conns}
            />
          ))}
        </div>
      )}
    </div>
  );
}
