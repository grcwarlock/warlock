import { Activity, Server } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { CardSkeleton, TableSkeleton } from "@/components/shared/LoadingState";
import { usePipelineStatus, useConnectors } from "@/hooks/useApi";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

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

export default function PipelineOverview() {
  const { data: pipeline, isLoading: pipeLoading } = usePipelineStatus();
  const { data: connectors, isLoading: connLoading } = useConnectors();

  const isLoading = pipeLoading || connLoading;
  const connectorList = Array.isArray(connectors) ? connectors : [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Pipeline</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Data collection pipeline status and connector health
        </p>
      </div>

      {isLoading && (
        <>
          <div className="grid grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <CardSkeleton key={i} />
            ))}
          </div>
          <TableSkeleton rows={8} />
        </>
      )}

      {!isLoading && (
        <>
          {/* Pipeline status cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                Status
              </div>
              <div className="flex items-center gap-2 mt-1">
                <div
                  className={cn(
                    "h-2.5 w-2.5 rounded-full",
                    pipeline?.running
                      ? "bg-amber-400 animate-pulse"
                      : "bg-green-400",
                  )}
                />
                <span className="text-lg font-bold text-zinc-100">
                  {pipeline?.running ? "Running" : "Idle"}
                </span>
              </div>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                Last Run
              </div>
              <div className="text-lg font-bold text-zinc-100 mt-1">
                {relativeTime(
                  pipeline?.last_run?.completed_at ??
                    pipeline?.last_run?.started_at,
                )}
              </div>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                Total Events
              </div>
              <div className="text-lg font-bold text-zinc-100 mt-1">
                {(pipeline?.totals?.raw_events ?? 0).toLocaleString()}
              </div>
            </div>
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                Connectors
              </div>
              <div className="text-lg font-bold text-zinc-100 mt-1">
                {connectorList.length}
              </div>
            </div>
          </div>

          {/* Connector list */}
          {connectorList.length === 0 ? (
            <EmptyState
              icon={Server}
              title="No connectors"
              description="No connectors configured yet."
            />
          ) : (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead>Connector</TableHead>
                    <TableHead>Source Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead>Errors</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {connectorList.map((c) => (
                    <TableRow
                      key={c.name ?? c.id}
                      className="border-zinc-800/50 hover:bg-zinc-800/50"
                    >
                      <TableCell className="font-medium text-zinc-200">
                        <div className="flex items-center gap-2">
                          <Activity className="h-3.5 w-3.5 text-zinc-500" />
                          {c.name ?? c.provider}
                        </div>
                      </TableCell>
                      <TableCell className="text-zinc-400">
                        {c.source_type ?? "custom"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            c.status === "success" ? "default" : "secondary"
                          }
                          className={cn(
                            "text-[10px] uppercase",
                            c.status === "success" && "text-green-400",
                            c.status === "error" && "text-red-400",
                          )}
                        >
                          {c.status ?? "unknown"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-zinc-400 tabular-nums">
                        {(c.event_count ?? 0).toLocaleString()}
                      </TableCell>
                      <TableCell
                        className={cn(
                          "tabular-nums",
                          c.error_count > 0 ? "text-red-400" : "text-zinc-500",
                        )}
                      >
                        {c.error_count ?? 0}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
