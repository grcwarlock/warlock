import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useIssues } from "@/hooks/useApi";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PAGE_SIZE = 25;

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

const SEVERITY_OPTIONS = ["", "critical", "high", "medium", "low"];
const STATUS_OPTIONS = ["", "open", "assigned", "in_progress", "remediated", "verified", "closed", "risk_accepted"];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IncidentsList() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const { data, isLoading, isError } = useIssues({
    priority: severityFilter || undefined,
    status: statusFilter || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Incidents</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Security incidents and issue tracking ({total.toLocaleString()} total)
        </p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={severityFilter}
          onChange={(e) => {
            setSeverityFilter(e.target.value);
            setPage(0);
          }}
          className="h-8 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
        >
          <option value="" className="bg-zinc-900">All Severities</option>
          {SEVERITY_OPTIONS.filter(Boolean).map((s) => (
            <option key={s} value={s} className="bg-zinc-900">
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>

        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
          className="h-8 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
        >
          <option value="" className="bg-zinc-900">All Statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map((s) => (
            <option key={s} value={s} className="bg-zinc-900">
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <TableSkeleton rows={10} />
      ) : isError || items.length === 0 ? (
        <EmptyState
          icon={AlertTriangle}
          title="No incidents found"
          description={
            severityFilter || statusFilter
              ? "Try adjusting your filters."
              : "No incidents have been reported."
          }
        />
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Assigned To</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((issue, idx) => (
                <TableRow
                  key={issue.id}
                  className={cn(
                    "border-zinc-800/50 hover:bg-zinc-800/50 cursor-pointer transition-colors",
                    idx % 2 === 1 && "bg-zinc-900/50"
                  )}
                  onClick={() => navigate(`/incidents/${issue.id}`)}
                >
                  <TableCell>
                    <SeverityBadge severity={issue.priority} />
                  </TableCell>
                  <TableCell className="text-zinc-200 max-w-[350px] truncate">
                    {issue.title}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={issue.status} />
                  </TableCell>
                  <TableCell className="text-zinc-400 text-xs font-mono">
                    {issue.source ?? "-"}
                  </TableCell>
                  <TableCell className="text-zinc-400 text-xs">
                    {issue.assigned_to ?? "Unassigned"}
                  </TableCell>
                  <TableCell className="text-zinc-500 text-xs">
                    {relativeTime(issue.created_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-zinc-400">
          <span>
            Showing {page * PAGE_SIZE + 1}-
            {Math.min((page + 1) * PAGE_SIZE, total)} of{" "}
            {total.toLocaleString()}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="text-xs text-zinc-500">
              Page {page + 1} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
              disabled={page >= totalPages - 1}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
