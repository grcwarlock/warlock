import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  ClipboardList,
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
import { StatusBadge } from "@/components/shared/StatusBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useRemediations } from "@/hooks/useApi";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PAGE_SIZE = 25;

const STATUS_OPTIONS = ["open", "assigned", "in_progress", "verification", "closed"];

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function isOverdue(dueDate: string | null | undefined, status: string): boolean {
  if (!dueDate || status === "closed" || status === "verified") return false;
  return new Date(dueDate).getTime() < Date.now();
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function RemediationOverview() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");

  const { data, isLoading, isError } = useRemediations({
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
        <h1 className="text-xl font-semibold text-zinc-100">Remediation</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Plans of Action and Milestones ({total.toLocaleString()} total)
        </p>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
          className="h-8 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
        >
          <option value="" className="bg-zinc-900">
            All Statuses
          </option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s} className="bg-zinc-900">
              {s
                .split("_")
                .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                .join(" ")}
            </option>
          ))}
        </select>

        {statusFilter && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStatusFilter("");
              setPage(0);
            }}
          >
            Clear filter
          </Button>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <TableSkeleton rows={10} />
      ) : isError || items.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title="No remediations found"
          description={
            statusFilter
              ? "Try adjusting your filter."
              : "No Plans of Action and Milestones have been created yet."
          }
        />
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Assigned To</TableHead>
                <TableHead>Framework</TableHead>
                <TableHead>Control</TableHead>
                <TableHead>Due Date</TableHead>
                <TableHead>Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((r, idx) => {
                const overdue = isOverdue(r.due_date, r.status);
                return (
                  <TableRow
                    key={r.id}
                    className={cn(
                      "border-zinc-800/50 hover:bg-zinc-800/50 cursor-pointer transition-colors",
                      idx % 2 === 1 && "bg-zinc-900/50",
                    )}
                    onClick={() => navigate(`/remediation/${r.id}`)}
                  >
                    <TableCell className="text-zinc-200 max-w-[250px] truncate">
                      {r.title}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={r.status} />
                    </TableCell>
                    <TableCell className="text-zinc-400 text-xs">
                      {r.assigned_to ?? "Unassigned"}
                    </TableCell>
                    <TableCell className="text-zinc-300 font-mono text-xs">
                      {r.framework ?? "-"}
                    </TableCell>
                    <TableCell className="text-zinc-300 font-mono text-xs">
                      {r.control_id ?? "-"}
                    </TableCell>
                    <TableCell>
                      <span
                        className={cn(
                          "text-xs",
                          overdue ? "text-red-400 font-medium" : "text-zinc-400",
                        )}
                      >
                        {formatDate(r.due_date)}
                      </span>
                      {overdue && (
                        <span className="ml-1.5 inline-flex items-center rounded-md border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase text-red-400">
                          Overdue
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-zinc-500 text-xs">
                      {formatDate(r.created_at)}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-zinc-400">
          <span>
            Showing {page * PAGE_SIZE + 1}-
            {Math.min((page + 1) * PAGE_SIZE, total)} of {total.toLocaleString()}
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
