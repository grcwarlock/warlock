import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ClipboardList,
  Shield,
  ShieldCheck,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
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
import { useRemediations } from "@/hooks/useApi";
import type { Remediation } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const PAGE_SIZE = 25;

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
// POA&Ms Tab
// ---------------------------------------------------------------------------

function POAMsTab() {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);

  const { data, isLoading, isError } = useRemediations({
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  if (isLoading) return <TableSkeleton rows={10} />;

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={ClipboardList}
        title="No POA&Ms found"
        description="No Plans of Action and Milestones have been created yet."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900">
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead>Framework</TableHead>
              <TableHead>Control</TableHead>
              <TableHead>Weakness</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Due Date</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((r: Remediation, idx: number) => {
              const overdue = isOverdue(r.due_date, r.status);
              return (
                <TableRow
                  key={r.id}
                  className={cn(
                    "border-zinc-800/50 hover:bg-zinc-800/50 cursor-pointer transition-colors",
                    idx % 2 === 1 && "bg-zinc-900/50"
                  )}
                  onClick={() => navigate(`/remediation/${r.id}`)}
                >
                  <TableCell className="text-zinc-300 font-mono text-xs">
                    {r.framework ?? "-"}
                  </TableCell>
                  <TableCell className="text-zinc-300 font-mono text-xs">
                    {r.control_id ?? "-"}
                  </TableCell>
                  <TableCell className="text-zinc-200 max-w-[250px] truncate">
                    {r.title}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={r.status} />
                  </TableCell>
                  <TableCell>
                    {r.finding_id ? (
                      <SeverityBadge severity="medium" />
                    ) : (
                      <span className="text-zinc-500 text-xs">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span
                      className={cn(
                        "text-xs",
                        overdue ? "text-red-400 font-medium" : "text-zinc-400"
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
                  <TableCell>
                    <ChevronRight className="h-4 w-4 text-zinc-600" />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-zinc-400">
          <span>
            Showing {page * PAGE_SIZE + 1}-
            {Math.min((page + 1) * PAGE_SIZE, total)} of {total}
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

// ---------------------------------------------------------------------------
// Compensating Controls Tab
// ---------------------------------------------------------------------------

function CompensatingControlsTab() {
  return (
    <EmptyState
      icon={ShieldCheck}
      title="Compensating Controls"
      description="Compensating controls data will appear here when available from the API."
    />
  );
}

// ---------------------------------------------------------------------------
// Risk Acceptances Tab
// ---------------------------------------------------------------------------

function RiskAcceptancesTab() {
  return (
    <EmptyState
      icon={AlertTriangle}
      title="Risk Acceptances"
      description="Risk acceptance records will appear here when available from the API."
    />
  );
}

// ---------------------------------------------------------------------------
// Remediations Tab
// ---------------------------------------------------------------------------

function RemediationsTab() {
  const [page, setPage] = useState(0);
  const { data, isLoading, isError } = useRemediations({
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  if (isLoading) return <TableSkeleton rows={8} />;

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No remediation records"
        description="Remediation records will appear once issues are tracked."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-zinc-800 bg-zinc-900">
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead>Title</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Assigned To</TableHead>
              <TableHead>Due Date</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((r: Remediation, idx: number) => (
              <TableRow
                key={r.id}
                className={cn(
                  "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                  idx % 2 === 1 && "bg-zinc-900/50"
                )}
              >
                <TableCell className="text-zinc-200 max-w-[300px] truncate">
                  {r.title}
                </TableCell>
                <TableCell>
                  <StatusBadge status={r.status} />
                </TableCell>
                <TableCell className="text-zinc-400 text-xs">
                  {r.assigned_to ?? "-"}
                </TableCell>
                <TableCell className="text-zinc-400 text-xs">
                  {formatDate(r.due_date)}
                </TableCell>
                <TableCell className="text-zinc-500 text-xs">
                  {formatDate(r.created_at)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-zinc-400">
          <span>
            Showing {page * PAGE_SIZE + 1}-
            {Math.min((page + 1) * PAGE_SIZE, total)} of {total}
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function RemediationOverview() {
  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Remediation</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          POA&Ms, compensating controls, and risk acceptances
        </p>
      </div>

      <Tabs defaultValue={0}>
        <TabsList>
          <TabsTrigger value={0}>
            <ClipboardList className="h-3.5 w-3.5 mr-1" />
            POA&Ms
          </TabsTrigger>
          <TabsTrigger value={1}>
            <ShieldCheck className="h-3.5 w-3.5 mr-1" />
            Compensating Controls
          </TabsTrigger>
          <TabsTrigger value={2}>
            <AlertTriangle className="h-3.5 w-3.5 mr-1" />
            Risk Acceptances
          </TabsTrigger>
          <TabsTrigger value={3}>
            <Shield className="h-3.5 w-3.5 mr-1" />
            Remediations
          </TabsTrigger>
        </TabsList>

        <TabsContent value={0}>
          <POAMsTab />
        </TabsContent>
        <TabsContent value={1}>
          <CompensatingControlsTab />
        </TabsContent>
        <TabsContent value={2}>
          <RiskAcceptancesTab />
        </TabsContent>
        <TabsContent value={3}>
          <RemediationsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
