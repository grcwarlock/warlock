import { useState } from "react";
import {
  BookOpen,
  CheckCircle2,
  FileCheck,
  Hash,
  Loader2,
  ScrollText,
  ShieldCheck,
  XCircle,
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
import { StatusBadge } from "@/components/shared/StatusBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  useEngagements,
  useAuditTrail,
  useVerifyAuditTrail,
  useAttestations,
} from "@/hooks/useApi";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function truncateHash(hash: string): string {
  if (hash.length <= 16) return hash;
  return hash.slice(0, 8) + "..." + hash.slice(-8);
}

// ---------------------------------------------------------------------------
// Engagements Tab
// ---------------------------------------------------------------------------

function EngagementsTab() {
  const { data: engagements, isLoading, isError } = useEngagements();

  if (isLoading) return <TableSkeleton rows={6} />;

  const items = Array.isArray(engagements) ? engagements : [];

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={BookOpen}
        title="No audit engagements"
        description="No audit engagements have been created yet."
      />
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900">
      <Table>
        <TableHeader>
          <TableRow className="border-zinc-800 hover:bg-transparent">
            <TableHead>Name</TableHead>
            <TableHead>Firm</TableHead>
            <TableHead>Framework</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Period</TableHead>
            <TableHead>Controls</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((eng, idx) => (
            <TableRow
              key={eng.id}
              className={cn(
                "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                idx % 2 === 1 && "bg-zinc-900/50"
              )}
            >
              <TableCell className="text-zinc-200 font-medium">
                {eng.name}
              </TableCell>
              <TableCell className="text-zinc-400 text-xs">
                {eng.auditor_firm ?? "-"}
              </TableCell>
              <TableCell className="text-zinc-300 font-mono text-xs">
                {eng.framework}
              </TableCell>
              <TableCell>
                <StatusBadge status={eng.status} />
              </TableCell>
              <TableCell className="text-zinc-400 text-xs">
                {formatDate(eng.period_start)} - {formatDate(eng.period_end)}
              </TableCell>
              <TableCell className="text-zinc-400 text-xs">
                {eng.in_scope_controls.length} in scope
                {eng.excluded_controls.length > 0 && (
                  <span className="text-zinc-600 ml-1">
                    ({eng.excluded_controls.length} excluded)
                  </span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit Trail Tab
// ---------------------------------------------------------------------------

function AuditTrailTab() {
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const { data, isLoading, isError } = useAuditTrail(pageSize, page * pageSize);
  const {
    data: verification,
    isLoading: verifying,
    refetch: verifyChain,
  } = useVerifyAuditTrail();

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  if (isLoading) return <TableSkeleton rows={12} />;

  return (
    <div className="space-y-4">
      {/* Verify bar */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-zinc-400">
          {total.toLocaleString()} hash-chained audit entries
        </p>
        <div className="flex items-center gap-3">
          {verification && (
            <div
              className={cn(
                "flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs",
                verification.valid
                  ? "border-green-500/20 bg-green-500/10 text-green-400"
                  : "border-red-500/20 bg-red-500/10 text-red-400"
              )}
            >
              {verification.valid ? (
                <CheckCircle2 className="h-3.5 w-3.5" />
              ) : (
                <XCircle className="h-3.5 w-3.5" />
              )}
              {verification.valid
                ? `Chain verified (${verification.total_entries} entries)`
                : `Chain broken! ${verification.errors.length} errors`}
            </div>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => verifyChain()}
            disabled={verifying}
          >
            {verifying ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
            ) : (
              <Hash className="h-3.5 w-3.5 mr-1" />
            )}
            Verify Chain
          </Button>
        </div>
      </div>

      {/* Entries */}
      {isError || items.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No audit trail entries"
          description="Audit trail entries will appear as operations are performed."
        />
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="w-16">Seq</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Entity Type</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>Hash</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((entry, idx) => (
                <TableRow
                  key={entry.id}
                  className={cn(
                    "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                    idx % 2 === 1 && "bg-zinc-900/50"
                  )}
                >
                  <TableCell className="text-zinc-500 font-mono text-xs">
                    #{entry.sequence}
                  </TableCell>
                  <TableCell className="text-zinc-200 text-xs">
                    {entry.action}
                  </TableCell>
                  <TableCell className="text-zinc-400 font-mono text-xs">
                    {entry.entity_type}
                  </TableCell>
                  <TableCell className="text-zinc-400 text-xs">
                    {entry.actor}
                  </TableCell>
                  <TableCell className="text-zinc-500 text-xs">
                    {formatDateTime(entry.created_at)}
                  </TableCell>
                  <TableCell
                    className="text-zinc-600 font-mono text-[10px]"
                    title={entry.entry_hash}
                  >
                    {truncateHash(entry.entry_hash)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Pagination */}
      {total > pageSize && (
        <div className="flex items-center justify-between text-sm text-zinc-400">
          <span>
            Showing {page * pageSize + 1}-
            {Math.min((page + 1) * pageSize, total)} of{" "}
            {total.toLocaleString()}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon-sm"
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0}
            >
              &larr;
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
              &rarr;
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attestations Tab
// ---------------------------------------------------------------------------

function AttestationsTab() {
  const { data: attestations, isLoading, isError } = useAttestations();

  if (isLoading) return <TableSkeleton rows={6} />;

  const items = Array.isArray(attestations) ? attestations : [];

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={FileCheck}
        title="No attestations"
        description="No attestation records found."
      />
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900">
      <Table>
        <TableHeader>
          <TableRow className="border-zinc-800 hover:bg-transparent">
            <TableHead>Framework</TableHead>
            <TableHead>Control</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Prepared By</TableHead>
            <TableHead>Approved By</TableHead>
            <TableHead>Created</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((att, idx) => (
            <TableRow
              key={att.id}
              className={cn(
                "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                idx % 2 === 1 && "bg-zinc-900/50"
              )}
            >
              <TableCell className="text-zinc-300 font-mono text-xs">
                {att.framework}
              </TableCell>
              <TableCell className="text-zinc-400 font-mono text-xs">
                {att.control_id ?? "All"}
              </TableCell>
              <TableCell>
                <StatusBadge status={att.status} />
              </TableCell>
              <TableCell className="text-zinc-400 text-xs">
                {att.prepared_by ?? "-"}
              </TableCell>
              <TableCell className="text-zinc-400 text-xs">
                {att.approved_by ?? "-"}
              </TableCell>
              <TableCell className="text-zinc-500 text-xs">
                {formatDate(att.created_at)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function AuditOverview() {
  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Audit</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Engagements, hash-chained audit trail, and attestations
        </p>
      </div>

      <Tabs defaultValue={0}>
        <TabsList>
          <TabsTrigger value={0}>
            <BookOpen className="h-3.5 w-3.5 mr-1" />
            Engagements
          </TabsTrigger>
          <TabsTrigger value={1}>
            <ScrollText className="h-3.5 w-3.5 mr-1" />
            Audit Trail
          </TabsTrigger>
          <TabsTrigger value={2}>
            <ShieldCheck className="h-3.5 w-3.5 mr-1" />
            Attestations
          </TabsTrigger>
        </TabsList>

        <TabsContent value={0}>
          <EngagementsTab />
        </TabsContent>
        <TabsContent value={1}>
          <AuditTrailTab />
        </TabsContent>
        <TabsContent value={2}>
          <AttestationsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
