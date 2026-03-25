import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  Search,
  ShieldAlert,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { useFindings } from "@/hooks/useApi";
import type { Finding } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

const PAGE_SIZE = 25;

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];
const SOURCE_OPTIONS = [
  "cloud_config",
  "vulnerability",
  "iam",
  "network",
  "code_scan",
  "container",
  "compliance",
];
const PROVIDER_OPTIONS = ["aws", "azure", "gcp", "github", "okta", "crowdstrike"];
const OBS_TYPE_OPTIONS = [
  "sighting",
  "finding",
  "policy_violation",
  "misconfiguration",
  "vulnerability",
];

type SortField = "title" | "severity" | "source" | "provider" | "observed_at";
type SortDir = "asc" | "desc";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function sortFindings(
  items: Finding[],
  field: SortField,
  dir: SortDir,
): Finding[] {
  const sorted = [...items].sort((a, b) => {
    if (field === "severity") {
      const av = SEVERITY_ORDER[a.severity] ?? 5;
      const bv = SEVERITY_ORDER[b.severity] ?? 5;
      return av - bv;
    }
    if (field === "observed_at") {
      return (
        new Date(a.observed_at).getTime() - new Date(b.observed_at).getTime()
      );
    }
    const av = (a[field] ?? "").toString().toLowerCase();
    const bv = (b[field] ?? "").toString().toLowerCase();
    return av.localeCompare(bv);
  });
  return dir === "desc" ? sorted.reverse() : sorted;
}

// ---------------------------------------------------------------------------
// Select component (shared styling)
// ---------------------------------------------------------------------------

function FilterSelect({
  value,
  onChange,
  placeholder,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  options: string[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-8 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
    >
      <option value="" className="bg-zinc-900">
        {placeholder}
      </option>
      {options.map((s) => (
        <option key={s} value={s} className="bg-zinc-900">
          {s
            .split("_")
            .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
            .join(" ")}
        </option>
      ))}
    </select>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function FindingsTable() {
  const navigate = useNavigate();

  const [page, setPage] = useState(0);
  const [severityFilter, setSeverityFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [providerFilter, setProviderFilter] = useState("");
  const [obsTypeFilter, setObsTypeFilter] = useState("");
  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("observed_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const { data, isLoading, isError } = useFindings({
    severity: severityFilter || undefined,
    source: sourceFilter || undefined,
    provider: providerFilter || undefined,
    observation_type: obsTypeFilter || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  // Client-side search filter on the current page
  const filtered = search
    ? items.filter(
        (f) =>
          f.title.toLowerCase().includes(search.toLowerCase()) ||
          (f.resource_id ?? "").toLowerCase().includes(search.toLowerCase()) ||
          f.source.toLowerCase().includes(search.toLowerCase()),
      )
    : items;

  const sorted = sortFindings(filtered, sortField, sortDir);

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  function resetFilters() {
    setSeverityFilter("");
    setSourceFilter("");
    setProviderFilter("");
    setObsTypeFilter("");
    setSearch("");
    setPage(0);
  }

  const hasFilters = !!(severityFilter || sourceFilter || providerFilter || obsTypeFilter || search);

  function SortIndicator({ field }: { field: SortField }) {
    if (sortField !== field) return null;
    return (
      <span className="ml-1 text-zinc-500">
        {sortDir === "asc" ? "\u2191" : "\u2193"}
      </span>
    );
  }

  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Findings</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          All normalized findings across {total.toLocaleString()} records
        </p>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search title, resource, source..."
            className="pl-8"
          />
        </div>

        <FilterSelect
          value={severityFilter}
          onChange={(v) => {
            setSeverityFilter(v);
            setPage(0);
          }}
          placeholder="All Severities"
          options={SEVERITY_OPTIONS}
        />

        <FilterSelect
          value={sourceFilter}
          onChange={(v) => {
            setSourceFilter(v);
            setPage(0);
          }}
          placeholder="All Sources"
          options={SOURCE_OPTIONS}
        />

        <FilterSelect
          value={providerFilter}
          onChange={(v) => {
            setProviderFilter(v);
            setPage(0);
          }}
          placeholder="All Providers"
          options={PROVIDER_OPTIONS}
        />

        <FilterSelect
          value={obsTypeFilter}
          onChange={(v) => {
            setObsTypeFilter(v);
            setPage(0);
          }}
          placeholder="All Types"
          options={OBS_TYPE_OPTIONS}
        />

        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={resetFilters}>
            Clear filters
          </Button>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <TableSkeleton rows={10} />
      ) : isError || sorted.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No findings found"
          description={
            hasFilters
              ? "Try adjusting your filters."
              : "Run the pipeline to generate findings."
          }
        />
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => handleSort("title")}
                >
                  Title
                  <SortIndicator field="title" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => handleSort("severity")}
                >
                  Severity
                  <SortIndicator field="severity" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => handleSort("source")}
                >
                  Source
                  <SortIndicator field="source" />
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => handleSort("provider")}
                >
                  Provider
                  <SortIndicator field="provider" />
                </TableHead>
                <TableHead>Resource Type</TableHead>
                <TableHead
                  className="cursor-pointer select-none"
                  onClick={() => handleSort("observed_at")}
                >
                  Observed
                  <SortIndicator field="observed_at" />
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.map((finding, idx) => (
                <TableRow
                  key={finding.id}
                  className={cn(
                    "border-zinc-800/50 hover:bg-zinc-800/50 cursor-pointer transition-colors",
                    idx % 2 === 1 && "bg-zinc-900/50",
                  )}
                  onClick={() => navigate(`/findings/${finding.id}`)}
                >
                  <TableCell className="text-zinc-200 max-w-[300px] truncate">
                    {finding.title}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={finding.severity} />
                  </TableCell>
                  <TableCell className="text-zinc-400 font-mono text-xs">
                    {finding.source}
                  </TableCell>
                  <TableCell className="text-zinc-400 font-mono text-xs">
                    {finding.provider}
                  </TableCell>
                  <TableCell className="text-zinc-400 text-xs">
                    {finding.resource_type ?? "-"}
                  </TableCell>
                  <TableCell className="text-zinc-500">
                    {relativeTime(finding.observed_at)}
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
