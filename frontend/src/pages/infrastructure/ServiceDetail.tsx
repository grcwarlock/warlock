import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ChevronRight,
  AlertTriangle,
  ArrowUpDown,
  Box,
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
import { useTopology } from "@/hooks/useApi";
import type { TopologyResource } from "@/api/types";

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

function formatSourceTypeName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatResourceType(rt: string): string {
  return rt.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Sort logic
// ---------------------------------------------------------------------------

type SortField = "resource_id" | "finding_count" | "worst_severity" | "controls";
type SortDir = "asc" | "desc";

function sortResources(
  items: TopologyResource[],
  field: SortField,
  dir: SortDir
): TopologyResource[] {
  const sorted = [...items].sort((a, b) => {
    switch (field) {
      case "resource_id":
        return a.resource_id.localeCompare(b.resource_id);
      case "finding_count":
        return a.finding_count - b.finding_count;
      case "worst_severity": {
        const av = SEVERITY_ORDER[a.worst_severity] ?? 4;
        const bv = SEVERITY_ORDER[b.worst_severity] ?? 4;
        return av - bv;
      }
      case "controls":
        return a.controls_affected.length - b.controls_affected.length;
      default:
        return 0;
    }
  });
  return dir === "desc" ? sorted.reverse() : sorted;
}

// ---------------------------------------------------------------------------
// Sortable header
// ---------------------------------------------------------------------------

function SortableHeader({
  label,
  field,
  currentField,
  currentDir,
  onSort,
}: {
  label: string;
  field: SortField;
  currentField: SortField;
  currentDir: SortDir;
  onSort: (field: SortField) => void;
}) {
  const isActive = field === currentField;
  return (
    <button
      onClick={() => onSort(field)}
      className="flex items-center gap-1 hover:text-zinc-200 transition-colors"
    >
      {label}
      <ArrowUpDown
        className={cn(
          "h-3 w-3",
          isActive ? "text-zinc-300" : "text-zinc-600"
        )}
      />
      {isActive && (
        <span className="text-[9px] text-zinc-500">
          {currentDir === "asc" ? "ASC" : "DESC"}
        </span>
      )}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Control chip
// ---------------------------------------------------------------------------

function ControlChip({ controlId }: { controlId: string }) {
  return (
    <span className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400">
      {controlId}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ServiceDetail() {
  const {
    sourceType,
    provider: providerName,
    resourceType,
  } = useParams<{
    sourceType: string;
    provider: string;
    resourceType: string;
  }>();

  const { data, isLoading, isError } = useTopology(sourceType, providerName);

  const [sortField, setSortField] = useState<SortField>("finding_count");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const service = useMemo(() => {
    if (!data?.source_types) return null;
    for (const st of data.source_types) {
      if (st.name === sourceType) {
        for (const p of st.providers) {
          if (p.name === providerName) {
            return p.services.find((s) => s.resource_type === resourceType) ?? null;
          }
        }
      }
    }
    return null;
  }, [data, sourceType, providerName, resourceType]);

  const sortedResources = useMemo(() => {
    if (!service) return [];
    return sortResources(service.resources, sortField, sortDir);
  }, [service, sortField, sortDir]);

  const handleSort = (field: SortField) => {
    if (field === sortField) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir(field === "resource_id" ? "asc" : "desc");
    }
  };

  // Count unique controls across all resources
  const totalControls = useMemo(() => {
    if (!service) return 0;
    const set = new Set(service.resources.flatMap((r) => r.controls_affected));
    return set.size;
  }, [service]);

  const breadcrumbBase = `/infrastructure/${encodeURIComponent(sourceType ?? "")}/${encodeURIComponent(providerName ?? "")}`;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link
            to={breadcrumbBase}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <div className="h-5 w-48 bg-zinc-800 rounded animate-pulse" />
            <div className="h-3 w-32 bg-zinc-800 rounded animate-pulse mt-1" />
          </div>
        </div>
        <TableSkeleton rows={10} />
      </div>
    );
  }

  if (isError || !service) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link
            to={breadcrumbBase}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <h1 className="text-lg font-semibold text-zinc-100">
            {formatResourceType(resourceType ?? "")}
          </h1>
        </div>
        <EmptyState
          icon={AlertTriangle}
          title="Service not found"
          description="No data available for this resource type."
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
            to={breadcrumbBase}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div>
            <h1 className="text-lg font-semibold text-zinc-100">
              {formatResourceType(service.resource_type)}
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
                to={breadcrumbBase}
                className="hover:text-zinc-300 transition-colors"
              >
                {providerName}
              </Link>
              <ChevronRight className="h-3 w-3" />
              <span className="text-zinc-300">
                {formatResourceType(service.resource_type)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="text-[10px] uppercase tracking-wide text-zinc-500 mb-1">
            Event Type
          </div>
          <div className="text-sm font-medium text-zinc-200">
            {service.event_type}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="text-[10px] uppercase tracking-wide text-zinc-500 mb-1">
            Findings
          </div>
          <div className="text-xl font-bold text-zinc-100">
            {formatCount(service.finding_count)}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="text-[10px] uppercase tracking-wide text-zinc-500 mb-1">
            Resources
          </div>
          <div className="text-xl font-bold text-zinc-100">
            {service.resources.length}
          </div>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
          <div className="text-[10px] uppercase tracking-wide text-zinc-500 mb-1">
            Controls Affected
          </div>
          <div className="text-xl font-bold text-zinc-100">{totalControls}</div>
        </div>
      </div>

      {/* Resource table */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        <div className="px-4 py-3 border-b border-zinc-800">
          <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
            Resources ({service.resources.length})
          </div>
        </div>

        {sortedResources.length === 0 ? (
          <EmptyState
            icon={Box}
            title="No resources"
            description="No resources found for this service."
            className="py-12"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead className="text-zinc-500">
                  <SortableHeader
                    label="Resource ID"
                    field="resource_id"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                </TableHead>
                <TableHead className="text-zinc-500">
                  <SortableHeader
                    label="Findings"
                    field="finding_count"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                </TableHead>
                <TableHead className="text-zinc-500">
                  <SortableHeader
                    label="Worst Severity"
                    field="worst_severity"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                </TableHead>
                <TableHead className="text-zinc-500">
                  <SortableHeader
                    label="Controls Affected"
                    field="controls"
                    currentField={sortField}
                    currentDir={sortDir}
                    onSort={handleSort}
                  />
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedResources.map((resource) => (
                <TableRow
                  key={resource.resource_id}
                  className="border-zinc-800 hover:bg-zinc-800/50"
                >
                  <TableCell>
                    <Link
                      to={`${breadcrumbBase}/${encodeURIComponent(resourceType ?? "")}/${encodeURIComponent(resource.resource_id)}`}
                      className="text-sm font-mono text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      {resource.resource_id}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <span className="text-sm font-medium text-zinc-200">
                      {resource.finding_count}
                    </span>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={resource.worst_severity} />
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1 max-w-md">
                      {resource.controls_affected.slice(0, 5).map((ctrl) => (
                        <ControlChip key={ctrl} controlId={ctrl} />
                      ))}
                      {resource.controls_affected.length > 5 && (
                        <span className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] text-zinc-500">
                          +{resource.controls_affected.length - 5} more
                        </span>
                      )}
                    </div>
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
