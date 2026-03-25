import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Clock,
  FileJson,
  Globe,
  Server,
  Shield,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CodeBlock } from "@/components/shared/CodeBlock";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useFindingDetail } from "@/hooks/useApi";

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

function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function FindingDetail() {
  const { findingId } = useParams<{ findingId: string }>();
  const decodedId = findingId ? decodeURIComponent(findingId) : "";
  const [detailOpen, setDetailOpen] = useState(false);

  const {
    data: finding,
    isLoading,
    isError,
  } = useFindingDetail(decodedId);

  const detailJson = useMemo(() => {
    if (!finding?.detail) return null;
    try {
      return JSON.stringify(finding.detail, null, 2);
    } catch {
      return null;
    }
  }, [finding?.detail]);

  if (isLoading) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (isError || !finding) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <EmptyState
          icon={AlertTriangle}
          title="Finding not found"
          description={`No finding found with ID: ${decodedId}`}
        />
      </div>
    );
  }

  const infoRows: [string, React.ReactNode][] = [
    [
      "Finding ID",
      <span key="id" className="font-mono text-zinc-300 text-xs break-all">
        {finding.id}
      </span>,
    ],
    ["Severity", <SeverityBadge key="sev" severity={finding.severity} />],
    [
      "Source",
      <span key="src" className="text-zinc-300">
        {finding.source}
      </span>,
    ],
    [
      "Provider",
      <span key="prov" className="text-zinc-300">
        {finding.provider}
      </span>,
    ],
    [
      "Observation Type",
      <span key="obs" className="text-zinc-300">
        {finding.observation_type}
      </span>,
    ],
    [
      "Observed At",
      <span key="obs-at" className="text-zinc-300">
        {formatDateTime(finding.observed_at)}{" "}
        <span className="text-zinc-500">({relativeTime(finding.observed_at)})</span>
      </span>,
    ],
  ];

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      {/* Back link */}
      <Link
        to="/findings"
        className="inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Findings
      </Link>

      {/* Header card */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2 min-w-0">
            <h1 className="text-lg font-semibold text-zinc-100 break-words">
              {finding.title}
            </h1>
            <div className="flex items-center gap-3 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs text-zinc-400 font-mono">
                {finding.source}
              </span>
              <span className="text-xs text-zinc-500">
                {finding.provider}
              </span>
              <span className="text-xs text-zinc-600">
                {finding.observation_type}
              </span>
            </div>
          </div>
          <div className="text-xs text-zinc-500 shrink-0 text-right">
            {relativeTime(finding.observed_at)}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Main content */}
        <div className="col-span-2 space-y-4">
          {/* Key-value details */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
              Finding Details
            </h3>
            <table className="w-full text-sm">
              <tbody>
                {infoRows.map(([label, value]) => (
                  <tr key={label} className="border-b border-zinc-800/50 last:border-0">
                    <td className="py-2.5 pr-4 text-zinc-500 font-medium w-40 align-top">
                      {label}
                    </td>
                    <td className="py-2.5">{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Detail JSON (collapsible) */}
          {detailJson && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900">
              <button
                onClick={() => setDetailOpen(!detailOpen)}
                className="w-full flex items-center justify-between px-4 py-3 text-sm text-zinc-300 hover:bg-zinc-800/50 transition-colors rounded-xl"
              >
                <span className="flex items-center gap-2">
                  <FileJson className="h-4 w-4 text-zinc-500" />
                  Raw Detail
                  <span className="text-[10px] text-zinc-600 font-mono">
                    ({detailJson.split("\n").length} lines)
                  </span>
                </span>
                {detailOpen ? (
                  <ChevronDown className="h-4 w-4 text-zinc-500" />
                ) : (
                  <ChevronRight className="h-4 w-4 text-zinc-500" />
                )}
              </button>
              {detailOpen && (
                <div className="px-4 pb-4">
                  <CodeBlock code={detailJson} language="json" />
                </div>
              )}
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Resource info */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Resource
            </h3>
            <div className="space-y-2.5 text-sm">
              <div className="flex items-center gap-2 text-zinc-400">
                <Server className="h-3.5 w-3.5 text-zinc-500" />
                <span>Resource ID:</span>
              </div>
              {finding.resource_id ? (
                <p className="font-mono text-xs text-zinc-300 break-all pl-5">
                  {finding.resource_id}
                </p>
              ) : (
                <p className="text-zinc-600 text-xs pl-5">N/A</p>
              )}

              <div className="flex items-center gap-2 text-zinc-400">
                <Globe className="h-3.5 w-3.5 text-zinc-500" />
                <span>Resource Type:</span>
              </div>
              <p className="text-xs text-zinc-300 pl-5">
                {finding.resource_type ?? "N/A"}
              </p>
            </div>

            {finding.resource_id && (
              <div className="pt-2 border-t border-zinc-800/50">
                <Link
                  to={`/pipeline/${encodeURIComponent(finding.provider)}`}
                  className="inline-flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 transition-colors"
                >
                  <Shield className="h-3 w-3" />
                  View in Infrastructure
                </Link>
              </div>
            )}
          </div>

          {/* Timestamps */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Timestamps
            </h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2 text-zinc-400">
                <Clock className="h-3.5 w-3.5 text-zinc-500" />
                <span>Observed:</span>
                <span className="text-zinc-200">
                  {formatDateTime(finding.observed_at)}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
