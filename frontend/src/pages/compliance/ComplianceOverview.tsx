import { useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { useCoverage, useFrameworks, useExportOscal } from "@/hooks/useApi";
import { Button } from "@/components/ui/button";
import { CardSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import type { CoverageData, Framework } from "@/api/types";

// ---------------------------------------------------------------------------
// Circular progress ring
// ---------------------------------------------------------------------------

function ComplianceRing({
  percent,
  size = 72,
  strokeWidth = 6,
}: {
  percent: number;
  size?: number;
  strokeWidth?: number;
}) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, percent));
  const offset = circumference - (clamped / 100) * circumference;

  let strokeColor = "stroke-red-500";
  if (clamped > 50) strokeColor = "stroke-green-500";
  else if (clamped >= 25) strokeColor = "stroke-amber-500";

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          className="text-zinc-800"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={strokeColor}
        />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center text-sm font-bold text-zinc-200">
        {Math.round(clamped)}%
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Proportion bar
// ---------------------------------------------------------------------------

function ProportionBar({ coverage }: { coverage: CoverageData }) {
  const total = coverage.total;
  if (total === 0) return null;

  const segments = [
    { count: coverage.compliant, color: "bg-green-500" },
    { count: coverage.partial, color: "bg-amber-500" },
    { count: coverage.non_compliant, color: "bg-red-500" },
    { count: coverage.not_assessed, color: "bg-zinc-700" },
  ];

  return (
    <div className="flex h-1.5 rounded-full overflow-hidden bg-zinc-800">
      {segments.map(
        (seg, i) =>
          seg.count > 0 && (
            <div
              key={i}
              className={seg.color}
              style={{ width: `${(seg.count / total) * 100}%` }}
            />
          ),
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Framework card
// ---------------------------------------------------------------------------

function FrameworkCard({
  framework,
  coverage,
}: {
  framework: Framework;
  coverage: CoverageData | undefined;
}) {
  const rate = coverage?.rate ?? 0;
  const ratePercent = rate * 100;
  const total = coverage?.total ?? framework.control_count ?? 0;
  const compliant = coverage?.compliant ?? 0;
  const nonCompliant = coverage?.non_compliant ?? 0;
  const partial = coverage?.partial ?? 0;
  const notAssessed = coverage?.not_assessed ?? 0;

  // Build URL-safe framework id: lowercase, spaces to underscores
  const frameworkSlug = framework.name.toLowerCase().replace(/\s+/g, "_");

  return (
    <Link
      to={`/compliance/${encodeURIComponent(frameworkSlug)}`}
      className="group rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <h3 className="text-base font-semibold text-zinc-100 truncate">
            {framework.name}
          </h3>
          <p className="text-xs text-zinc-500 mt-1">
            {total} control{total !== 1 ? "s" : ""}
          </p>
        </div>
        <ComplianceRing percent={ratePercent} />
      </div>

      {coverage && (
        <div className="mt-3">
          <ProportionBar coverage={coverage} />
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-green-500" />
          <span className="text-zinc-400">{compliant} compliant</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-red-500" />
          <span className="text-zinc-400">{nonCompliant} non-compliant</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-amber-500" />
          <span className="text-zinc-400">{partial} partial</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-zinc-600" />
          <span className="text-zinc-400">{notAssessed} not assessed</span>
        </span>
      </div>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ComplianceOverview() {
  const {
    data: frameworks,
    isLoading: fwLoading,
    isError: fwError,
  } = useFrameworks();
  const { data: coverageList, isLoading: covLoading } = useCoverage();
  const exportMutation = useExportOscal();
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  const isLoading = fwLoading || covLoading;

  // Index coverage by framework name for O(1) lookup
  const coverageMap = new Map<string, CoverageData>();
  if (coverageList) {
    for (const c of coverageList) {
      coverageMap.set(c.framework, c);
    }
  }

  // Sort frameworks by compliance rate (worst first) so users see highest-risk first
  const sortedFrameworks = frameworks
    ? [...frameworks].sort((a, b) => {
        const rateA = coverageMap.get(a.name)?.rate ?? 0;
        const rateB = coverageMap.get(b.name)?.rate ?? 0;
        return rateA - rateB;
      })
    : [];

  function handleExportOscal() {
    exportMutation.mutate(
      { format: "json", system_name: "Warlock GRC" },
      {
        onSuccess: (data) => {
          const blob = new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "warlock-oscal-export.json";
          a.click();
          URL.revokeObjectURL(url);
          setExportMsg("OSCAL export downloaded");
          setTimeout(() => setExportMsg(null), 3000);
        },
        onError: () => {
          setExportMsg("Export failed");
          setTimeout(() => setExportMsg(null), 3000);
        },
      },
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100">
            Compliance Frameworks
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Monitor compliance posture across all active frameworks
          </p>
        </div>
        <div className="flex items-center gap-3">
          {exportMsg && (
            <span className="text-xs text-zinc-400">{exportMsg}</span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleExportOscal}
            disabled={exportMutation.isPending}
          >
            {exportMutation.isPending ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
            ) : (
              <Download className="h-3.5 w-3.5 mr-1.5" />
            )}
            Export OSCAL
          </Button>
        </div>
      </div>

      {/* Aggregate stats bar */}
      {!isLoading && !fwError && coverageList && coverageList.length > 0 && (() => {
        const totals = coverageList.reduce(
          (acc, c) => ({
            controls: acc.controls + c.total,
            compliant: acc.compliant + c.compliant,
            nonCompliant: acc.nonCompliant + c.non_compliant,
            partial: acc.partial + c.partial,
            notAssessed: acc.notAssessed + c.not_assessed,
          }),
          { controls: 0, compliant: 0, nonCompliant: 0, partial: 0, notAssessed: 0 },
        );
        const overallPct = totals.controls > 0
          ? Math.round((totals.compliant / totals.controls) * 100)
          : 0;
        return (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <ShieldCheck className="h-3.5 w-3.5" />
                Overall Compliance
              </div>
              <p className="mt-1 text-lg font-semibold text-zinc-100">{overallPct}%</p>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                Compliant
              </div>
              <p className="mt-1 text-lg font-semibold text-green-400">{totals.compliant}</p>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <AlertTriangle className="h-3.5 w-3.5 text-red-500" />
                Non-Compliant
              </div>
              <p className="mt-1 text-lg font-semibold text-red-400">{totals.nonCompliant}</p>
            </div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <Clock className="h-3.5 w-3.5 text-zinc-500" />
                Not Assessed
              </div>
              <p className="mt-1 text-lg font-semibold text-zinc-400">{totals.notAssessed}</p>
            </div>
          </div>
        );
      })()}

      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Array.from({ length: 9 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      )}

      {!isLoading && fwError && (
        <EmptyState
          icon={ShieldCheck}
          title="Failed to load frameworks"
          description="Could not retrieve compliance framework data from the API."
        />
      )}

      {!isLoading && !fwError && sortedFrameworks.length === 0 && (
        <EmptyState
          icon={ShieldCheck}
          title="No frameworks configured"
          description="Run the pipeline to generate compliance data."
        />
      )}

      {!isLoading && !fwError && sortedFrameworks.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {sortedFrameworks.map((fw) => (
            <FrameworkCard
              key={fw.name}
              framework={fw}
              coverage={coverageMap.get(fw.name)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
