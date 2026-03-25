import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useCoverage, useFrameworks } from "@/hooks/useApi";
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

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">
          Compliance Frameworks
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Monitor compliance posture across all active frameworks
        </p>
      </div>

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
