import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ChevronDown, ChevronRight, ArrowLeft, ShieldCheck } from "lucide-react";
import { useCoverage, useFrameworkControls, useResults } from "@/hooks/useApi";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { CardSkeleton, LoadingState } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import type { Control, ControlResult } from "@/api/types";

// ---------------------------------------------------------------------------
// Assessment method badge
// ---------------------------------------------------------------------------

const METHOD_STYLES: Record<string, string> = {
  assertion: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  ai: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  opa: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  inherited: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
};

const METHOD_LABELS: Record<string, string> = {
  assertion: "Assertion",
  ai: "AI",
  opa: "OPA",
  inherited: "Inherited",
};

function AssessmentMethodBadge({ method }: { method: string }) {
  const normalized = method.toLowerCase();
  const style = METHOD_STYLES[normalized] ?? METHOD_STYLES.assertion;
  const label = METHOD_LABELS[normalized] ?? method;

  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wide ${style}`}
    >
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Family section
// ---------------------------------------------------------------------------

interface ControlFamily {
  family: string;
  controls: Control[];
  results: Map<string, ControlResult>;
}

function FamilySection({
  family,
  frameworkId,
}: {
  family: ControlFamily;
  frameworkId: string;
}) {
  const [expanded, setExpanded] = useState(false);

  const compliantCount = family.controls.filter((c) => {
    const r = family.results.get(c.control_id);
    return r?.status === "compliant";
  }).length;

  const passRate =
    family.controls.length > 0
      ? Math.round((compliantCount / family.controls.length) * 100)
      : 0;

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0" />
        )}
        <span className="font-medium text-sm text-zinc-200 flex-1">
          {family.family}
        </span>
        <span className="text-xs text-zinc-500">
          {family.controls.length} control{family.controls.length !== 1 ? "s" : ""}
        </span>
        <span
          className={`text-xs font-medium ${
            passRate > 50
              ? "text-green-400"
              : passRate >= 25
                ? "text-amber-400"
                : "text-red-400"
          }`}
        >
          {passRate}% pass
        </span>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 divide-y divide-zinc-800/50">
          {family.controls.map((ctrl) => {
            const result = family.results.get(ctrl.control_id);
            const status = result?.status ?? "not_assessed";
            const assessor = result?.assessor ?? "assertion";

            return (
              <Link
                key={ctrl.control_id}
                to={`/compliance/${encodeURIComponent(frameworkId)}/${encodeURIComponent(ctrl.control_id)}`}
                className="flex items-center gap-3 px-4 py-2.5 hover:bg-zinc-800/30 transition-colors"
              >
                <span className="font-mono text-xs text-zinc-300 w-20 shrink-0">
                  {ctrl.control_id}
                </span>
                <span className="text-sm text-zinc-400 flex-1 truncate min-w-0">
                  {ctrl.control_family || ctrl.control_id}
                </span>
                <AssessmentMethodBadge method={assessor} />
                <StatusBadge status={status} />
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function FrameworkDetail() {
  const { frameworkId } = useParams<{ frameworkId: string }>();
  const decodedId = frameworkId ? decodeURIComponent(frameworkId) : "";

  const {
    data: controls,
    isLoading: ctrlLoading,
    isError: ctrlError,
  } = useFrameworkControls(decodedId);

  const { data: coverageList } = useCoverage(decodedId);
  const coverage = coverageList?.[0];

  const { data: resultsData } = useResults({
    framework: decodedId,
    limit: 5000,
  });

  // Build a map of control_id -> latest result for status lookups
  const resultMap = new Map<string, ControlResult>();
  if (resultsData?.items) {
    for (const r of resultsData.items) {
      const existing = resultMap.get(r.control_id);
      if (!existing || r.assessed_at > existing.assessed_at) {
        resultMap.set(r.control_id, r);
      }
    }
  }

  // Group controls by family
  const familyMap = new Map<string, Control[]>();
  if (controls) {
    for (const ctrl of controls) {
      // Derive family from control_family field, or from control_id prefix (e.g., "AC" from "AC-2")
      const family =
        ctrl.control_family || ctrl.control_id.replace(/-[\d.]+$/, "") || "Other";
      const existing = familyMap.get(family);
      if (existing) {
        existing.push(ctrl);
      } else {
        familyMap.set(family, [ctrl]);
      }
    }
  }

  const families: ControlFamily[] = Array.from(familyMap.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([family, ctrls]) => ({
      family,
      controls: ctrls.sort((a, b) => a.control_id.localeCompare(b.control_id)),
      results: resultMap,
    }));

  const rate = coverage?.rate ?? 0;
  const total = coverage?.total ?? controls?.length ?? 0;
  const compliant = coverage?.compliant ?? 0;
  const nonCompliant = coverage?.non_compliant ?? 0;
  const partial = coverage?.partial ?? 0;
  const notAssessed = coverage?.not_assessed ?? 0;

  return (
    <div className="p-6 space-y-6">
      {/* Breadcrumb + back */}
      <div className="flex items-center gap-2 text-sm">
        <Link
          to="/compliance"
          className="flex items-center gap-1 text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Frameworks
        </Link>
        <span className="text-zinc-700">/</span>
        <span className="text-zinc-300">{decodedId}</span>
      </div>

      {/* Header stats card */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">{decodedId}</h1>
            <p className="text-sm text-zinc-500 mt-1">
              {total} controls across {families.length} famil{families.length !== 1 ? "ies" : "y"}
            </p>
          </div>
          <div className="text-right">
            <div
              className={`text-3xl font-bold ${
                rate * 100 > 50
                  ? "text-green-400"
                  : rate * 100 >= 25
                    ? "text-amber-400"
                    : "text-red-400"
              }`}
            >
              {Math.round(rate * 100)}%
            </div>
            <p className="text-xs text-zinc-500 mt-0.5">compliance rate</p>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-6 text-xs">
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

        {/* Mini bar */}
        {total > 0 && (
          <div className="mt-3 flex h-1.5 rounded-full overflow-hidden bg-zinc-800">
            {compliant > 0 && (
              <div
                className="bg-green-500"
                style={{ width: `${(compliant / total) * 100}%` }}
              />
            )}
            {partial > 0 && (
              <div
                className="bg-amber-500"
                style={{ width: `${(partial / total) * 100}%` }}
              />
            )}
            {nonCompliant > 0 && (
              <div
                className="bg-red-500"
                style={{ width: `${(nonCompliant / total) * 100}%` }}
              />
            )}
            {notAssessed > 0 && (
              <div
                className="bg-zinc-700"
                style={{ width: `${(notAssessed / total) * 100}%` }}
              />
            )}
          </div>
        )}
      </div>

      {/* Loading */}
      {ctrlLoading && (
        <div className="space-y-3">
          <CardSkeleton />
          <CardSkeleton />
          <LoadingState rows={6} />
        </div>
      )}

      {/* Error */}
      {!ctrlLoading && ctrlError && (
        <EmptyState
          icon={ShieldCheck}
          title="Failed to load controls"
          description={`Could not retrieve controls for ${decodedId}.`}
        />
      )}

      {/* Empty */}
      {!ctrlLoading && !ctrlError && families.length === 0 && (
        <EmptyState
          icon={ShieldCheck}
          title="No controls found"
          description={`Framework ${decodedId} has no controls yet.`}
        />
      )}

      {/* Families list */}
      {!ctrlLoading && !ctrlError && families.length > 0 && (
        <div className="space-y-3">
          {families.map((fam) => (
            <FamilySection
              key={fam.family}
              family={fam}
              frameworkId={decodedId}
            />
          ))}
        </div>
      )}
    </div>
  );
}
