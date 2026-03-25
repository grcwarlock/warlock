import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Loader2,
  Wrench,
  BookOpen,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import {
  useControlDetail,
  useGenerateRemediation,
} from "@/hooks/useApi";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { CodeBlock } from "@/components/shared/CodeBlock";
import { CardSkeleton, LoadingState } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";
import type {
  ControlDetailResource,
  ControlDetailRemediation,
  RemediationGenerateResponse,
} from "@/api/types";

// ---------------------------------------------------------------------------
// Section wrapper
// ---------------------------------------------------------------------------

function Section({
  title,
  icon: Icon,
  children,
  className,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden",
        className,
      )}
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b border-zinc-800">
        <Icon className="h-4 w-4 text-zinc-500" />
        <h2 className="text-sm font-medium text-zinc-300">{title}</h2>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Status summary bar
// ---------------------------------------------------------------------------

function StatusSummaryBar({
  total,
  compliant,
  nonCompliant,
  partial,
  notAssessed,
}: {
  total: number;
  compliant: number;
  nonCompliant: number;
  partial: number;
  notAssessed: number;
}) {
  if (total === 0) return null;

  const segments = [
    { count: compliant, color: "bg-green-500", label: "Compliant" },
    { count: partial, color: "bg-amber-500", label: "Partial" },
    { count: nonCompliant, color: "bg-red-500", label: "Non-Compliant" },
    { count: notAssessed, color: "bg-zinc-700", label: "Not Assessed" },
  ];

  return (
    <div className="space-y-2">
      <div className="flex h-2.5 rounded-full overflow-hidden bg-zinc-800">
        {segments.map(
          (seg, i) =>
            seg.count > 0 && (
              <div
                key={i}
                className={cn(seg.color, "transition-all")}
                style={{ width: `${(seg.count / total) * 100}%` }}
                title={`${seg.label}: ${seg.count}`}
              />
            ),
        )}
      </div>
      <div className="flex items-center gap-5 text-xs">
        <span className="text-zinc-500">{total} total</span>
        <span className="text-green-400">{compliant} compliant</span>
        <span className="text-red-400">{nonCompliant} non-compliant</span>
        <span className="text-amber-400">{partial} partial</span>
        <span className="text-zinc-500">{notAssessed} not assessed</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Generated remediation panel (shown after clicking Remediate)
// ---------------------------------------------------------------------------

function GeneratedRemediationPanel({
  data,
  onClose,
}: {
  data: RemediationGenerateResponse;
  onClose: () => void;
}) {
  return (
    <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <Wrench className="h-4 w-4 text-blue-400" />
          <h3 className="text-sm font-medium text-blue-300">
            Remediation for {data.resource_id}
          </h3>
        </div>
        <button
          onClick={onClose}
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Dismiss
        </button>
      </div>

      {/* Playbook summary */}
      {data.playbook.summary && (
        <p className="text-sm text-zinc-300">{data.playbook.summary}</p>
      )}

      {/* Playbook steps */}
      {data.playbook.steps.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Steps
          </h4>
          <ol className="list-decimal list-inside space-y-1 text-sm text-zinc-400">
            {data.playbook.steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {/* Console path */}
      {data.playbook.console_path && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Console Path
          </h4>
          <p className="text-sm text-zinc-400 font-mono">
            {data.playbook.console_path}
          </p>
        </div>
      )}

      {/* CLI commands */}
      {data.commands.cli && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            CLI Command
          </h4>
          <CodeBlock code={data.commands.cli} language="bash" />
        </div>
      )}

      {/* Terraform */}
      {data.commands.terraform && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Terraform
          </h4>
          <CodeBlock code={data.commands.terraform} language="terraform" />
        </div>
      )}

      {/* Console URL */}
      {data.commands.console_url && (
        <a
          href={data.commands.console_url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300 transition-colors"
        >
          <ExternalLink className="h-3.5 w-3.5" />
          Open in Cloud Console
        </a>
      )}

      {/* Recommended reading */}
      {data.playbook.recommended_reading.length > 0 && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Recommended Reading
          </h4>
          <ul className="list-disc list-inside text-xs text-zinc-400 space-y-0.5">
            {data.playbook.recommended_reading.map((link, i) => (
              <li key={i}>
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  {link}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Failing resources table
// ---------------------------------------------------------------------------

function FailingResourcesTable({
  resources,
  controlId,
  frameworkId,
}: {
  resources: ControlDetailResource[];
  controlId: string;
  frameworkId: string;
}) {
  const remediationMutation = useGenerateRemediation();
  const [activeResourceId, setActiveResourceId] = useState<string | null>(null);
  const [generatedData, setGeneratedData] =
    useState<RemediationGenerateResponse | null>(null);

  const handleRemediate = (resource: ControlDetailResource) => {
    setActiveResourceId(resource.resource_id);
    setGeneratedData(null);

    remediationMutation.mutate(
      {
        control_id: controlId,
        resource_id: resource.resource_id,
        resource_type: resource.resource_type,
        provider: resource.provider ?? "unknown",
        framework: frameworkId,
      },
      {
        onSuccess: (data) => {
          setGeneratedData(data);
        },
      },
    );
  };

  if (resources.length === 0) {
    return (
      <div className="flex items-center gap-2 text-sm text-zinc-500 py-2">
        <CheckCircle2 className="h-4 w-4 text-green-400" />
        No failing resources found for this control.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                Resource ID
              </th>
              <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                Type
              </th>
              <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                Provider
              </th>
              <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                Region
              </th>
              <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                Severity
              </th>
              <th className="text-right text-xs font-medium text-zinc-500 uppercase tracking-wide py-2">
                Action
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {resources.map((resource) => {
              const isActive = activeResourceId === resource.resource_id;
              const isLoading =
                isActive && remediationMutation.isPending;

              return (
                <tr
                  key={resource.resource_id}
                  className={cn(
                    "hover:bg-zinc-800/30 transition-colors",
                    isActive && generatedData && "bg-zinc-800/20",
                  )}
                >
                  <td className="py-2.5 pr-3">
                    <span className="font-mono text-xs text-zinc-300 break-all">
                      {resource.resource_id}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    <span className="text-xs text-zinc-400">
                      {resource.resource_type}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    <span className="text-xs text-zinc-400">
                      {resource.provider ?? "-"}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    <span className="text-xs text-zinc-500">
                      {resource.region ?? "-"}
                    </span>
                  </td>
                  <td className="py-2.5 pr-3">
                    {resource.severity ? (
                      <SeverityBadge severity={resource.severity} />
                    ) : (
                      <span className="text-xs text-zinc-600">-</span>
                    )}
                  </td>
                  <td className="py-2.5 text-right">
                    <button
                      onClick={() => handleRemediate(resource)}
                      disabled={isLoading}
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                        isActive && generatedData
                          ? "border-blue-500/30 bg-blue-500/10 text-blue-400"
                          : "border-zinc-700 bg-zinc-800 text-zinc-300 hover:bg-zinc-700 hover:text-zinc-100",
                        isLoading && "opacity-60 cursor-not-allowed",
                      )}
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="h-3 w-3 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Wrench className="h-3 w-3" />
                          Remediate
                        </>
                      )}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Mutation error */}
      {remediationMutation.isError && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-sm text-red-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Failed to generate remediation. Try again.
        </div>
      )}

      {/* Generated remediation */}
      {generatedData && (
        <GeneratedRemediationPanel
          data={generatedData}
          onClose={() => {
            setActiveResourceId(null);
            setGeneratedData(null);
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Static remediation panel
// ---------------------------------------------------------------------------

function StaticRemediationPanel({
  remediation,
}: {
  remediation: ControlDetailRemediation | null;
}) {
  const hasContent =
    remediation &&
    (remediation.summary ||
      remediation.steps.length > 0 ||
      remediation.console_path ||
      remediation.recommended_reading.length > 0);

  if (!hasContent) {
    return (
      <p className="text-sm text-zinc-500">
        No static remediation guidance available for this control.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {remediation.summary && (
        <p className="text-sm text-zinc-300">{remediation.summary}</p>
      )}

      {remediation.steps.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Remediation Steps
          </h4>
          <ol className="list-decimal list-inside space-y-1 text-sm text-zinc-400">
            {remediation.steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {remediation.console_path && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Console Path
          </h4>
          <CodeBlock code={remediation.console_path} language="text" />
        </div>
      )}

      {remediation.recommended_reading.length > 0 && (
        <div className="space-y-1">
          <h4 className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Recommended Reading
          </h4>
          <ul className="list-disc list-inside text-xs text-zinc-400 space-y-0.5">
            {remediation.recommended_reading.map((link, i) => (
              <li key={i}>
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:underline"
                >
                  {link}
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Passing resources (collapsible)
// ---------------------------------------------------------------------------

function PassingResourcesSection({
  resources,
}: {
  resources: ControlDetailResource[];
}) {
  const [expanded, setExpanded] = useState(false);

  if (resources.length === 0) {
    return null;
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 text-zinc-500 shrink-0" />
        ) : (
          <ChevronRight className="h-4 w-4 text-zinc-500 shrink-0" />
        )}
        <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
        <span className="text-sm font-medium text-zinc-300">
          Passing Resources
        </span>
        <span className="text-xs text-zinc-500 ml-auto">
          {resources.length} resource{resources.length !== 1 ? "s" : ""}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 p-4">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                    Resource ID
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                    Type
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                    Provider
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2 pr-3">
                    Region
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wide py-2">
                    Source
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {resources.map((resource) => (
                  <tr
                    key={resource.resource_id}
                    className="hover:bg-zinc-800/20 transition-colors"
                  >
                    <td className="py-2 pr-3">
                      <span className="font-mono text-xs text-zinc-400 break-all">
                        {resource.resource_id}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-xs text-zinc-500">
                      {resource.resource_type}
                    </td>
                    <td className="py-2 pr-3 text-xs text-zinc-500">
                      {resource.provider ?? "-"}
                    </td>
                    <td className="py-2 pr-3 text-xs text-zinc-600">
                      {resource.region ?? "-"}
                    </td>
                    <td className="py-2 text-xs text-zinc-600">
                      {resource.source}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ControlDetail() {
  const { frameworkId, controlId } = useParams<{
    frameworkId: string;
    controlId: string;
  }>();

  const decodedFramework = frameworkId ? decodeURIComponent(frameworkId) : "";
  const decodedControl = controlId ? decodeURIComponent(controlId) : "";

  const {
    data: detail,
    isLoading: detailLoading,
    isError: detailError,
  } = useControlDetail(decodedControl, decodedFramework);

  // Determine overall status from counts
  const overallStatus =
    detail && detail.non_compliant_count > 0
      ? "non_compliant"
      : detail && detail.partial_count > 0
        ? "partial"
        : detail && detail.compliant_count > 0
          ? "compliant"
          : "not_assessed";

  return (
    <div className="p-6 space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <Link
          to="/compliance"
          className="text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Frameworks
        </Link>
        <span className="text-zinc-700">/</span>
        <Link
          to={`/compliance/${encodeURIComponent(decodedFramework)}`}
          className="flex items-center gap-1 text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          {decodedFramework}
        </Link>
        <span className="text-zinc-700">/</span>
        <span className="font-mono text-zinc-300">{decodedControl}</span>
      </div>

      {/* Loading */}
      {detailLoading && (
        <div className="space-y-4">
          <CardSkeleton />
          <LoadingState rows={8} />
        </div>
      )}

      {/* Error */}
      {!detailLoading && detailError && (
        <EmptyState
          icon={ShieldCheck}
          title="Failed to load control"
          description={`Could not retrieve details for ${decodedControl}.`}
        />
      )}

      {/* Content */}
      {!detailLoading && !detailError && detail && (
        <>
          {/* Header card */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-2 flex-1 min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <h1 className="text-2xl font-bold font-mono text-zinc-100">
                    {detail.control_id}
                  </h1>
                  <span className="inline-flex items-center rounded-md border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] font-medium text-zinc-400">
                    {decodedFramework}
                  </span>
                </div>
                {detail.description && (
                  <p className="text-sm text-zinc-400 max-w-3xl">
                    {detail.description}
                  </p>
                )}
              </div>
              <div className="shrink-0">
                <StatusBadge
                  status={overallStatus}
                  className="text-xs px-3 py-1"
                />
              </div>
            </div>

            <StatusSummaryBar
              total={detail.total_results}
              compliant={detail.compliant_count}
              nonCompliant={detail.non_compliant_count}
              partial={detail.partial_count}
              notAssessed={detail.not_assessed_count}
            />

            {/* Crosswalk frameworks */}
            {detail.frameworks.length > 1 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-zinc-500">Also mapped to:</span>
                {detail.frameworks
                  .filter((f) => f !== decodedFramework)
                  .map((fw) => (
                    <Link
                      key={fw}
                      to={`/compliance/${encodeURIComponent(fw)}/${encodeURIComponent(detail.control_id)}`}
                      className="inline-flex items-center rounded-md border border-zinc-700/40 bg-zinc-800/60 px-2 py-0.5 text-[10px] font-medium text-zinc-400 hover:text-zinc-200 hover:border-zinc-600 transition-colors"
                    >
                      {fw}
                    </Link>
                  ))}
              </div>
            )}
          </div>

          {/* Failing Resources -- THE CRITICAL FEATURE */}
          <Section title="Failing Resources" icon={ShieldAlert}>
            <FailingResourcesTable
              resources={detail.failing_resources}
              controlId={detail.control_id}
              frameworkId={decodedFramework}
            />
          </Section>

          {/* Static Remediation Guidance */}
          <Section title="Remediation Guidance" icon={BookOpen}>
            <StaticRemediationPanel remediation={detail.remediation} />
          </Section>

          {/* AI Remediation (raw JSON if present) */}
          {detail.ai_remediation &&
            Object.keys(detail.ai_remediation).length > 0 && (
              <Section title="AI Remediation Analysis" icon={ShieldOff}>
                <CodeBlock
                  code={JSON.stringify(detail.ai_remediation, null, 2)}
                  language="json"
                />
              </Section>
            )}

          {/* Passing Resources */}
          <PassingResourcesSection resources={detail.passing_resources} />

          {/* POA&M link */}
          <div className="flex items-center gap-3">
            <Link
              to={`/remediation?control_id=${encodeURIComponent(detail.control_id)}&framework=${encodeURIComponent(decodedFramework)}`}
              className="inline-flex items-center justify-center rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm font-medium text-zinc-300 hover:bg-zinc-800 transition-colors"
            >
              Create POA&M
            </Link>
          </div>
        </>
      )}
    </div>
  );
}
