import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Calendar,
  CheckCircle2,
  Clock,
  ExternalLink,
  User,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useRemediationDetail, useTransitionRemediation } from "@/hooks/useApi";
import { useQueryClient } from "@tanstack/react-query";

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
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function isOverdue(dueDate: string | null | undefined, status: string): boolean {
  if (!dueDate || status === "closed" || status === "verified") return false;
  return new Date(dueDate).getTime() < Date.now();
}

const STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ["in_progress"],
  in_progress: ["pending_verification", "closed"],
  pending_verification: ["verified", "in_progress"],
  verified: ["closed"],
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function POAMDetail() {
  const { poamId } = useParams();
  const queryClient = useQueryClient();
  const { data: remediation, isLoading, isError } = useRemediationDetail(poamId ?? "");
  const transition = useTransitionRemediation();

  if (isLoading) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <TableSkeleton rows={8} />
      </div>
    );
  }

  if (isError || !remediation) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <EmptyState
          icon={Clock}
          title="POA&M not found"
          description={`No remediation record found with ID: ${poamId}`}
        />
      </div>
    );
  }

  const r = remediation;
  const overdue = isOverdue(r.due_date, r.status);
  const transitions = STATUS_TRANSITIONS[r.status] ?? [];
  const steps = Array.isArray(r.remediation_steps) ? r.remediation_steps : [];
  const evidence = Array.isArray(r.evidence) ? r.evidence : [];

  // Build timeline entries from available timestamps
  const timeline: { label: string; date: string | null; icon: React.ReactNode }[] = [
    { label: "Created", date: r.created_at, icon: <Clock className="h-3 w-3" /> },
    { label: "Assigned", date: r.assigned_at, icon: <User className="h-3 w-3" /> },
    { label: "Verified", date: r.verified_at, icon: <CheckCircle2 className="h-3 w-3 text-green-400" /> },
    { label: "Closed", date: r.closed_at, icon: <CheckCircle2 className="h-3 w-3 text-green-400" /> },
  ].filter((t) => t.date);

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      {/* Back link */}
      <Link
        to="/remediation"
        className="inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Remediation
      </Link>

      {/* Header */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2 min-w-0">
            <h1 className="text-lg font-semibold text-zinc-100 break-words">
              {r.title}
            </h1>
            {r.description && (
              <p className="text-sm text-zinc-400 max-w-2xl">{r.description}</p>
            )}
            <div className="flex items-center gap-4 flex-wrap text-sm">
              <StatusBadge status={r.status} />
              {overdue && (
                <span className="inline-flex items-center rounded-md border border-red-500/20 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium uppercase text-red-400">
                  Overdue
                </span>
              )}
              {r.framework && (
                <span className="text-zinc-400">
                  Framework:{" "}
                  <span className="text-zinc-200 font-mono">{r.framework}</span>
                </span>
              )}
              {r.control_id && (
                <span className="text-zinc-400">
                  Control:{" "}
                  <span className="text-zinc-200 font-mono">{r.control_id}</span>
                </span>
              )}
            </div>
          </div>

          {/* Status transition buttons */}
          {transitions.length > 0 && (
            <div className="flex items-center gap-2 shrink-0">
              {transitions.map((t) => (
                <Button
                  key={t}
                  variant="outline"
                  size="sm"
                  disabled={transition.isPending}
                  onClick={() => {
                    const payload: Record<string, unknown> = {};
                    if (t === "closed" || t === "verified") {
                      payload.verification_notes = "Verified via dashboard";
                      payload.approved = true;
                    }
                    transition.mutate(
                      { id: r.id, targetStatus: t, payload },
                      {
                        onSuccess: () => {
                          queryClient.invalidateQueries({
                            queryKey: ["remediations"],
                          });
                        },
                      },
                    );
                  }}
                >
                  {transition.isPending ? "..." : t
                    .split("_")
                    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                    .join(" ")}
                </Button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Details panel */}
        <div className="col-span-2 space-y-4">
          {/* Remediation plan */}
          {r.remediation_plan && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Remediation Plan
              </h3>
              <p className="text-sm text-zinc-300 whitespace-pre-wrap">
                {r.remediation_plan}
              </p>
            </div>
          )}

          {/* Milestones / Steps */}
          {steps.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Remediation Steps
              </h3>
              <div className="relative ml-3 border-l border-zinc-700 space-y-4 pl-6">
                {steps.map((step, idx) => {
                  const label =
                    typeof step === "object" && step !== null
                      ? (step as Record<string, unknown>).description ??
                        (step as Record<string, unknown>).title ??
                        JSON.stringify(step)
                      : String(step);
                  const done =
                    typeof step === "object" && step !== null
                      ? !!(step as Record<string, unknown>).completed
                      : false;
                  return (
                    <div key={idx} className="relative">
                      <div className="absolute -left-[9px] top-0 flex items-center justify-center">
                        <div className="flex items-center justify-center h-5 w-5 rounded-full bg-zinc-900">
                          <span
                            className={cn(
                              "text-[10px] font-bold",
                              done ? "text-green-400" : "text-zinc-500",
                            )}
                          >
                            {idx + 1}
                          </span>
                        </div>
                      </div>
                      <p
                        className={cn(
                          "text-sm ml-3",
                          done ? "text-zinc-500 line-through" : "text-zinc-200",
                        )}
                      >
                        {String(label)}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Evidence */}
          {evidence.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Evidence
              </h3>
              <div className="space-y-2">
                {evidence.map((ev, idx) => {
                  const label =
                    typeof ev === "object" && ev !== null
                      ? (ev as Record<string, unknown>).description ??
                        (ev as Record<string, unknown>).title ??
                        (ev as Record<string, unknown>).name ??
                        JSON.stringify(ev)
                      : String(ev);
                  return (
                    <div
                      key={idx}
                      className="flex items-start gap-2 text-sm text-zinc-300 py-1.5 border-b border-zinc-800/50 last:border-0"
                    >
                      <span className="text-zinc-500 font-mono text-xs shrink-0">
                        #{idx + 1}
                      </span>
                      <span className="break-words">{String(label)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Verification */}
          {r.verified_by && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Verification
              </h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2 text-zinc-300">
                  <CheckCircle2 className="h-4 w-4 text-green-400" />
                  Verified by {r.verified_by} on {formatDateTime(r.verified_at)}
                </div>
                {r.verification_notes && (
                  <p className="text-zinc-400 ml-6">{r.verification_notes}</p>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Metadata */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
              Details
            </h3>
            <div className="space-y-2.5 text-sm">
              <div className="flex items-center gap-2 text-zinc-400">
                <User className="h-3.5 w-3.5 text-zinc-500" />
                <span>Assigned to:</span>
                <span className="text-zinc-200">
                  {r.assigned_to ?? "Unassigned"}
                </span>
              </div>
              {r.assigned_by && (
                <div className="flex items-center gap-2 text-zinc-400">
                  <User className="h-3.5 w-3.5 text-zinc-500" />
                  <span>Assigned by:</span>
                  <span className="text-zinc-200">{r.assigned_by}</span>
                </div>
              )}
              <div className="flex items-center gap-2 text-zinc-400">
                <Calendar className="h-3.5 w-3.5 text-zinc-500" />
                <span>Due date:</span>
                <span
                  className={cn(overdue ? "text-red-400" : "text-zinc-200")}
                >
                  {formatDate(r.due_date)}
                </span>
              </div>
              {r.framework && (
                <div className="text-zinc-400">
                  Framework:{" "}
                  <span className="text-zinc-300 font-mono">{r.framework}</span>
                </div>
              )}
              {r.control_id && (
                <div className="text-zinc-400">
                  Control:{" "}
                  <span className="text-zinc-300 font-mono">{r.control_id}</span>
                </div>
              )}
            </div>
          </div>

          {/* Timeline */}
          {timeline.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-3">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
                Timeline
              </h3>
              <div className="relative ml-2 border-l border-zinc-700 space-y-3 pl-5">
                {timeline.map((t, idx) => (
                  <div key={idx} className="relative">
                    <div className="absolute -left-[24px] top-0.5 h-3 w-3 rounded-full border-2 bg-zinc-800 border-zinc-600" />
                    <div className="flex items-center gap-2 text-xs">
                      {t.icon}
                      <span className="text-zinc-300">{t.label}</span>
                      <span className="text-zinc-500">
                        {formatDateTime(t.date)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Linked finding */}
          {r.finding_id && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Linked Finding
              </h3>
              <Link
                to={`/findings/${r.finding_id}`}
                className="flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                {r.finding_id}
              </Link>
            </div>
          )}

          {/* Created / Updated by */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-2 text-sm text-zinc-400">
            {r.created_by && (
              <div>
                Created by:{" "}
                <span className="text-zinc-300">{r.created_by}</span>
              </div>
            )}
            {r.updated_at && (
              <div>
                Last updated:{" "}
                <span className="text-zinc-300">
                  {formatDateTime(r.updated_at)}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
