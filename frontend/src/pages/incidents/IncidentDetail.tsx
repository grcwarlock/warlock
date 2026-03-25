import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Clock,
  ExternalLink,
  Loader2,
  MessageSquare,
  Send,
  User,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { SeverityBadge } from "@/components/shared/SeverityBadge";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useIssueDetail, useTransitionIssue } from "@/hooks/useApi";
import { useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "@/hooks/useApi";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

const STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ["investigating"],
  investigating: ["mitigating", "resolved"],
  mitigating: ["resolved"],
  resolved: ["closed", "open"],
  closed: ["open"],
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function IncidentDetail() {
  const { incidentId } = useParams();
  const queryClient = useQueryClient();
  const {
    data,
    isLoading,
    isError,
  } = useIssueDetail(incidentId ?? "");
  const transitionMutation = useTransitionIssue();

  const [comment, setComment] = useState("");

  if (isLoading) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <TableSkeleton rows={8} />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <EmptyState
          icon={MessageSquare}
          title="Incident not found"
          description={`No incident found with ID: ${incidentId}`}
        />
      </div>
    );
  }

  const issue = data.issue;
  const comments = data.comments ?? [];
  const transitions = STATUS_TRANSITIONS[issue.status] ?? [];

  function handleTransition(status: string) {
    if (!incidentId) return;
    transitionMutation.mutate(
      { id: incidentId, status, notes: comment || undefined },
      {
        onSuccess: () => {
          setComment("");
          queryClient.invalidateQueries({
            queryKey: queryKeys.issueDetail(incidentId),
          });
        },
      }
    );
  }

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      {/* Back link */}
      <Link
        to="/incidents"
        className="inline-flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to Incidents
      </Link>

      {/* Header */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2 min-w-0">
            <h1 className="text-lg font-semibold text-zinc-100 break-words">
              {issue.title}
            </h1>
            {issue.description && (
              <p className="text-sm text-zinc-400 max-w-2xl">
                {issue.description}
              </p>
            )}
            <div className="flex items-center gap-3 flex-wrap">
              <SeverityBadge severity={issue.priority} />
              <StatusBadge status={issue.status} />
              {issue.source && (
                <span className="text-xs font-mono text-zinc-500">
                  {issue.source}
                </span>
              )}
              {issue.framework && (
                <span className="text-xs text-zinc-400">
                  {issue.framework} / {issue.control_id}
                </span>
              )}
            </div>
          </div>

          {/* Transition buttons */}
          {transitions.length > 0 && (
            <div className="flex items-center gap-2 shrink-0">
              {transitions.map((t) => (
                <Button
                  key={t}
                  variant="outline"
                  size="sm"
                  onClick={() => handleTransition(t)}
                  disabled={transitionMutation.isPending}
                >
                  {transitionMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                  ) : null}
                  {t.charAt(0).toUpperCase() + t.slice(1).replace(/_/g, " ")}
                </Button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Timeline */}
        <div className="col-span-2 space-y-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-4">
              Timeline
            </h3>

            {comments.length === 0 ? (
              <p className="text-sm text-zinc-500 py-4 text-center">
                No comments or status changes yet.
              </p>
            ) : (
              <div className="relative ml-3 border-l border-zinc-700 space-y-5 pl-6">
                {comments.map((c) => (
                  <div key={c.id} className="relative">
                    <div
                      className={cn(
                        "absolute -left-[30px] top-0.5 h-3 w-3 rounded-full border-2",
                        c.comment_type === "status_change"
                          ? "bg-indigo-400 border-indigo-400"
                          : "bg-zinc-700 border-zinc-600"
                      )}
                    />
                    <div className="flex items-center gap-2 text-xs text-zinc-500 mb-1">
                      <User className="h-3 w-3" />
                      <span className="text-zinc-300">{c.author}</span>
                      <span>{relativeTime(c.created_at)}</span>
                      {c.comment_type === "status_change" && (
                        <span className="rounded-md border border-indigo-500/20 bg-indigo-500/10 px-1.5 py-0.5 text-[10px] text-indigo-400">
                          status change
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-zinc-300">{c.content}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Add comment */}
            <div className="mt-5 pt-4 border-t border-zinc-800">
              <Textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Add a comment or note..."
                className="min-h-[80px]"
              />
              <div className="flex justify-end mt-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!comment.trim()}
                  onClick={() => {
                    // Comments are typically sent via transition or a dedicated endpoint.
                    // For now, trigger a transition with notes if a valid transition exists.
                    if (transitions.length > 0) {
                      handleTransition(issue.status);
                    }
                  }}
                >
                  <Send className="h-3.5 w-3.5 mr-1" />
                  Add Comment
                </Button>
              </div>
            </div>
          </div>
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
                <span>Assigned:</span>
                <span className="text-zinc-200">
                  {issue.assigned_to ?? "Unassigned"}
                </span>
              </div>
              <div className="flex items-center gap-2 text-zinc-400">
                <Clock className="h-3.5 w-3.5 text-zinc-500" />
                <span>Created:</span>
                <span className="text-zinc-200">
                  {formatDateTime(issue.created_at)}
                </span>
              </div>
              {issue.due_date && (
                <div className="flex items-center gap-2 text-zinc-400">
                  <Clock className="h-3.5 w-3.5 text-zinc-500" />
                  <span>Due:</span>
                  <span className="text-zinc-200">
                    {formatDateTime(issue.due_date)}
                  </span>
                </div>
              )}
              {issue.remediated_at && (
                <div className="text-zinc-400">
                  Remediated: {formatDateTime(issue.remediated_at)}
                </div>
              )}
              {issue.closed_at && (
                <div className="text-zinc-400">
                  Closed: {formatDateTime(issue.closed_at)}
                </div>
              )}
            </div>
          </div>

          {/* Risk acceptance */}
          {issue.risk_accepted && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4 space-y-2">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-amber-400">
                Risk Accepted
              </h3>
              <div className="text-sm text-zinc-300 space-y-1">
                {issue.risk_acceptance_owner && (
                  <p>Owner: {issue.risk_acceptance_owner}</p>
                )}
                {issue.risk_acceptance_expiry && (
                  <p>Expires: {formatDateTime(issue.risk_acceptance_expiry)}</p>
                )}
                {issue.risk_acceptance_justification && (
                  <p className="text-zinc-400 text-xs">
                    {issue.risk_acceptance_justification}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Linked finding */}
          {issue.finding_id && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Linked Finding
              </h3>
              <Link
                to={`/findings/${issue.finding_id}`}
                className="flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                {issue.finding_id}
              </Link>
            </div>
          )}

          {/* Tags */}
          {issue.tags && issue.tags.length > 0 && (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
                Tags
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {issue.tags.map((tag) => (
                  <span
                    key={tag}
                    className="rounded-md border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-400"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
