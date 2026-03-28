import { ShieldCheck } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { useCoverage } from "@/hooks/useApi";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

export default function GDPROverview() {
  const { data: coverageList, isLoading } = useCoverage("gdpr");

  const items = Array.isArray(coverageList) ? coverageList : [];
  const gdprData = items.length > 0 ? items[0] : null;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">
          GDPR Compliance
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Data protection and privacy compliance workflows
        </p>
      </div>

      {isLoading && <TableSkeleton rows={6} />}

      {!isLoading && !gdprData && (
        <EmptyState
          icon={ShieldCheck}
          title="No GDPR data"
          description="Run the pipeline with GDPR framework enabled to see compliance data."
        />
      )}

      {!isLoading && gdprData && (
        <>
          <div className="grid grid-cols-4 gap-4">
            {[
              {
                label: "Compliant",
                value: gdprData.compliant,
                color: "text-green-400",
              },
              {
                label: "Non-Compliant",
                value: gdprData.non_compliant,
                color: "text-red-400",
              },
              {
                label: "Partial",
                value: gdprData.partial,
                color: "text-amber-400",
              },
              {
                label: "Not Assessed",
                value: gdprData.not_assessed,
                color: "text-zinc-400",
              },
            ].map((stat) => (
              <div
                key={stat.label}
                className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"
              >
                <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                  {stat.label}
                </div>
                <div className={cn("text-2xl font-bold mt-1", stat.color)}>
                  {stat.value}
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead>Workflow</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[
                  {
                    name: "Data Subject Access Requests",
                    desc: "Process DSAR requests within 30-day window",
                    status: "active",
                  },
                  {
                    name: "Breach Notification",
                    desc: "72-hour notification workflow to supervisory authority",
                    status: "active",
                  },
                  {
                    name: "Data Erasure",
                    desc: "Right to erasure (anonymization) workflow",
                    status: "active",
                  },
                  {
                    name: "Consent Management",
                    desc: "Track and manage processing consent records",
                    status: "configured",
                  },
                  {
                    name: "Data Portability",
                    desc: "Export personal data in machine-readable format",
                    status: "configured",
                  },
                ].map((wf) => (
                  <TableRow
                    key={wf.name}
                    className="border-zinc-800/50 hover:bg-zinc-800/50"
                  >
                    <TableCell className="font-medium text-zinc-200">
                      {wf.name}
                    </TableCell>
                    <TableCell className="text-zinc-400">{wf.desc}</TableCell>
                    <TableCell>
                      <span
                        className={cn(
                          "inline-flex items-center gap-1.5 text-xs",
                          wf.status === "active"
                            ? "text-green-400"
                            : "text-zinc-500",
                        )}
                      >
                        <span
                          className={cn(
                            "h-1.5 w-1.5 rounded-full",
                            wf.status === "active"
                              ? "bg-green-400"
                              : "bg-zinc-600",
                          )}
                        />
                        {wf.status}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}
    </div>
  );
}
