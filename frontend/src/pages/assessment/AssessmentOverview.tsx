import { ClipboardCheck } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { useDashboardSummary } from "@/hooks/useApi";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export default function AssessmentOverview() {
  const { data: summary, isLoading } = useDashboardSummary();

  const frameworks = summary?.frameworks ?? [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Assessments</h1>
        <p className="text-sm text-zinc-500 mt-1">
          View assessment status across all compliance frameworks
        </p>
      </div>

      {isLoading && <TableSkeleton rows={8} />}

      {!isLoading && frameworks.length === 0 && (
        <EmptyState
          icon={ClipboardCheck}
          title="No assessments"
          description="Run the pipeline to generate assessment data."
        />
      )}

      {!isLoading && frameworks.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Framework</TableHead>
                <TableHead>Controls</TableHead>
                <TableHead>Compliant</TableHead>
                <TableHead>Non-Compliant</TableHead>
                <TableHead>Trend</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {frameworks.map((fw) => (
                <TableRow
                  key={fw.name}
                  className="border-zinc-800/50 hover:bg-zinc-800/50"
                >
                  <TableCell className="font-medium text-zinc-200">
                    {fw.name}
                  </TableCell>
                  <TableCell className="text-zinc-400">
                    {fw.total_controls}
                  </TableCell>
                  <TableCell className="text-green-400">
                    {fw.compliant_controls}
                  </TableCell>
                  <TableCell className="text-red-400">
                    {fw.total_controls - fw.compliant_controls}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        fw.trend === "improving" ? "default" : "secondary"
                      }
                      className="text-[10px] uppercase"
                    >
                      {fw.trend || "stable"}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
