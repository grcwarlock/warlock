import { Building2 } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { useVendorRisk } from "@/hooks/useApi";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export default function VendorOverview() {
  const { data: vendors, isLoading, isError } = useVendorRisk();

  const items = Array.isArray(vendors) ? vendors : [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">
          Vendor Management
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Third-party vendor risk assessments and monitoring
        </p>
      </div>

      {isLoading && <TableSkeleton rows={8} />}

      {!isLoading && (isError || items.length === 0) && (
        <EmptyState
          icon={Building2}
          title="No vendors"
          description="Vendor risk data is not yet available."
        />
      )}

      {!isLoading && !isError && items.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Vendor</TableHead>
                <TableHead>Risk Level</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((v, i) => (
                <TableRow
                  key={v.id ?? i}
                  className="border-zinc-800/50 hover:bg-zinc-800/50"
                >
                  <TableCell className="font-medium text-zinc-200">
                    {v.name ?? v.vendor_name ?? "Unknown"}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="secondary"
                      className={cn(
                        "text-[10px] uppercase",
                        v.risk_level === "high" && "text-red-400",
                        v.risk_level === "medium" && "text-amber-400",
                        v.risk_level === "low" && "text-green-400",
                      )}
                    >
                      {v.risk_level ?? "unknown"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-zinc-400">
                    {v.category ?? "general"}
                  </TableCell>
                  <TableCell className="text-zinc-400">
                    {v.status ?? "active"}
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
