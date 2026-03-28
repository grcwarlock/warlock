import { Users } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { useUsers } from "@/hooks/useApi";
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

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function PersonnelOverview() {
  const { data: users, isLoading, isError } = useUsers();

  const items = Array.isArray(users) ? users : [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Personnel</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Personnel security and access management
        </p>
      </div>

      {isLoading && <TableSkeleton rows={8} />}

      {!isLoading && (isError || items.length === 0) && (
        <EmptyState
          icon={Users}
          title="No personnel data"
          description="Personnel data is not yet available."
        />
      )}

      {!isLoading && !isError && items.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Active</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((user) => (
                <TableRow
                  key={user.id}
                  className="border-zinc-800/50 hover:bg-zinc-800/50"
                >
                  <TableCell className="font-medium text-zinc-200">
                    {user.name}
                  </TableCell>
                  <TableCell className="font-mono text-zinc-400">
                    {user.email}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={user.role === "admin" ? "default" : "secondary"}
                      className="text-[10px] uppercase"
                    >
                      {user.role}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span
                      className={cn(
                        "inline-flex items-center gap-1.5 text-xs",
                        user.is_active ? "text-green-400" : "text-zinc-500",
                      )}
                    >
                      <span
                        className={cn(
                          "h-1.5 w-1.5 rounded-full",
                          user.is_active ? "bg-green-400" : "bg-zinc-600",
                        )}
                      />
                      {user.is_active ? "Active" : "Inactive"}
                    </span>
                  </TableCell>
                  <TableCell className="text-zinc-400">
                    {relativeTime(user.last_login)}
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
