import { UserCog } from "lucide-react";
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

export default function UserManagement() {
  const { data: users, isLoading, isError } = useUsers();

  const items = Array.isArray(users) ? users : [];

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">
          User Management
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Manage users, roles, and permissions
        </p>
      </div>

      {isLoading && <TableSkeleton rows={8} />}

      {!isLoading && (isError || items.length === 0) && (
        <EmptyState
          icon={UserCog}
          title="No users"
          description="No user data available."
        />
      )}

      {!isLoading && !isError && items.length > 0 && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800 hover:bg-transparent">
                <TableHead>Email</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((user) => (
                <TableRow
                  key={user.id}
                  className="border-zinc-800/50 hover:bg-zinc-800/50"
                >
                  <TableCell className="font-mono text-zinc-200">
                    {user.email}
                  </TableCell>
                  <TableCell className="text-zinc-300">{user.name}</TableCell>
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
                        "text-xs",
                        user.is_active ? "text-green-400" : "text-zinc-500",
                      )}
                    >
                      {user.is_active ? "Active" : "Inactive"}
                    </span>
                  </TableCell>
                  <TableCell className="text-zinc-500 text-xs">
                    {/* TODO: Wire edit/deactivate actions to API */}
                    Edit | Deactivate
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
