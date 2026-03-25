import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Search, LogOut, ChevronRight } from "lucide-react";

const routeLabels: Record<string, string> = {
  pipeline: "Pipeline",
  compliance: "Frameworks",
  findings: "Findings",
  remediation: "Remediation",
  incidents: "Incidents",
  risk: "Risk",
  audit: "Audit",
  settings: "Settings",
};

function buildBreadcrumbs(pathname: string) {
  if (pathname === "/") {
    return [{ label: "Dashboard", path: "/" }];
  }

  const segments = pathname.split("/").filter(Boolean);
  const crumbs = [];

  for (let i = 0; i < segments.length; i++) {
    const path = "/" + segments.slice(0, i + 1).join("/");
    const raw = segments[i];
    const label =
      routeLabels[raw] ||
      raw
        .split("-")
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");
    crumbs.push({ label, path });
  }

  return crumbs;
}

export default function Topbar() {
  const location = useLocation();
  const breadcrumbs = buildBreadcrumbs(location.pathname);

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-border bg-background px-4">
      {/* Left: Breadcrumbs */}
      <nav className="flex items-center gap-1 text-sm">
        {breadcrumbs.map((crumb, i) => {
          const isLast = i === breadcrumbs.length - 1;
          return (
            <span key={crumb.path} className="flex items-center gap-1">
              {i > 0 && (
                <ChevronRight className="h-3 w-3 text-muted-foreground" />
              )}
              {isLast ? (
                <span className="font-mono text-foreground">
                  {crumb.label}
                </span>
              ) : (
                <Link
                  to={crumb.path}
                  className="font-mono text-muted-foreground transition-colors hover:text-foreground"
                >
                  {crumb.label}
                </Link>
              )}
            </span>
          );
        })}
      </nav>

      {/* Right: Search + User */}
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" className="gap-2 text-muted-foreground">
          <Search className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">Search...</span>
          <kbd className="pointer-events-none hidden h-5 select-none items-center rounded border border-border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
            <span className="text-xs">&#8984;</span>K
          </kbd>
        </Button>

        <DropdownMenu>
          <DropdownMenuTrigger
            className={cn(
              "flex items-center gap-2 rounded-md px-1.5 py-1 transition-colors hover:bg-muted focus:outline-none"
            )}
          >
            <Avatar size="sm">
              <AvatarFallback className="bg-indigo-500/20 text-xs text-indigo-400">
                A
              </AvatarFallback>
            </Avatar>
          </DropdownMenuTrigger>
          <DropdownMenuContent side="bottom" align="end" sideOffset={8}>
            <DropdownMenuLabel className="flex flex-col gap-1 py-2">
              <span className="text-sm font-medium text-foreground">
                admin@acme.com
              </span>
              <Badge variant="secondary" className="w-fit text-[10px]">
                Admin
              </Badge>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="gap-2">
              <LogOut className="h-3.5 w-3.5" />
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
