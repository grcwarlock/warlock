import { useState, useEffect, useRef, useCallback } from "react";
import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  LayoutDashboard,
  GitBranch,
  Shield,
  Search,
  Wrench,
  AlertTriangle,
  BarChart3,
  FileCheck,
  Settings,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";

const STORAGE_KEY = "warlock-sidebar-collapsed";
const HOVER_DELAY = 300;

interface NavItem {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  path: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const mainSections: NavSection[] = [
  {
    title: "OVERVIEW",
    items: [
      { icon: LayoutDashboard, label: "Dashboard", path: "/" },
      { icon: GitBranch, label: "Pipeline", path: "/pipeline" },
    ],
  },
  {
    title: "COMPLIANCE",
    items: [
      { icon: Shield, label: "Frameworks", path: "/compliance" },
      { icon: Search, label: "Findings", path: "/findings" },
      { icon: Wrench, label: "Remediation", path: "/remediation" },
    ],
  },
  {
    title: "OPERATIONS",
    items: [
      { icon: AlertTriangle, label: "Incidents", path: "/incidents" },
      { icon: BarChart3, label: "Risk", path: "/risk" },
      { icon: FileCheck, label: "Audit", path: "/audit" },
    ],
  },
];

const bottomItems: NavItem[] = [
  { icon: Settings, label: "Settings", path: "/settings" },
];

function isActive(currentPath: string, itemPath: string): boolean {
  if (itemPath === "/") return currentPath === "/";
  return currentPath === itemPath || currentPath.startsWith(itemPath + "/");
}

export default function Sidebar() {
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === null ? true : stored === "true";
  });
  const [peeking, setPeeking] = useState(false);
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sidebarRef = useRef<HTMLElement>(null);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, String(collapsed));
  }, [collapsed]);

  const handleMouseEnter = useCallback(() => {
    if (!collapsed) return;
    hoverTimerRef.current = setTimeout(() => {
      setPeeking(true);
    }, HOVER_DELAY);
  }, [collapsed]);

  const handleMouseLeave = useCallback(() => {
    if (hoverTimerRef.current) {
      clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = null;
    }
    setPeeking(false);
  }, []);

  useEffect(() => {
    return () => {
      if (hoverTimerRef.current) clearTimeout(hoverTimerRef.current);
    };
  }, []);

  const expanded = !collapsed || peeking;

  const toggleCollapse = () => {
    setCollapsed((prev) => !prev);
    setPeeking(false);
  };

  return (
    <TooltipProvider delay={0}>
      <aside
        ref={sidebarRef}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className={cn(
          "flex h-screen flex-col border-r border-border bg-sidebar text-sidebar-foreground transition-[width] duration-200 ease-in-out",
          expanded ? "w-60" : "w-14"
        )}
      >
        {/* Logo */}
        <div className="flex h-12 items-center gap-2.5 border-b border-border px-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-indigo-500 text-sm font-bold text-white">
            W
          </div>
          <span
            className={cn(
              "overflow-hidden text-sm font-semibold tracking-tight transition-[opacity,width] duration-200",
              expanded
                ? "w-auto opacity-100"
                : "w-0 opacity-0"
            )}
          >
            Warlock
          </span>
        </div>

        {/* Main navigation */}
        <nav className="flex flex-1 flex-col gap-1 overflow-y-auto px-2 py-3">
          {mainSections.map((section) => (
            <div key={section.title} className="mb-2">
              <div
                className={cn(
                  "mb-1 overflow-hidden px-2 text-[10px] font-medium uppercase tracking-widest text-muted-foreground transition-[opacity,height] duration-200",
                  expanded
                    ? "h-4 opacity-100"
                    : "h-0 opacity-0"
                )}
              >
                {section.title}
              </div>
              {section.items.map((item) => (
                <SidebarLink
                  key={item.path}
                  item={item}
                  active={isActive(location.pathname, item.path)}
                  expanded={expanded}
                  collapsed={collapsed}
                />
              ))}
            </div>
          ))}
        </nav>

        {/* Bottom section */}
        <div className="flex flex-col gap-1 border-t border-border px-2 py-2">
          {bottomItems.map((item) => (
            <SidebarLink
              key={item.path}
              item={item}
              active={isActive(location.pathname, item.path)}
              expanded={expanded}
              collapsed={collapsed}
            />
          ))}

          {/* Collapse toggle */}
          <button
            onClick={toggleCollapse}
            className="flex h-8 w-full items-center gap-2.5 rounded-md px-2 text-sm text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
          >
            {collapsed ? (
              <ChevronsRight className="h-4 w-4 shrink-0" />
            ) : (
              <ChevronsLeft className="h-4 w-4 shrink-0" />
            )}
            <span
              className={cn(
                "overflow-hidden whitespace-nowrap transition-[opacity,width] duration-200",
                expanded ? "w-auto opacity-100" : "w-0 opacity-0"
              )}
            >
              Collapse
            </span>
          </button>
        </div>
      </aside>
    </TooltipProvider>
  );
}

function SidebarLink({
  item,
  active,
  expanded,
  collapsed,
}: {
  item: NavItem;
  active: boolean;
  expanded: boolean;
  collapsed: boolean;
}) {
  const Icon = item.icon;

  const linkContent = (
    <Link
      to={item.path}
      className={cn(
        "flex h-8 items-center gap-2.5 rounded-md px-2 text-sm transition-colors",
        active
          ? "bg-indigo-500/10 text-white"
          : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span
        className={cn(
          "overflow-hidden whitespace-nowrap transition-[opacity,width] duration-200",
          expanded ? "w-auto opacity-100" : "w-0 opacity-0"
        )}
      >
        {item.label}
      </span>
    </Link>
  );

  if (collapsed && !expanded) {
    return (
      <Tooltip>
        <TooltipTrigger render={<div />}>{linkContent}</TooltipTrigger>
        <TooltipContent side="right" sideOffset={8}>
          {item.label}
        </TooltipContent>
      </Tooltip>
    );
  }

  return linkContent;
}
