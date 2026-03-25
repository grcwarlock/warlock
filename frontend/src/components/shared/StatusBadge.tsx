import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, string> = {
  compliant: "bg-green-500/10 text-green-400 border-green-500/20",
  non_compliant: "bg-red-500/10 text-red-400 border-red-500/20",
  partial: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  not_assessed: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  not_applicable: "bg-zinc-800/50 text-zinc-500 border-zinc-700/30",
};

const STATUS_LABELS: Record<string, string> = {
  compliant: "Compliant",
  non_compliant: "Non-Compliant",
  partial: "Partial",
  not_assessed: "Not Assessed",
  not_applicable: "N/A",
};

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.not_assessed;
  const label = STATUS_LABELS[status] ?? status.replace(/_/g, " ");

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        style,
        className
      )}
    >
      {label}
    </span>
  );
}
