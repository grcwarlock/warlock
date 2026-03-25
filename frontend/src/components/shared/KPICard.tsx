import { cn } from "@/lib/utils";
import { Link } from "react-router-dom";

interface KPICardProps {
  label: string;
  value: string | number;
  trend?: {
    text: string;
    direction: "up" | "down" | "neutral";
  };
  href?: string;
  valueColor?: string;
  className?: string;
}

export function KPICard({ label, value, trend, href, valueColor, className }: KPICardProps) {
  const content = (
    <div
      className={cn(
        "rounded-xl border border-zinc-800 bg-zinc-900 p-4 transition-colors hover:border-zinc-700 cursor-pointer",
        className
      )}
    >
      <div className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-1.5">{label}</div>
      <div className={cn("text-[28px] font-bold tracking-tight", valueColor)}>{value}</div>
      {trend && (
        <div
          className={cn("text-[11px] mt-1", {
            "text-green-400": trend.direction === "up",
            "text-red-400": trend.direction === "down",
            "text-zinc-500": trend.direction === "neutral",
          })}
        >
          {trend.direction === "up" && "▲ "}
          {trend.direction === "down" && "▼ "}
          {trend.text}
        </div>
      )}
    </div>
  );

  if (href) {
    return <Link to={href}>{content}</Link>;
  }

  return content;
}
