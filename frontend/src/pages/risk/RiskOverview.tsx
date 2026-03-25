import { useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  Loader2,
  Shield,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import { useVendorRisk, useAnalyzeRisk } from "@/hooks/useApi";
import type { VendorRisk, RiskAnalysis } from "@/api/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function riskScoreColor(score: number): string {
  if (score > 80) return "text-green-400";
  if (score >= 60) return "text-amber-400";
  return "text-red-400";
}

function riskScoreBg(score: number): string {
  if (score > 80) return "bg-green-500/10";
  if (score >= 60) return "bg-amber-500/10";
  return "bg-red-500/10";
}

function riskLevelBadge(level: string): string {
  switch (level.toLowerCase()) {
    case "low":
      return "bg-green-500/10 text-green-400 border-green-500/20";
    case "medium":
      return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "critical":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    default:
      return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
  }
}

function formatCurrency(value: number): string {
  if (value >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `$${(value / 1_000).toFixed(0)}K`;
  return `$${value.toFixed(0)}`;
}

// ---------------------------------------------------------------------------
// Vendor Risk Tab
// ---------------------------------------------------------------------------

function VendorRiskTab() {
  const { data: vendors, isLoading, isError } = useVendorRisk();

  if (isLoading) return <TableSkeleton rows={8} />;

  const items: VendorRisk[] = Array.isArray(vendors) ? vendors : [];

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={Shield}
        title="No vendor risk data"
        description="Run a vendor risk assessment to populate this view."
      />
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900">
      <Table>
        <TableHeader>
          <TableRow className="border-zinc-800 hover:bg-transparent">
            <TableHead>Vendor</TableHead>
            <TableHead>Risk Score</TableHead>
            <TableHead>Risk Level</TableHead>
            <TableHead>Security Posture</TableHead>
            <TableHead>SLA Compliance</TableHead>
            <TableHead>Issues</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((v, idx) => (
            <TableRow
              key={v.vendor_id}
              className={cn(
                "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                idx % 2 === 1 && "bg-zinc-900/50"
              )}
            >
              <TableCell className="text-zinc-200 font-medium">
                {v.vendor_name}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <div
                    className={cn(
                      "h-7 w-12 flex items-center justify-center rounded-md text-xs font-bold",
                      riskScoreBg(v.overall_score),
                      riskScoreColor(v.overall_score)
                    )}
                  >
                    {v.overall_score}
                  </div>
                </div>
              </TableCell>
              <TableCell>
                <span
                  className={cn(
                    "inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                    riskLevelBadge(v.risk_level)
                  )}
                >
                  {v.risk_level}
                </span>
              </TableCell>
              <TableCell>
                <span className={cn("text-sm font-mono", riskScoreColor(v.security_posture_score))}>
                  {v.security_posture_score}
                </span>
              </TableCell>
              <TableCell>
                <span className={cn("text-sm font-mono", riskScoreColor(v.sla_compliance_score))}>
                  {v.sla_compliance_score}
                </span>
              </TableCell>
              <TableCell className="text-zinc-400 text-sm">
                {v.issues_count}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Risk Register Tab (Monte Carlo analysis)
// ---------------------------------------------------------------------------

function RiskRegisterTab() {
  const analyzeMutation = useAnalyzeRisk();
  const [framework, setFramework] = useState("nist_800_53");
  const [result, setResult] = useState<RiskAnalysis | null>(null);

  function handleAnalyze() {
    analyzeMutation.mutate(
      { framework, iterations: 10000 },
      {
        onSuccess: (data) => setResult(data),
      }
    );
  }

  return (
    <div className="space-y-5">
      {/* Analysis trigger */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
          Monte Carlo Risk Analysis
        </h3>
        <div className="flex items-center gap-3">
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value)}
            className="h-8 rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="nist_800_53" className="bg-zinc-900">NIST 800-53</option>
            <option value="iso_27001" className="bg-zinc-900">ISO 27001</option>
            <option value="soc2" className="bg-zinc-900">SOC 2</option>
            <option value="hipaa" className="bg-zinc-900">HIPAA</option>
            <option value="pci_dss" className="bg-zinc-900">PCI DSS</option>
          </select>
          <Button onClick={handleAnalyze} disabled={analyzeMutation.isPending}>
            {analyzeMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
            ) : (
              <BarChart3 className="h-4 w-4 mr-1.5" />
            )}
            Run Analysis
          </Button>
        </div>
      </div>

      {/* Results */}
      {result && (
        <>
          {/* Portfolio summary */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: "Total Mean ALE", value: formatCurrency(result.portfolio.total_mean_ale) },
              { label: "VaR (95%)", value: formatCurrency(result.portfolio.total_var_95) },
              { label: "VaR (99%)", value: formatCurrency(result.portfolio.total_var_99) },
              { label: "Scenarios", value: String(result.portfolio.scenario_count) },
            ].map((kpi) => (
              <div
                key={kpi.label}
                className="rounded-xl border border-zinc-800 bg-zinc-900 p-4"
              >
                <div className="text-[10px] uppercase tracking-wide text-zinc-500">
                  {kpi.label}
                </div>
                <div className="text-xl font-bold text-zinc-100 mt-1">
                  {kpi.value}
                </div>
              </div>
            ))}
          </div>

          {/* Scenarios table */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead>Scenario</TableHead>
                  <TableHead>Mean ALE</TableHead>
                  <TableHead>VaR 95%</TableHead>
                  <TableHead>VaR 99%</TableHead>
                  <TableHead>Control Effectiveness</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.scenarios.map((s, idx) => (
                  <TableRow
                    key={s.name}
                    className={cn(
                      "border-zinc-800/50 hover:bg-zinc-800/50 transition-colors",
                      idx % 2 === 1 && "bg-zinc-900/50"
                    )}
                  >
                    <TableCell className="text-zinc-200">{s.name}</TableCell>
                    <TableCell className="text-zinc-300 font-mono text-xs">
                      {formatCurrency(s.mean_ale)}
                    </TableCell>
                    <TableCell className="text-zinc-300 font-mono text-xs">
                      {formatCurrency(s.var_95)}
                    </TableCell>
                    <TableCell className="text-zinc-300 font-mono text-xs">
                      {formatCurrency(s.var_99)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-zinc-700 max-w-[100px]">
                          <div
                            className={cn(
                              "h-full rounded-full",
                              s.control_effectiveness > 0.7
                                ? "bg-green-400"
                                : s.control_effectiveness > 0.4
                                  ? "bg-amber-400"
                                  : "bg-red-400"
                            )}
                            style={{
                              width: `${(s.control_effectiveness * 100).toFixed(0)}%`,
                            }}
                          />
                        </div>
                        <span className="text-xs text-zinc-400 font-mono">
                          {(s.control_effectiveness * 100).toFixed(0)}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* AI narrative */}
          {result.ai_narrative && (
            <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-4">
              <h3 className="text-[11px] uppercase tracking-[0.06em] text-indigo-400 mb-2">
                AI Risk Narrative
              </h3>
              <p className="text-sm text-zinc-300 whitespace-pre-wrap">
                {result.ai_narrative}
              </p>
              {result.ai_metadata && (
                <div className="mt-2 flex items-center gap-3 text-[10px] text-zinc-500">
                  <span>{result.ai_metadata.provider}/{result.ai_metadata.model}</span>
                  <span>{result.ai_metadata.latency_ms}ms</span>
                  <span>confidence: {(result.ai_metadata.confidence * 100).toFixed(0)}%</span>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {!result && !analyzeMutation.isPending && (
        <EmptyState
          icon={BarChart3}
          title="No analysis results"
          description="Select a framework and run the Monte Carlo analysis to see risk scenarios."
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export default function RiskOverview() {
  return (
    <div className="p-6 space-y-5 max-w-[1440px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Risk</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Vendor risk assessments and quantitative risk analysis
        </p>
      </div>

      <Tabs defaultValue={0}>
        <TabsList>
          <TabsTrigger value={0}>
            <Shield className="h-3.5 w-3.5 mr-1" />
            Vendor Risk
          </TabsTrigger>
          <TabsTrigger value={1}>
            <AlertTriangle className="h-3.5 w-3.5 mr-1" />
            Risk Register
          </TabsTrigger>
        </TabsList>

        <TabsContent value={0}>
          <VendorRiskTab />
        </TabsContent>
        <TabsContent value={1}>
          <RiskRegisterTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
