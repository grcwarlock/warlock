import { useState } from "react";
import {
  Bot,
  CheckCircle2,
  Eye,
  EyeOff,
  Key,
  Loader2,
  Shield,
  Users,
  XCircle,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { TableSkeleton } from "@/components/shared/LoadingState";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  useAIStatus,
  useConfigureAI,
  useUsers,
  useAlertConfig,
  useUpdateAlertConfig,
} from "@/hooks/useApi";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

const PROVIDERS = ["anthropic", "openai", "gemini", "ollama"] as const;

// ---------------------------------------------------------------------------
// AI Configuration Tab
// ---------------------------------------------------------------------------

function AIConfigTab() {
  const { data: status, isLoading: statusLoading } = useAIStatus();
  const configureMutation = useConfigureAI();

  const [provider, setProvider] = useState("anthropic");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [confidenceFloor, setConfidenceFloor] = useState(0.7);
  const [temperature, setTemperature] = useState(0.0);
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  function handleSave() {
    configureMutation.mutate(
      {
        provider,
        api_key: apiKey,
        ...(baseUrl ? { base_url: baseUrl } : {}),
      },
      {
        onSuccess: (res) => {
          setTestResult({
            success: res.connected,
            message: res.connected
              ? `Connected to ${res.provider}. ${res.available_models.length} models available.`
              : "Connection failed. Check your API key and try again.",
          });
        },
        onError: (err) => {
          setTestResult({
            success: false,
            message: err instanceof Error ? err.message : "Configuration failed",
          });
        },
      }
    );
  }

  function handleTest() {
    handleSave();
  }

  return (
    <div className="space-y-6">
      {/* Current status */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500 mb-3">
          Current AI Status
        </h3>
        {statusLoading ? (
          <div className="flex items-center gap-2 text-sm text-zinc-500">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Loading status...
          </div>
        ) : status ? (
          <div className="flex items-center gap-6 text-sm flex-wrap">
            <div className="flex items-center gap-2">
              <div
                className={cn(
                  "h-2.5 w-2.5 rounded-full",
                  status.ai_enabled && status.healthy
                    ? "bg-green-400"
                    : "bg-zinc-600"
                )}
              />
              <span className="text-zinc-300">
                {status.ai_enabled ? "Enabled" : "Disabled"}
              </span>
            </div>
            <div className="text-zinc-400">
              Provider:{" "}
              <span className="text-zinc-200">{status.provider || "none"}</span>
            </div>
            <div className="text-zinc-400">
              Model:{" "}
              <span className="text-zinc-200">{status.model || "none"}</span>
            </div>
            <div className="text-zinc-400">
              Health:{" "}
              <span
                className={
                  status.healthy ? "text-green-400" : "text-red-400"
                }
              >
                {status.healthy ? "healthy" : "unhealthy"}
              </span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">No AI status available</p>
        )}
      </div>

      {/* Configuration form */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-5">
        <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
          Configure AI Provider
        </h3>

        <div className="grid grid-cols-2 gap-4">
          {/* Provider */}
          <div className="space-y-1.5">
            <Label htmlFor="ai-provider">Provider</Label>
            <select
              id="ai-provider"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            >
              {PROVIDERS.map((p) => (
                <option key={p} value={p} className="bg-zinc-900">
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </option>
              ))}
            </select>
          </div>

          {/* Model */}
          <div className="space-y-1.5">
            <Label htmlFor="ai-model">Model</Label>
            <Input
              id="ai-model"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="e.g. claude-sonnet-4-20250514"
            />
          </div>
        </div>

        {/* API Key */}
        <div className="space-y-1.5">
          <Label htmlFor="ai-key">API Key</Label>
          <div className="relative">
            <Input
              id="ai-key"
              type={showKey ? "text" : "password"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              className="pr-10"
            />
            <button
              type="button"
              onClick={() => setShowKey(!showKey)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              {showKey ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          </div>
        </div>

        {/* Base URL (Ollama) */}
        {provider === "ollama" && (
          <div className="space-y-1.5">
            <Label htmlFor="ai-base-url">Base URL</Label>
            <Input
              id="ai-base-url"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="http://localhost:11434"
            />
          </div>
        )}

        {/* Sliders */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label>
              Confidence Floor:{" "}
              <span className="font-mono text-zinc-400">
                {confidenceFloor.toFixed(2)}
              </span>
            </Label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={confidenceFloor}
              onChange={(e) => setConfidenceFloor(parseFloat(e.target.value))}
              className="w-full accent-indigo-500"
            />
            <div className="flex justify-between text-[10px] text-zinc-600">
              <span>0.0</span>
              <span>0.7 (default)</span>
              <span>1.0</span>
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>
              Temperature:{" "}
              <span className="font-mono text-zinc-400">
                {temperature.toFixed(2)}
              </span>
            </Label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className="w-full accent-indigo-500"
            />
            <div className="flex justify-between text-[10px] text-zinc-600">
              <span>0.0 (default)</span>
              <span>0.5</span>
              <span>1.0</span>
            </div>
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={cn(
              "flex items-center gap-2 rounded-lg border px-3 py-2 text-sm",
              testResult.success
                ? "border-green-500/20 bg-green-500/10 text-green-400"
                : "border-red-500/20 bg-red-500/10 text-red-400"
            )}
          >
            {testResult.success ? (
              <CheckCircle2 className="h-4 w-4 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 shrink-0" />
            )}
            {testResult.message}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            onClick={handleTest}
            disabled={!apiKey || configureMutation.isPending}
          >
            {configureMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
            ) : (
              <Bot className="h-4 w-4 mr-1.5" />
            )}
            Test Connection
          </Button>
          <Button
            onClick={handleSave}
            disabled={!apiKey || configureMutation.isPending}
          >
            {configureMutation.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
            ) : (
              <CheckCircle2 className="h-4 w-4 mr-1.5" />
            )}
            Save Configuration
          </Button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Users Tab
// ---------------------------------------------------------------------------

function UsersTab() {
  const { data: users, isLoading, isError } = useUsers();

  if (isLoading) return <TableSkeleton rows={6} />;

  const items = Array.isArray(users) ? users : [];

  if (isError || items.length === 0) {
    return (
      <EmptyState
        icon={Users}
        title="No users found"
        description="User management data is not available."
      />
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900">
      <Table>
        <TableHeader>
          <TableRow className="border-zinc-800 hover:bg-transparent">
            <TableHead>Email</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last Login</TableHead>
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
                    "inline-flex items-center gap-1.5 text-xs",
                    user.is_active ? "text-green-400" : "text-zinc-500"
                  )}
                >
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full",
                      user.is_active ? "bg-green-400" : "bg-zinc-600"
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
  );
}

// ---------------------------------------------------------------------------
// API Keys Tab
// ---------------------------------------------------------------------------

function APIKeysTab() {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-zinc-400">
          Manage API keys for programmatic access.
        </p>
        <Button variant="outline" size="sm">
          <Key className="h-3.5 w-3.5 mr-1.5" />
          Generate New Key
        </Button>
      </div>
      <div className="rounded-xl border border-zinc-800 bg-zinc-900">
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800 hover:bg-transparent">
              <TableHead>Name</TableHead>
              <TableHead>Scopes</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Last Used</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow className="border-zinc-800/50 hover:bg-zinc-800/50">
              <TableCell className="text-zinc-300">
                demo-key
              </TableCell>
              <TableCell>
                <Badge variant="secondary" className="text-[10px]">
                  read:all
                </Badge>
              </TableCell>
              <TableCell className="text-zinc-400">2026-01-15</TableCell>
              <TableCell className="text-zinc-400">2h ago</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Alerts Tab
// ---------------------------------------------------------------------------

function AlertsTab() {
  const { data: config, isLoading } = useAlertConfig();
  const updateMutation = useUpdateAlertConfig();

  const [slackUrl, setSlackUrl] = useState("");
  const [pagerdutyKey, setPagerdutyKey] = useState("");
  const [slackSeverity, setSlackSeverity] = useState("high");
  const [pdSeverity, setPdSeverity] = useState("critical");
  const [saved, setSaved] = useState(false);

  function handleSave() {
    updateMutation.mutate(
      {
        alert_rules: [
          {
            channel: "slack",
            webhook_url: slackUrl,
            min_severity: slackSeverity,
          },
          {
            channel: "pagerduty",
            routing_key: pagerdutyKey,
            min_severity: pdSeverity,
          },
        ],
      },
      {
        onSuccess: () => {
          setSaved(true);
          setTimeout(() => setSaved(false), 3000);
        },
      }
    );
  }

  if (isLoading) return <TableSkeleton rows={4} />;

  return (
    <div className="space-y-6">
      {/* Slack */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-4">
        <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
          Slack Integration
        </h3>
        <div className="space-y-1.5">
          <Label htmlFor="slack-url">Webhook URL</Label>
          <Input
            id="slack-url"
            value={slackUrl}
            onChange={(e) => setSlackUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/..."
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="slack-severity">Minimum Severity</Label>
          <select
            id="slack-severity"
            value={slackSeverity}
            onChange={(e) => setSlackSeverity(e.target.value)}
            className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="critical" className="bg-zinc-900">Critical</option>
            <option value="high" className="bg-zinc-900">High</option>
            <option value="medium" className="bg-zinc-900">Medium</option>
            <option value="low" className="bg-zinc-900">Low</option>
          </select>
        </div>
      </div>

      {/* PagerDuty */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 space-y-4">
        <h3 className="text-[11px] uppercase tracking-[0.06em] text-zinc-500">
          PagerDuty Integration
        </h3>
        <div className="space-y-1.5">
          <Label htmlFor="pd-key">Routing Key</Label>
          <Input
            id="pd-key"
            value={pagerdutyKey}
            onChange={(e) => setPagerdutyKey(e.target.value)}
            placeholder="Routing key..."
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="pd-severity">Minimum Severity</Label>
          <select
            id="pd-severity"
            value={pdSeverity}
            onChange={(e) => setPdSeverity(e.target.value)}
            className="h-8 w-full rounded-lg border border-input bg-transparent px-2.5 py-1 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="critical" className="bg-zinc-900">Critical</option>
            <option value="high" className="bg-zinc-900">High</option>
            <option value="medium" className="bg-zinc-900">Medium</option>
            <option value="low" className="bg-zinc-900">Low</option>
          </select>
        </div>
      </div>

      {/* Save */}
      <div className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={updateMutation.isPending}>
          {updateMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
          ) : (
            <CheckCircle2 className="h-4 w-4 mr-1.5" />
          )}
          Save Alert Configuration
        </Button>
        {saved && (
          <span className="text-sm text-green-400">Saved successfully</span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Settings Page
// ---------------------------------------------------------------------------

export default function SettingsOverview() {
  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">Settings</h1>
        <p className="text-sm text-zinc-500 mt-0.5">
          Platform configuration and integrations
        </p>
      </div>

      <Tabs defaultValue={0}>
        <TabsList>
          <TabsTrigger value={0}>
            <Bot className="h-3.5 w-3.5 mr-1" />
            AI Configuration
          </TabsTrigger>
          <TabsTrigger value={1}>
            <Users className="h-3.5 w-3.5 mr-1" />
            Users
          </TabsTrigger>
          <TabsTrigger value={2}>
            <Key className="h-3.5 w-3.5 mr-1" />
            API Keys
          </TabsTrigger>
          <TabsTrigger value={3}>
            <Shield className="h-3.5 w-3.5 mr-1" />
            Alerts
          </TabsTrigger>
        </TabsList>

        <TabsContent value={0}>
          <AIConfigTab />
        </TabsContent>
        <TabsContent value={1}>
          <UsersTab />
        </TabsContent>
        <TabsContent value={2}>
          <APIKeysTab />
        </TabsContent>
        <TabsContent value={3}>
          <AlertsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
