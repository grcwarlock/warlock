# Frontend Plan 1: Scaffold + Auth + Shell

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a running Vite + React + shadcn/ui application with JWT authentication, collapsible icon-rail sidebar, breadcrumb topbar, and routing stubs for all 9 pages.

**Architecture:** SPA in `frontend/` directory, Vite dev server proxied to FastAPI on :8000. TanStack Query for server state, React Router v6 for routing. Dark zinc theme with Geist fonts. Auth via JWT stored in memory (with refresh token in httpOnly cookie pattern).

**Tech Stack:** Vite 6, React 18, TypeScript, Tailwind CSS 4, shadcn/ui, React Router 6, TanStack Query 5, Recharts 2, Geist fonts

**Spec:** `docs/superpowers/specs/2026-03-25-frontend-design.md`

**IMPORTANT — Before starting:**
- Read the full spec at the path above
- Read CLAUDE.md for project rules
- The FastAPI backend runs on port 8000. The Vite dev server runs on port 5173 with a proxy to 8000.
- All API calls go through `/api/v1/` prefix
- Demo credentials: `admin@acme.com` / `WarlockAdmin2026!`

---

## Task 1: Scaffold Vite + React + TypeScript project

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/vite.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/tsconfig.app.json`
- Create: `frontend/tsconfig.node.json`
- Create: `frontend/index.html`
- Create: `frontend/src/main.tsx`
- Create: `frontend/src/App.tsx`
- Create: `frontend/src/index.css`
- Create: `frontend/components.json` (shadcn config)

**Note:** Tailwind v4 with `@tailwindcss/vite` does NOT use `postcss.config.js` or `tailwind.config.ts`. Do not create those files.

- [ ] **Step 1: Update .gitignore BEFORE scaffolding**

Add to `.gitignore`:
```
frontend/node_modules/
frontend/dist/
.superpowers/
```

- [ ] **Step 2: Create the Vite project**

```bash
cd /Users/jsn/warlock
npm create vite@latest frontend -- --template react-ts
cd frontend
```

- [ ] **Step 3: Install core dependencies**

```bash
cd /Users/jsn/warlock/frontend
npm install
npm install @tanstack/react-query react-router-dom recharts lucide-react clsx tailwind-merge
npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 4: Configure Vite with API proxy**

Write `frontend/vite.config.ts`:

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
```

- [ ] **Step 5: Initialize shadcn/ui FIRST (before custom CSS)**

```bash
cd /Users/jsn/warlock/frontend
npx shadcn@latest init
```

Select: New York style, zinc base, CSS variables enabled. This will create `src/lib/utils.ts` with `cn()` and may modify `index.css`.

Then install essential components:

```bash
npx shadcn@latest add button card badge table tabs input label separator tooltip dropdown-menu avatar sheet dialog command scroll-area
```

- [ ] **Step 6: Override index.css with dark zinc theme**

**AFTER shadcn init**, overwrite `frontend/src/index.css` with the custom theme (shadcn may have written its own CSS vars — replace them):

```css
@import "tailwindcss";

@theme {
  --color-background: #09090b;
  --color-foreground: #fafafa;
  --color-card: #18181b;
  --color-card-foreground: #fafafa;
  --color-popover: #18181b;
  --color-popover-foreground: #fafafa;
  --color-primary: #6366f1;
  --color-primary-foreground: #fafafa;
  --color-secondary: #27272a;
  --color-secondary-foreground: #fafafa;
  --color-muted: #27272a;
  --color-muted-foreground: #a1a1aa;
  --color-accent: #27272a;
  --color-accent-foreground: #fafafa;
  --color-destructive: #ef4444;
  --color-destructive-foreground: #fafafa;
  --color-border: #27272a;
  --color-input: #27272a;
  --color-ring: #6366f1;
  --color-success: #22c55e;
  --color-warning: #f59e0b;
  --color-ai: #a78bfa;
  --radius: 0.5rem;
}

body {
  background-color: var(--color-background);
  color: var(--color-foreground);
  font-family: "Geist", "Inter", system-ui, sans-serif;
}

code, .font-mono {
  font-family: "Geist Mono", "Fira Code", monospace;
}
```

- [ ] **Step 7: Verify `src/lib/utils.ts` exists with cn() utility**

shadcn init should have created it. If not, create it:

```typescript
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
```

- [ ] **Step 8: Verify the dev server starts**

```bash
cd /Users/jsn/warlock/frontend
npm run dev
```

Open http://localhost:5173 — should show the default Vite React page with dark background.

- [ ] **Step 9: Commit**

```bash
cd /Users/jsn/warlock
git add .gitignore frontend/
git commit -m "feat(frontend): scaffold Vite + React + TypeScript + shadcn/ui + Tailwind dark theme"
```

---

## Task 2: API client with JWT auth

**Files:**
- Create: `frontend/src/api/client.ts`
- Create: `frontend/src/api/auth.ts`
- Create: `frontend/src/api/types.ts`
- Create: `frontend/src/hooks/useAuth.ts`
- Create: `frontend/src/contexts/AuthContext.tsx`

- [ ] **Step 1: Create the base API client**

Write `frontend/src/api/client.ts` — a fetch wrapper that:
- Prepends `/api/v1/` to all paths
- Attaches `Authorization: Bearer {token}` from in-memory storage
- On 401 response, attempts token refresh via `/api/v1/auth/refresh`
- If refresh fails, redirects to `/login`
- Returns typed JSON responses

```typescript
let accessToken: string | null = null;
let refreshToken: string | null = null;

export function setTokens(access: string | null, refresh: string | null = null) {
  accessToken = access;
  if (refresh !== null) refreshToken = refresh;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
}

export async function api<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && accessToken) {
    // Try refresh — backend requires refresh_token in body
    if (!refreshToken) {
      clearTokens();
      window.location.href = "/login";
      throw new ApiError(401, "No refresh token");
    }
    const refreshResponse = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (refreshResponse.ok) {
      const data = await refreshResponse.json();
      setTokens(data.access_token, data.refresh_token);
      headers["Authorization"] = `Bearer ${accessToken}`;
      const retryResponse = await fetch(`/api/v1${path}`, {
        ...options,
        headers,
      });
      if (!retryResponse.ok) {
        throw new ApiError(retryResponse.status, await retryResponse.text());
      }
      return retryResponse.json();
    }

    // Refresh failed — clear tokens, redirect to login
    clearTokens();
    window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }

  if (!response.ok) {
    throw new ApiError(response.status, await response.text());
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

export class ApiError extends Error {
  constructor(public status: number, public body: string) {
    super(`API Error ${status}: ${body}`);
  }
}
```

- [ ] **Step 2: Create auth API functions**

Write `frontend/src/api/auth.ts`:

```typescript
import { api, setTokens, clearTokens, getAccessToken } from "./client";

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface MFARequiredResponse {
  mfa_required: true;
  mfa_token: string;
  message: string;
}

export interface User {
  id: string;
  email: string;
  role: string;
  full_name: string | null;
}

export async function login(
  credentials: LoginRequest
): Promise<LoginResponse | MFARequiredResponse> {
  const data = await api<LoginResponse | MFARequiredResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(credentials),
  });
  // Check for MFA challenge
  if ("mfa_required" in data && data.mfa_required) {
    return data as MFARequiredResponse;
  }
  const loginData = data as LoginResponse;
  setTokens(loginData.access_token, loginData.refresh_token);
  return loginData;
}

export async function logout(): Promise<void> {
  try {
    await api("/auth/logout", { method: "POST" });
  } finally {
    clearTokens();
  }
}

export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}
```

- [ ] **Step 3: Create AuthContext and useAuth hook**

Write `frontend/src/contexts/AuthContext.tsx` — React context that:
- Stores auth state (user, isAuthenticated, isLoading)
- Provides login/logout functions
- On mount, checks if token exists (from prior session via refresh)
- Wraps children — unauthenticated users see login page

Write `frontend/src/hooks/useAuth.ts` — convenience hook for accessing auth context.

- [ ] **Step 4: Verify login works against the running API**

Start the FastAPI backend (`make demo` in another terminal), then:

```bash
cd /Users/jsn/warlock/frontend
npm run dev
```

Open browser console, test:
```javascript
const res = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'admin@acme.com', password: 'WarlockAdmin2026!'})
});
const data = await res.json();
console.log(data.access_token); // should print a JWT
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api/ frontend/src/hooks/ frontend/src/contexts/
git commit -m "feat(frontend): API client with JWT auth, login/logout, AuthContext"
```

---

## Task 3: Login page

**Files:**
- Create: `frontend/src/pages/Login.tsx`

- [ ] **Step 1: Build the login page**

Full-screen centered card on dark background:
- Warlock logo/name at top
- Email + password fields (pre-filled with demo credentials)
- "Sign In" button
- Error message display
- On success → redirect to `/`
- Loading state while authenticating

Use shadcn Card, Input, Button, Label components.

- [ ] **Step 2: Verify login flow end-to-end**

1. Navigate to http://localhost:5173/login
2. Credentials should be pre-filled
3. Click "Sign In"
4. Should redirect to `/` (blank page is fine — shell comes next)
5. Refresh page — should stay authenticated (or redirect back to login if no refresh token)

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Login.tsx
git commit -m "feat(frontend): login page with demo credentials pre-filled"
```

---

## Task 4: App shell — collapsible sidebar + topbar

**Files:**
- Create: `frontend/src/components/layout/AppShell.tsx`
- Create: `frontend/src/components/layout/Sidebar.tsx`
- Create: `frontend/src/components/layout/Topbar.tsx`
- Modify: `frontend/src/App.tsx`

- [ ] **Step 1: Build the Sidebar component**

Collapsible icon rail:
- Default width: 56px (icons only)
- Expanded width: 240px (icons + labels)
- Toggle via hover or pin button
- Persist collapsed/expanded state in localStorage
- Use lucide-react icons for each section:
  - LayoutDashboard → Dashboard
  - GitBranch → Pipeline
  - Shield → Compliance
  - Search → Findings
  - Wrench → Remediation
  - AlertTriangle → Incidents
  - BarChart3 → Risk
  - FileCheck → Audit
  - Settings → Settings
- Active route highlighted with indigo accent
- Grouped with subtle dividers (overview / operations / admin)
- Warlock logo at top (icon when collapsed, logo + name when expanded)

- [ ] **Step 2: Build the Topbar component**

Fixed top bar:
- Breadcrumb trail (from React Router location — slash-separated, monospace-styled)
- Cmd+K search trigger (just the button for now — search comes later)
- User avatar + dropdown (email, role, logout)

- [ ] **Step 3: Build the AppShell component**

Layout wrapper:
- Sidebar (left)
- Main content area (right, with Topbar at top)
- Content area scrolls independently
- `<Outlet />` for React Router nested routes

- [ ] **Step 4: Wire up routing in App.tsx**

```typescript
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

// Routes:
// /login → Login page (no shell)
// / → Dashboard (inside shell)
// /pipeline → Pipeline (inside shell)
// /pipeline/:provider → Provider detail
// /pipeline/:provider/:eventType → Event type findings
// /pipeline/:provider/:eventType/:findingId → Finding detail (breadcrumb under Pipeline)
// /compliance → Compliance overview
// /compliance/:frameworkId → Framework detail
// /compliance/:frameworkId/:controlId → Control detail
// /findings → Findings table
// /findings/:findingId → Finding detail
// /remediation → POA&M / compensating / risk-accept tabs
// /remediation/:poamId → POA&M detail
// /incidents → Incidents list
// /incidents/:incidentId → Incident detail
// /risk → Risk overview
// /audit → Audit overview
// /settings → Settings tabs
```

Each route renders a placeholder page component (just `<div>Page name</div>`) for now.

Protected routes redirect to `/login` if not authenticated.

- [ ] **Step 5: Verify the shell renders correctly**

1. Login at http://localhost:5173/login
2. Should redirect to `/` and show: sidebar (collapsed icon rail) + topbar with breadcrumbs + empty content area
3. Hover sidebar — should expand to show labels
4. Click sidebar items — should navigate to routes, breadcrumbs update
5. Click user avatar — should show dropdown with email and logout

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/layout/ frontend/src/App.tsx frontend/src/pages/
git commit -m "feat(frontend): app shell with collapsible icon-rail sidebar, topbar, routing"
```

---

## Task 5: Shared components

**Files:**
- Create: `frontend/src/components/shared/StatusBadge.tsx`
- Create: `frontend/src/components/shared/SeverityBadge.tsx`
- Create: `frontend/src/components/shared/CodeBlock.tsx`
- Create: `frontend/src/components/shared/KPICard.tsx`
- Create: `frontend/src/components/shared/DataTable.tsx`
- Create: `frontend/src/components/shared/EmptyState.tsx`
- Create: `frontend/src/components/shared/LoadingState.tsx`

- [ ] **Step 1: Build StatusBadge**

Renders compliance status as a colored badge:
- `compliant` → green bg, green text
- `non_compliant` → red bg, red text
- `partial` → amber bg, amber text
- `not_assessed` → zinc bg, muted text
- `not_applicable` → dim zinc

Uses `bg-{color}-500/10 text-{color}-400` pattern.

- [ ] **Step 2: Build SeverityBadge**

Renders severity as a colored badge:
- `critical` → red
- `high` → orange
- `medium` → amber
- `low` → blue
- `info` → zinc

- [ ] **Step 3: Build CodeBlock**

Renders code with:
- Dark zinc-950 background, zinc-800 border
- Geist Mono font
- Copy button (top-right)
- Optional language label
- Optional syntax highlighting for terraform/bash/json (use simple regex-based highlighting, not a full parser)

- [ ] **Step 4: Build KPICard**

Dashboard metric card:
- Title (muted, uppercase, small)
- Value (large, semibold)
- Subtitle/trend indicator (colored, small)
- Click handler (navigates to detail)

- [ ] **Step 5: Build DataTable**

Wrapper around shadcn Table with:
- Sortable columns (click header to sort)
- Optional filters bar
- Pagination (page size selector + prev/next)
- Loading state (skeleton rows)
- Empty state
- Row click handler (navigates to detail)

- [ ] **Step 6: Build EmptyState and LoadingState**

EmptyState: icon + message + optional action button.
LoadingState: skeleton with animated pulse matching the layout of the target component.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/shared/
git commit -m "feat(frontend): shared components — StatusBadge, SeverityBadge, CodeBlock, KPICard, DataTable"
```

---

## Task 6: TanStack Query setup + API endpoint hooks

**Files:**
- Create: `frontend/src/api/endpoints.ts`
- Create: `frontend/src/hooks/useApi.ts`
- Modify: `frontend/src/main.tsx`

- [ ] **Step 1: Add QueryClientProvider to main.tsx**

Wrap the app in `QueryClientProvider` with sensible defaults (staleTime: 30s, retry: 1).

- [ ] **Step 2: Create typed API endpoint functions**

Write `frontend/src/api/endpoints.ts` — typed functions for every API call the frontend needs:

```typescript
import { api } from "./client";

// Dashboard
export const getDashboardSummary = () => api<DashboardSummary>("/dashboard/summary");
export const getCoverage = () => api<CoverageData>("/results/coverage");
export const getPostureHistory = (framework: string) =>
  api<PostureHistory>(`/posture/history?framework=${framework}`);
export const getCadence = () => api<CadenceData>("/cadence");
export const getDrift = () => api<DriftEvent[]>("/drift");

// Pipeline
export const getConnectors = () => api<Connector[]>("/connectors");
export const getConnectorStatus = (provider: string) =>
  api<ConnectorStatus>(`/connectors/${provider}/status`);
export const getPipelineStatus = () => api<PipelineStatus>("/pipeline/status");

// Compliance
export const getFrameworks = () => api<Framework[]>("/frameworks");
export const getFrameworkControls = (frameworkId: string) =>
  api<Control[]>(`/frameworks/${frameworkId}/controls`);
export const getControlDetail = (controlId: string) =>
  api<ControlDetail>(`/controls/${controlId}`);
export const getResults = (params?: Record<string, string>) => {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return api<ResultsPage>(`/results${qs}`);
};

// Findings
export const getFindings = (params?: Record<string, string>) => {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return api<FindingsPage>(`/findings${qs}`);
};
export const getFindingDetail = (id: string) =>
  api<FindingDetail>(`/findings/${id}`);

// ... (continue for all endpoints referenced in the spec)
```

- [ ] **Step 3: Create useApi hooks**

Write `frontend/src/hooks/useApi.ts` — TanStack Query wrappers:

```typescript
import { useQuery } from "@tanstack/react-query";
import * as endpoints from "../api/endpoints";

export const useDashboardSummary = () =>
  useQuery({ queryKey: ["dashboard-summary"], queryFn: endpoints.getDashboardSummary });

export const useCoverage = () =>
  useQuery({ queryKey: ["coverage"], queryFn: endpoints.getCoverage });

// ... (continue for all endpoints)
```

- [ ] **Step 4: Create TypeScript types for API responses**

Write `frontend/src/api/types.ts` — types for every API response shape. Check the actual FastAPI response models by reading `warlock/api/routers/*.py` Pydantic response models.

Key types:
- `DashboardSummary`, `CoverageData`, `PostureHistory`
- `Connector`, `ConnectorStatus`, `PipelineStatus`
- `Framework`, `Control`, `ControlDetail`, `ControlResult`
- `Finding`, `FindingDetail`
- `POAM`, `CompensatingControl`, `RiskAcceptance`
- `Issue` (incidents), `Alert`, `Remediation`
- `Vendor`, `Attestation`, `AuditEngagement`
- `User`, `AIStatus`

- [ ] **Step 5: Verify a query works end-to-end**

Add a temporary test to the Dashboard page stub:

```typescript
const { data, isLoading, error } = useDashboardSummary();
if (isLoading) return <div>Loading...</div>;
if (error) return <div>Error: {error.message}</div>;
return <pre>{JSON.stringify(data, null, 2)}</pre>;
```

Should show the actual dashboard summary JSON from the API.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api/ frontend/src/hooks/ frontend/src/main.tsx
git commit -m "feat(frontend): TanStack Query setup, typed API endpoints, useApi hooks"
```

---

## Task 7: Add frontend Make targets

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add frontend Make targets**

Add to Makefile:
```makefile
frontend-install: ## Install frontend dependencies
	cd frontend && npm install

frontend-dev: ## Start frontend dev server (proxy to API on :8000)
	cd frontend && npm run dev

frontend-build: ## Build frontend for production
	cd frontend && npm run build
```

- [ ] **Step 2: Commit**

```bash
git add Makefile
git commit -m "chore: add frontend Make targets"
```

---

## Verification

After all tasks complete:

- [ ] **Start the full stack:**
```bash
# Terminal 1: Backend
make demo

# Terminal 2: Frontend
cd frontend && npm run dev
```

- [ ] **Verify:**
1. http://localhost:5173/login shows login page with pre-filled credentials
2. Click "Sign In" → redirects to dashboard
3. Sidebar shows 9 sections with icons, collapses/expands on hover
4. Breadcrumbs update when navigating between sections
5. Dashboard page shows raw JSON from the API (temporary — replaced in Plan 2)
6. Clicking sidebar items navigates to placeholder pages
7. User dropdown shows email and role, logout works
8. Refreshing the page after login redirects to login (no refresh token persistence yet — acceptable)

---

## What This Plan Does NOT Build

- No real page content (just stubs) — that's Plans 2-6
- No search functionality (Cmd+K) — deferred
- No notification bell — deferred
- No refresh token persistence — acceptable for demo (re-login after refresh)
