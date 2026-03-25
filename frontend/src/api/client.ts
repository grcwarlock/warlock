/**
 * Base fetch wrapper with JWT authentication and automatic token refresh.
 *
 * All API calls go through the `api()` function which prepends `/api/v1`,
 * attaches the bearer token, and handles 401 refresh flows transparently.
 */

const TOKEN_STORAGE_KEY = "warlock_access_token";
const REFRESH_STORAGE_KEY = "warlock_refresh_token";

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

export function setTokens(access: string, refresh: string): void {
  localStorage.setItem(TOKEN_STORAGE_KEY, access);
  localStorage.setItem(REFRESH_STORAGE_KEY, refresh);
}

export function clearTokens(): void {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
  localStorage.removeItem(REFRESH_STORAGE_KEY);
}

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_STORAGE_KEY);
}

// ---------------------------------------------------------------------------
// ApiError
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown) {
    const message =
      typeof body === "object" && body !== null && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : `API error ${status}`;
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// ---------------------------------------------------------------------------
// Refresh lock — prevent concurrent refresh attempts
// ---------------------------------------------------------------------------

let refreshPromise: Promise<boolean> | null = null;

async function attemptRefresh(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  try {
    const res = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!res.ok) return false;

    const data = (await res.json()) as {
      access_token: string;
      refresh_token: string;
    };
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

async function refreshOrFail(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = attemptRefresh().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

interface ApiOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const url = `/api/v1${path}`;
  const token = getAccessToken();

  const headers = new Headers(options.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const fetchOptions: RequestInit = {
    ...options,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  };

  let res = await fetch(url, fetchOptions);

  // On 401, attempt a single token refresh and retry the original request
  if (res.status === 401) {
    const refreshed = await refreshOrFail();
    if (refreshed) {
      const retryToken = getAccessToken();
      if (retryToken) {
        headers.set("Authorization", `Bearer ${retryToken}`);
      }
      res = await fetch(url, { ...fetchOptions, headers });
    }

    if (res.status === 401) {
      clearTokens();
      window.location.href = "/login";
      // This throw will never be reached in practice due to redirect,
      // but it satisfies the type system and handles edge cases.
      throw new ApiError(401, { detail: "Session expired" });
    }
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  if (!res.ok) {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = { detail: res.statusText };
    }
    throw new ApiError(res.status, body);
  }

  return (await res.json()) as T;
}
