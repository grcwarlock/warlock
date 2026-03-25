/**
 * Auth API functions.
 *
 * Handles login (with MFA support), logout, and token presence checks.
 */

import { api, setTokens, clearTokens, getAccessToken } from "@/api/client";
import type {
  LoginRequest,
  LoginResult,
  LoginResponse,
  MFARequiredResponse,
} from "@/api/types";

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

export function isMFARequired(result: LoginResult): result is MFARequiredResponse {
  return "mfa_required" in result && result.mfa_required === true;
}

// ---------------------------------------------------------------------------
// Auth functions
// ---------------------------------------------------------------------------

/**
 * Authenticate with email and password.
 *
 * On success (no MFA), stores tokens automatically.
 * If MFA is required, returns the MFA challenge without storing tokens.
 */
export async function login(credentials: LoginRequest): Promise<LoginResult> {
  // Login endpoint does not require auth, call fetch directly
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(credentials),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(
      typeof body.detail === "string" ? body.detail : `Login failed (${res.status})`,
    );
  }

  const data = (await res.json()) as LoginResult;

  if (!isMFARequired(data)) {
    const loginData = data as LoginResponse;
    setTokens(loginData.access_token, loginData.refresh_token);
  }

  return data;
}

/**
 * Revoke all tokens for the current user and clear local storage.
 */
export async function logout(): Promise<void> {
  try {
    await api<{ message: string }>("/auth/logout", { method: "POST" });
  } catch {
    // Best-effort server-side logout; always clear client tokens
  } finally {
    clearTokens();
  }
}

/**
 * Check whether an access token exists in local storage.
 *
 * This is a client-side-only check. It does not validate the token
 * against the server.
 */
export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}
