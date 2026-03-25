/**
 * Auth context provider.
 *
 * Stores authentication state and exposes login/logout to the entire
 * component tree. On mount, checks for an existing token in localStorage
 * to restore sessions across page reloads.
 */

import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  login as apiLogin,
  logout as apiLogout,
  isAuthenticated as checkAuth,
  isMFARequired,
} from "@/api/auth";
import type {
  LoginRequest,
  LoginResult,
  MFARequiredResponse,
  UserResponse,
} from "@/api/types";
import { api } from "@/api/client";

// ---------------------------------------------------------------------------
// Context shape
// ---------------------------------------------------------------------------

export interface AuthContextValue {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<LoginResult>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // On mount: if a token exists, mark as authenticated.
  // We skip a /me fetch for demo simplicity -- the dashboard will load user
  // data as needed. If the token is expired, the first API call will trigger
  // a refresh or redirect to /login.
  useEffect(() => {
    const hasToken = checkAuth();
    setIsAuthenticated(hasToken);
    if (hasToken) {
      // Best-effort fetch of current user profile
      api<UserResponse>("/auth/me")
        .then(setUser)
        .catch(() => {
          // Token might be expired; that is fine, the 401 handler will
          // redirect to /login on the next real API call.
        })
        .finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    const result = await apiLogin(credentials);
    if (!isMFARequired(result)) {
      setIsAuthenticated(true);
      // Extract user info from the token response
      setUser({
        id: result.user_id,
        email: credentials.email,
        name: credentials.email,
        role: result.role,
        is_active: true,
        allowed_frameworks: [],
        allowed_sources: [],
        created_at: "",
        last_login: null,
      });
    }
    return result;
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated,
      isLoading,
      login,
      logout,
    }),
    [user, isAuthenticated, isLoading, login, logout],
  );

  return <AuthContext value={value}>{children}</AuthContext>;
}
