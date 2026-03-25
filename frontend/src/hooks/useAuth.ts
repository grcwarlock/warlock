/**
 * React hook for accessing auth state and actions.
 *
 * Must be used within an <AuthProvider>.
 */

import { useContext } from "react";
import { AuthContext, type AuthContextValue } from "@/contexts/AuthContext";

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return context;
}
