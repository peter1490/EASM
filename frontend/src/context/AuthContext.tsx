"use client";

import React, { createContext, useContext, useState, useEffect, useRef, ReactNode, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { listCompanies, type CompanyWithRole, getStoredCompanyId, setStoredCompanyId, getApiBase } from '@/app/api';

interface User {
  user_id?: string;
  email?: string;
  roles: string[];
  is_api_key: boolean;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  companies: CompanyWithRole[];
  companyId: string | null;
  /**
   * Bumped every time the active company is swapped for another one. The shell
   * keys the routed page on it, so a switch remounts the page (and refetches)
   * without a full browser reload.
   */
  companyEpoch: number;
  /** True while a switch is mid-dip: the shell fades the routed page out. */
  companySwitching: boolean;
  setCompanyId: (companyId: string) => void;
  refreshCompanies: () => Promise<void>;
  login: () => void; // Redirects to login page
  loginLocal: (email: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

/** Must match the `.company-leaving` transition in globals.css. */
const COMPANY_FADE_OUT_MS = 140;

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [companies, setCompanies] = useState<CompanyWithRole[]>([]);
  const [companyId, setCompanyIdState] = useState<string | null>(null);
  const [companyEpoch, setCompanyEpoch] = useState(0);
  const [companySwitching, setCompanySwitching] = useState(false);
  const appliedCompanyId = useRef<string | null>(null);
  const switchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const router = useRouter();
  const apiBase = getApiBase();

  /**
   * Single place the active company is committed: React state, localStorage
   * (which `apiFetch` reads for the X-Company-ID header) and the remount epoch
   * stay in lockstep, so the switcher label can never render against another
   * company's data.
   */
  const applyCompanyId = useCallback((next: string | null) => {
    setCompanyIdState(next);
    setStoredCompanyId(next);
    // Only a swap between two resolved companies remounts pages. The first
    // resolution after sign-in must not, or every page would mount twice.
    if (appliedCompanyId.current !== null && appliedCompanyId.current !== next) {
      setCompanyEpoch((epoch) => epoch + 1);
    }
    appliedCompanyId.current = next;
  }, []);

  const checkAuth = useCallback(async () => {
    try {
      const storedCompanyId = getStoredCompanyId();
      // We use credentials: 'include' to send cookies
      const res = await fetch(`${apiBase}/api/auth/me`, {
        credentials: 'include',
        headers: storedCompanyId ? { 'X-Company-ID': storedCompanyId } : undefined,
      });

      if (res.ok) {
        const userData = await res.json();
        setUser(userData);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  const loadCompanies = useCallback(async () => {
    if (!user) return;
    try {
      const list = await listCompanies();
      setCompanies(list);

      const stored = getStoredCompanyId();
      const validStored = stored && list.some((company) => company.id === stored);
      const nextCompanyId = validStored ? stored : list[0]?.id || null;

      applyCompanyId(nextCompanyId);
    } catch (error) {
      console.error('Failed to load companies:', error);
      setCompanies([]);
      applyCompanyId(null);
    }
  }, [user, applyCompanyId]);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    if (user) {
      loadCompanies();
      return;
    }

    // Avoid clearing the stored company while the initial auth check is still in flight.
    if (!loading) {
      setCompanies([]);
      applyCompanyId(null);
    }
  }, [user, loadCompanies, loading, applyCompanyId]);

  const login = () => {
    router.push('/login');
  };

  const loginLocal = async (email: string, password: string): Promise<boolean> => {
    try {
      applyCompanyId(null);
      const res = await fetch(`${apiBase}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });

      if (res.ok) {
        const userData = await res.json();
        setUser(userData);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const logout = async () => {
    try {
      await fetch(`${apiBase}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
      setUser(null);
      applyCompanyId(null);
      router.push('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const commitCompanyId = useCallback((nextCompanyId: string) => {
    applyCompanyId(nextCompanyId);

    // Every record id in the URL belongs to the company we are leaving: a
    // detail route would 404 and a list filter would select nothing. Land on
    // the clean list route for wherever we are -- client-side, so the shell,
    // the session and the scroll container survive the switch.
    if (typeof window !== 'undefined') {
      const { pathname, search } = window.location;
      const target = pathname.startsWith('/surface/') ? '/surface' : pathname;
      if (target !== pathname || search) router.replace(target);
    }
  }, [applyCompanyId, router]);

  useEffect(() => () => {
    if (switchTimer.current) clearTimeout(switchTimer.current);
  }, []);

  const setCompanyId = useCallback((nextCompanyId: string) => {
    if (nextCompanyId === appliedCompanyId.current) return;
    if (switchTimer.current) clearTimeout(switchTimer.current);

    if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      commitCompanyId(nextCompanyId);
      return;
    }

    // Fade the page out first, then swap the label and the content together at
    // the trough. Committing at the bottom of the dip is what keeps the
    // switcher from ever naming one company over another's numbers, and it
    // hides the page's own loading state -- around 50ms -- inside the fade
    // rather than letting it flash.
    setCompanySwitching(true);
    switchTimer.current = setTimeout(() => {
      switchTimer.current = null;
      setCompanySwitching(false);
      commitCompanyId(nextCompanyId);
    }, COMPANY_FADE_OUT_MS);
  }, [commitCompanyId]);

  const refreshCompanies = useCallback(async () => {
    await loadCompanies();
  }, [loadCompanies]);

  return (
    <AuthContext.Provider value={{ user, loading, companies, companyId, companyEpoch, companySwitching, setCompanyId, refreshCompanies, login, loginLocal, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
