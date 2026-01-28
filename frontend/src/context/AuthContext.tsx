"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
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
  setCompanyId: (companyId: string) => void;
  refreshCompanies: () => Promise<void>;
  login: () => void; // Redirects to login page
  loginLocal: (email: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [companies, setCompanies] = useState<CompanyWithRole[]>([]);
  const [companyId, setCompanyIdState] = useState<string | null>(null);
  const router = useRouter();
  const apiBase = getApiBase();

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

      setCompanyIdState(nextCompanyId);
      setStoredCompanyId(nextCompanyId);
    } catch (error) {
      console.error('Failed to load companies:', error);
      setCompanies([]);
      setCompanyIdState(null);
    }
  }, [user]);

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
      setCompanyIdState(null);
      setStoredCompanyId(null);
    }
  }, [user, loadCompanies, loading]);

  const login = () => {
    router.push('/login');
  };

  const loginLocal = async (email: string, password: string): Promise<boolean> => {
    try {
      setStoredCompanyId(null);
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
      setStoredCompanyId(null);
      router.push('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const setCompanyId = (nextCompanyId: string) => {
    setCompanyIdState(nextCompanyId);
    setStoredCompanyId(nextCompanyId);

    if (typeof window !== 'undefined') {
      const { pathname } = window.location;
      if (pathname.startsWith('/security/scans/')) {
        window.location.assign('/security');
        return;
      }
      if (pathname.startsWith('/asset/')) {
        window.location.assign('/assets');
        return;
      }
    }

    window.location.reload();
  };

  const refreshCompanies = useCallback(async () => {
    await loadCompanies();
  }, [loadCompanies]);

  return (
    <AuthContext.Provider value={{ user, loading, companies, companyId, setCompanyId, refreshCompanies, login, loginLocal, logout }}>
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
