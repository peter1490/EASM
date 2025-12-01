"use client";

import React, { useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import Button from '@/components/ui/Button';
import Input from '@/components/ui/Input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card';

export default function LoginPage() {
  const apiBase = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';
  const searchParams = useSearchParams();
  const errorParam = searchParams.get('error');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState('');
  const [loading, setLoading] = useState(false);
  const { loginLocal } = useAuth();
  const router = useRouter();

  const handleGoogleLogin = () => {
    window.location.href = `${apiBase}/api/auth/google/login`;
  };

  const handleKeycloakLogin = () => {
    window.location.href = `${apiBase}/api/auth/keycloak/login`;
  };

  const handleLocalLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');
    setLoading(true);
    try {
      const success = await loginLocal(email, password);
      if (success) {
        router.push('/');
      } else {
        setLocalError('Invalid email or password');
      }
    } catch {
      setLocalError('An error occurred during login');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background py-12 px-4 sm:px-6 lg:px-8">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-info/5 rounded-full blur-3xl" />
      </div>
      
      <Card className="relative w-full max-w-md animate-scale-in">
        <CardHeader className="text-center space-y-4">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-primary text-primary-foreground text-3xl font-bold shadow-lg">
            🛡️
          </div>
          <div>
            <CardTitle className="text-2xl">Welcome to EASM</CardTitle>
            <CardDescription className="mt-2">
              External Attack Surface Management
            </CardDescription>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {(errorParam || localError) && (
            <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
              {localError || "Authentication failed. Please try again."}
            </div>
          )}

          <form onSubmit={handleLocalLogin} className="space-y-4">
            <Input
              label="Email"
              type="email"
              placeholder="admin@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <Input
              label="Password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <Button 
              type="submit" 
              className="w-full" 
              loading={loading}
              size="lg"
            >
              Sign In
            </Button>
          </form>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="px-2 bg-card text-muted-foreground">Or continue with</span>
            </div>
          </div>

          <div className="space-y-3">
            <button
              onClick={handleGoogleLogin}
              className="w-full flex items-center justify-center gap-3 py-2.5 px-4 border border-border rounded-lg text-sm font-medium bg-card hover:bg-muted transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>
              Sign in with Google
            </button>

            <button
              onClick={handleKeycloakLogin}
              className="w-full flex items-center justify-center gap-3 py-2.5 px-4 border border-border rounded-lg text-sm font-medium bg-card hover:bg-muted transition-colors"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="m7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
              Sign in with SSO (Keycloak)
            </button>
          </div>

        </CardContent>
      </Card>
    </div>
  );
}
