"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import { getApiBase } from "@/app/api";
import { Button } from "@/components/kit/Button";
import { Input, Label } from "@/components/kit/Field";
import { Icon } from "@/components/kit/Icon";
import { ErrorState } from "@/components/kit/States";
import { SurfaceConstellation } from "@/components/shell/SurfaceConstellation";

function LoginForm() {
  const { loginLocal } = useAuth();
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(params.get("error"));

  const apiBase = getApiBase();

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const ok = await loginLocal(email, password);
      if (ok) router.push("/");
      else setError("That email and password did not match an account.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-paper">
      <div className="w-[600px] shrink-0 flex flex-col px-16 py-11 max-lg:w-full">
        <div className="flex items-center gap-2.5 text-accent">
          <Icon name="shieldCheck" size={21} />
          <span className="text-[15px] font-semibold tracking-[-0.02em] text-ink">EASM</span>
        </div>

        <div className="flex-1 flex flex-col justify-center max-w-[376px] w-full">
          <h1 className="text-[28px] font-semibold tracking-[-0.03em] leading-tight">Sign in</h1>
          <p className="text-[13px] text-ink-2 mt-2">Use the account your administrator created for you.</p>

          {error && <ErrorState error={error} className="mt-5" />}

          <form onSubmit={submit} className="flex flex-col gap-3.5 mt-6">
            <div>
              <Label>Email</Label>
              <Input
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@acme.com"
                className="h-[38px]"
              />
            </div>
            {/*
              The reveal toggle is laid out beside the label but comes after the
              field in the DOM, so tabbing out of the email lands on the password
              box rather than on "Show". A grid puts it back on the label line
              without changing the focus order.
            */}
            <div className="grid grid-cols-[1fr_auto] items-center">
              <span className="lbl mb-1.5">Password</span>
              <Input
                type={reveal ? "text" : "password"}
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="h-[38px] row-start-2 col-span-2"
              />
              <button
                type="button"
                onClick={() => setReveal((v) => !v)}
                className="row-start-1 col-start-2 mb-1.5 text-[11px] font-medium text-accent hover:text-accent-ink"
              >
                {reveal ? "Hide" : "Show"}
              </button>
            </div>
            <Button type="submit" variant="primary" size="lg" loading={busy} className="justify-center mt-1">
              Sign in
            </Button>
          </form>

          <div className="flex items-center gap-2.5 mt-6">
            <span className="flex-1 h-px bg-rule" />
            <span className="text-[11px] text-ink-3">or</span>
            <span className="flex-1 h-px bg-rule" />
          </div>

          <div className="flex flex-col gap-2 mt-4">
            <Button
              size="lg"
              className="justify-center"
              onClick={() => {
                window.location.href = `${apiBase}/api/auth/google/login`;
              }}
            >
              <Icon name="key" size={15} />
              Continue with Google
            </Button>
            <Button
              size="lg"
              className="justify-center"
              onClick={() => {
                window.location.href = `${apiBase}/api/auth/keycloak/login`;
              }}
            >
              <Icon name="key" size={15} />
              Continue with Keycloak
            </Button>
          </div>
        </div>

        <p className="text-[11.5px] text-ink-3">
          Trouble signing in? Your global administrator can reset the account from Settings → Members.
        </p>
      </div>

      <div className="flex-1 relative overflow-hidden bg-ink flex flex-col justify-end p-13 max-lg:hidden">
        <SurfaceConstellation />
        <div className="relative max-w-[520px]">
          <div className="text-[26px] font-semibold tracking-[-0.03em] leading-tight text-paper">
            Everything of yours that faces the internet — found, scored and watched.
          </div>
          <p className="text-[13px] leading-relaxed text-ink-3 mt-3.5">
            Discovery walks out from your seeds. Each asset it reaches gets fingerprinted, scanned and scored, so the
            surface you are defending is the one that actually exists.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
