"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { DiscoveryProvider } from "@/hooks/useDiscovery";
import { TopBar } from "./TopBar";
import { CommandPalette } from "./CommandPalette";
import { LoadingBlock } from "@/components/kit/States";

function Shell({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const isLogin = pathname === "/login";

  useEffect(() => {
    if (!loading && !user && !isLogin) router.push("/login");
  }, [user, loading, isLogin, router]);

  // One global shortcut, registered once, rather than per-page key handlers.
  useEffect(() => {
    if (isLogin) return;
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [isLogin]);

  if (loading) {
    return (
      <div className="h-screen grid place-items-center">
        <LoadingBlock label="Signing you in" />
      </div>
    );
  }

  if (isLogin) return <div className="h-screen overflow-hidden">{children}</div>;
  if (!user) return null; // redirecting

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-paper">
      <TopBar onOpenPalette={() => setPaletteOpen(true)} />
      {/* `relative` makes this the containing block for any absolutely
          positioned descendant, so `overflow-hidden` actually clips it. Without
          it an abspos child resolves against the viewport and can scroll the
          whole document behind the shell. */}
      <main className="relative flex-1 min-h-0 overflow-hidden">{children}</main>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <DiscoveryProvider>
        <Shell>{children}</Shell>
      </DiscoveryProvider>
    </AuthProvider>
  );
}
