"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { DiscoveryProvider } from "@/hooks/useDiscovery";
import { TopBar } from "./TopBar";
import { CommandPalette } from "./CommandPalette";
import { LoadingBlock } from "@/components/kit/States";
import { cn } from "@/lib/cn";

/**
 * How long the shell will hold a switched-to page hidden while it loads before
 * revealing it anyway. Past this, a spinner is better than a blank panel.
 */
const REVEAL_CAP_MS = 600;

type SwitchPhase = "idle" | "leaving" | "entering";

function Shell({ children }: { children: React.ReactNode }) {
  const { user, loading, companyEpoch, companySwitching } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [phase, setPhase] = useState<SwitchPhase>("idle");
  const mainRef = useRef<HTMLElement | null>(null);
  const isLogin = pathname === "/login";

  // Not derived from `companySwitching`: the fade has to stay on after the
  // switch clears it, until the effect below reveals the remounted page.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (companySwitching) setPhase("leaving");
  }, [companySwitching]);

  /**
   * The swap lands on a node that is still faded out, so nothing has been shown
   * yet. Reveal it once the routed page has something real to paint -- or once
   * the cap runs out, whichever comes first. Waiting is what turns the old
   * blink of a loading spinner into one continuous dip.
   */
  useEffect(() => {
    if (companyEpoch === 0) return;
    const main = mainRef.current;
    let settled = false;
    const reveal = () => {
      if (settled) return;
      settled = true;
      setPhase("entering");
    };

    const stillLoading = () => Boolean(main?.querySelector("[data-page-loading]"));
    if (!stillLoading()) {
      reveal();
      return;
    }

    const observer = new MutationObserver(() => {
      if (!stillLoading()) reveal();
    });
    if (main) observer.observe(main, { childList: true, subtree: true });
    const cap = setTimeout(reveal, REVEAL_CAP_MS);

    return () => {
      observer.disconnect();
      clearTimeout(cap);
    };
  }, [companyEpoch]);

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
      {/* Keyed on the company epoch: switching company remounts the routed page
          so every load effect re-runs against the new tenant. That replaces the
          full `window.location.reload()` the switcher used to do, which tore
          down the whole shell and briefly painted the previous company's data
          under the new company's name.

          The classes are the halves of one dip. `company-leaving` fades this
          node out and stays on through the swap, so the replacement mounts
          already hidden and its loading state is never seen; `animate-company-in`
          then fades the finished page back in. It is a keyframe rather than a
          transition because the swap mounts a new node, and transitions do not
          carry across one. */}
      <main
        key={companyEpoch}
        ref={mainRef}
        className={cn(
          "relative flex-1 min-h-0 overflow-hidden",
          phase === "leaving" && "company-leaving",
          phase === "entering" && "animate-company-in",
        )}
      >
        {children}
      </main>
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
