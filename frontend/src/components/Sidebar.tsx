"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/", label: "Dashboard", icon: "📊" },
  { href: "/assets", label: "Assets", icon: "🎯" },
  { href: "/seeds", label: "Seeds", icon: "🌱" },
  { href: "/findings", label: "Findings", icon: "🔍" },
  { href: "/settings", label: "System Status", icon: "⚙️" },
];

export default function Sidebar() {
  const pathname = usePathname();
  
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };
  
  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 bg-sidebar border-r border-border">
      <div className="flex h-full flex-col">
        {/* Logo/Brand */}
        <div className="flex h-16 items-center border-b border-sidebar-accent px-6">
          <Link href="/" className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary text-primary-foreground text-xl font-bold">
              🛡️
            </div>
            <div>
              <h1 className="text-lg font-bold text-sidebar-foreground">EASM</h1>
              <p className="text-xs text-sidebar-foreground/60">Attack Surface Management</p>
            </div>
          </Link>
        </div>
        
        {/* Navigation */}
        <nav className="flex-1 space-y-1 px-3 py-4">
          {navItems.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive(item.href)
                  ? "bg-sidebar-accent text-sidebar-foreground"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground"
              }`}
            >
              <span className="text-xl">{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>
        
        {/* Footer */}
        <div className="border-t border-sidebar-accent px-6 py-4">
          <div className="text-xs text-sidebar-foreground/50">
            <div className="flex items-center gap-2 mb-1">
              <div className="h-2 w-2 rounded-full bg-success animate-pulse" />
              <span>System Operational</span>
            </div>
            <div>Version 1.0.0</div>
          </div>
        </div>
      </div>
    </aside>
  );
}

