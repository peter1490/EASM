"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/context/AuthContext";

const navItems = [
  { href: "/", label: "Dashboard", icon: "📊", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/assets", label: "Assets", icon: "🎯", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/discovery", label: "Discovery", icon: "🔄", roles: ["admin", "operator"] },
  { href: "/security", label: "Security", icon: "🛡️", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/risk", label: "Risk", icon: "⚠️", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/search", label: "Search", icon: "🔎", roles: ["admin", "operator", "analyst", "viewer"] },
  { href: "/settings", label: "Settings", icon: "⚙️", roles: ["admin", "operator", "analyst", "viewer"] },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user, logout, companies, companyId, setCompanyId } = useAuth();
  
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  // Filter items based on user roles
  const filteredNavItems = navItems.filter(item => {
    if (!user) return false;
    return item.roles.some(role => user.roles.includes(role));
  });
  
  return (
    <aside className="fixed left-0 top-0 z-40 h-screen w-64 bg-sidebar border-r border-sidebar-border">
      <div className="flex h-full flex-col">
        {/* Logo/Brand */}
        <div className="flex h-16 items-center border-b border-sidebar-border px-5">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-info text-primary-foreground text-lg font-bold shadow-lg">
                🛡️
              </div>
              <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 bg-success rounded-full border-2 border-sidebar animate-pulse" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-sidebar-foreground tracking-tight">EASM</h1>
              <p className="text-[10px] text-sidebar-foreground/50 font-mono uppercase tracking-widest">Attack Surface</p>
            </div>
          </Link>
        </div>

        {/* Company Switcher */}
        {companies.length > 0 && (
          <div className="border-b border-sidebar-border px-5 py-4">
            <div className="text-[10px] font-semibold text-sidebar-foreground/40 uppercase tracking-widest mb-2">
              Company
            </div>
            <select
              className="w-full rounded-lg border border-sidebar-border bg-sidebar px-3 py-2 text-sm text-sidebar-foreground outline-none transition focus:border-primary"
              value={companyId || ""}
              onChange={(event) => setCompanyId(event.target.value)}
            >
              {companies.map((company) => (
                <option key={company.id} value={company.id}>
                  {company.name}
                </option>
              ))}
            </select>
          </div>
        )}
        
        {/* Navigation */}
        <nav className="flex-1 space-y-1 px-3 py-5 overflow-y-auto">
          <div className="text-[10px] font-semibold text-sidebar-foreground/40 uppercase tracking-widest px-3 mb-3">
            Navigation
          </div>
          {filteredNavItems.map((item, index) => (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200 ${
                isActive(item.href)
                  ? "bg-gradient-to-r from-primary/20 to-primary/10 text-sidebar-foreground border-l-2 border-primary shadow-sm"
                  : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
              }`}
              style={{ animationDelay: `${index * 50}ms` }}
            >
              <span className={`text-lg transition-transform duration-200 ${isActive(item.href) ? "scale-110" : ""}`}>
                {item.icon}
              </span>
              <span>{item.label}</span>
              {isActive(item.href) && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              )}
            </Link>
          ))}
        </nav>
        
        {/* User info & Logout */}
        {user && (
          <div className="border-t border-sidebar-border px-4 py-4">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-9 w-9 rounded-full bg-gradient-to-br from-primary/30 to-info/30 flex items-center justify-center text-primary text-sm font-semibold ring-2 ring-primary/20">
                {user.email?.[0]?.toUpperCase() || "U"}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-sidebar-foreground truncate">
                  {user.email?.split("@")[0] || "User"}
                </div>
                <div className="flex items-center gap-1 mt-0.5">
                  {user.roles.slice(0, 2).map((role) => (
                    <span 
                      key={role}
                      className="text-[10px] px-1.5 py-0.5 bg-sidebar-accent rounded font-medium text-sidebar-foreground/60"
                    >
                      {role}
                    </span>
                  ))}
                  {user.roles.length > 2 && (
                    <span className="text-[10px] text-sidebar-foreground/40">+{user.roles.length - 2}</span>
                  )}
                </div>
              </div>
            </div>
            <button
              onClick={logout}
              className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm text-sidebar-foreground/70 hover:bg-destructive/20 hover:text-destructive transition-all duration-200 group"
            >
              <span className="group-hover:translate-x-0.5 transition-transform">🚪</span>
              <span>Sign Out</span>
            </button>
          </div>
        )}
        
        {/* Footer */}
        <div className="border-t border-sidebar-border px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-success animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
              <span className="text-xs text-sidebar-foreground/50">Operational</span>
            </div>
            <span className="text-[10px] font-mono text-sidebar-foreground/30">v1.0.0</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
