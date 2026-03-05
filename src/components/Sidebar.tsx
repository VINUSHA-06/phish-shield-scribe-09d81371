import { NavLink } from "react-router-dom";
import { Shield, LayoutDashboard, Clock, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

const links = [
  { to: "/", icon: Shield, label: "URL Scanner" },
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/recent", icon: Clock, label: "Recent Scans" },
  { to: "/campaigns", icon: AlertTriangle, label: "Campaign Alerts" },
];

export function Sidebar() {
  return (
    <aside className="fixed left-0 top-0 h-full w-64 flex flex-col border-r border-border bg-sidebar z-50">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-border">
        <div className="relative">
          <div className="w-10 h-10 rounded-xl bg-primary/20 border border-primary/40 flex items-center justify-center glow-primary">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <span className="absolute -top-1 -right-1 w-3 h-3 bg-safe rounded-full border-2 border-sidebar animate-pulse" />
        </div>
        <div>
          <h1 className="font-bold text-foreground text-sm leading-tight">ThreatIQ</h1>
          <p className="text-muted-foreground text-xs">AI Threat Intelligence</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
                isActive
                  ? "bg-primary/15 text-primary border border-primary/20 glow-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Status indicator */}
      <div className="px-4 py-4 border-t border-border">
        <div className="rounded-lg bg-muted p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">ML Model</span>
            <span className="text-safe font-mono">XGBoost v2.1</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Accuracy</span>
            <span className="text-primary font-mono">97.3%</span>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="w-2 h-2 rounded-full bg-safe animate-pulse" />
            <span className="text-safe">System Online</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
