import { useState } from "react";
import { RecentScan } from "@/lib/api";
import { ThreatBadge } from "@/components/ThreatBadge";
import { ExternalLink, Trash2, ScanLine } from "lucide-react";
import { cn } from "@/lib/utils";
import { getHistory, clearHistory } from "@/lib/scanHistory";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";

export default function RecentScans() {
  const [scans, setScans] = useState<RecentScan[]>(() => getHistory());
  const navigate = useNavigate();

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <Loader2 className="w-8 h-8 text-primary animate-spin" />
    </div>
  );

  return (
    <div className="px-8 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Recent Scans</h1>
        <p className="text-muted-foreground text-sm">Last {scans.length} URLs analyzed by the system</p>
      </div>

      <div className="rounded-xl border border-border bg-gradient-card overflow-hidden">
        <div className="grid grid-cols-[1fr_140px_80px_140px_180px] gap-0 text-xs font-mono text-muted-foreground uppercase tracking-wider border-b border-border">
          {["URL", "Verdict", "Risk", "Category", "Scanned At"].map(h => (
            <div key={h} className="px-5 py-3">{h}</div>
          ))}
        </div>
        <div className="divide-y divide-border">
          {scans.map(scan => (
            <div key={scan.id} className="grid grid-cols-[1fr_140px_80px_140px_180px] gap-0 items-center hover:bg-muted/30 transition-colors">
              <div className="px-5 py-4 flex items-center gap-2 min-w-0">
                <span className="text-sm font-mono text-foreground truncate">{scan.url}</span>
                <a href={scan.url} target="_blank" rel="noopener noreferrer" className="flex-shrink-0">
                  <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-primary transition-colors" />
                </a>
              </div>
              <div className="px-5 py-4">
                <ThreatBadge prediction={scan.prediction as any} size="sm" />
              </div>
              <div className="px-5 py-4">
                <span className={cn(
                  "font-mono text-sm font-bold",
                  scan.risk_score > 60 ? "text-danger" : scan.risk_score > 30 ? "text-warning" : "text-safe"
                )}>
                  {scan.risk_score}
                </span>
              </div>
              <div className="px-5 py-4">
                <span className={cn(
                  "text-xs px-2.5 py-1 rounded-full border font-mono",
                  scan.risk_category === "High Risk" ? "bg-danger/10 text-danger border-danger/20" :
                  scan.risk_category === "Suspicious" ? "bg-warning/10 text-warning border-warning/20" :
                  "bg-safe/10 text-safe border-safe/20"
                )}>
                  {scan.risk_category}
                </span>
              </div>
              <div className="px-5 py-4 text-xs text-muted-foreground font-mono">
                {new Date(scan.scanned_at).toLocaleString()}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
