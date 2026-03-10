import { useEffect, useState } from "react";
import { getCampaignAlerts, CampaignAlert } from "@/lib/api";
import { Loader2, AlertTriangle, Globe, ExternalLink, Shield, Clock, ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/utils";

export default function CampaignAlerts() {
  const [alerts, setAlerts] = useState<CampaignAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>("ca_001");

  useEffect(() => {
    getCampaignAlerts().then(a => { setAlerts(a); setLoading(false); });
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <Loader2 className="w-8 h-8 text-primary animate-spin" />
    </div>
  );

  return (
    <div className="px-8 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Phishing Campaign Alerts</h1>
        <p className="text-muted-foreground text-sm">
          Coordinated attack clusters — grouped by shared IP, registrar &amp; structural similarity
        </p>
      </div>

      {/* Info banner */}
      <div className="rounded-xl border border-warning/20 bg-warning/5 p-4 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0 mt-0.5" />
        <div className="text-sm text-foreground">
          <strong className="text-warning">How campaign detection works: </strong>
          URLs sharing the same IP address, registrar, or structural similarity score &gt; 80% are clustered using unsupervised ML.
          The predictive engine then forecasts likely future domains based on naming patterns.
        </div>
      </div>

      {/* Campaign cards */}
      <div className="space-y-4">
        {alerts.map(alert => {
          const isOpen = expanded === alert.id;
          return (
            <div key={alert.id} className="rounded-xl border border-danger/30 bg-gradient-card overflow-hidden">

              {/* Header */}
              <button
                className="w-full flex items-center justify-between px-6 py-4 border-b border-border hover:bg-muted/20 transition-colors"
                onClick={() => setExpanded(isOpen ? null : alert.id)}
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-danger/20 flex items-center justify-center flex-shrink-0">
                    <AlertTriangle className="w-4 h-4 text-danger" />
                  </div>
                  <div className="text-left">
                    <div className="text-sm font-semibold text-foreground">
                      Campaign ID: <span className="font-mono text-danger">{alert.campaign_id}</span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {alert.urls.length} domains · {new Date(alert.detected_at).toLocaleDateString()}
                    </div>
                  </div>
                  {alert.target_brand && (
                    <span className="text-xs bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 rounded font-mono">
                      🎯 {alert.target_brand}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right text-xs">
                    <div className="font-mono text-danger">{(alert.similarity_score * 100).toFixed(0)}% similarity</div>
                  </div>
                  {isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                </div>
              </button>

              {isOpen && (
                <div className="p-6 space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

                    {/* Clustered URLs */}
                    <div className="space-y-3">
                      <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5" />
                        Clustered Domains ({alert.urls.length})
                      </h4>
                      <div className="space-y-2">
                        {alert.urls.map((url, i) => (
                          <div key={i} className="flex items-center gap-2 bg-background rounded-lg px-3 py-2.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-danger flex-shrink-0" />
                            <span className="text-xs font-mono text-foreground truncate flex-1">{url}</span>
                            <a href={url} target="_blank" rel="noopener noreferrer" className="flex-shrink-0">
                              <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-primary transition-colors" />
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Shared Infrastructure */}
                    <div className="space-y-3">
                      <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                        <Globe className="w-3.5 h-3.5" />
                        Shared Infrastructure
                      </h4>
                      <div className="space-y-2.5">
                        {[
                          { label: "Common IP Address", value: alert.common_ip },
                          { label: "Common Registrar", value: alert.common_registrar },
                          { label: "Cluster Similarity Score", value: `${(alert.similarity_score * 100).toFixed(0)}%` },
                          { label: "Total URLs in Cluster", value: `${alert.urls.length} domains` },
                          { label: "Target Brand", value: alert.target_brand || "Unknown" },
                        ].map(item => (
                          <div key={item.label} className="flex items-center justify-between text-sm border-b border-border/40 pb-2 last:border-0">
                            <span className="text-muted-foreground text-xs">{item.label}</span>
                            <span className="font-mono text-xs text-foreground">{item.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Attack Timeline */}
                  <div className="space-y-3">
                    <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5" />
                      Phishing Attack Timeline (Phase 10)
                    </h4>
                    <div className="relative">
                      <div className="absolute left-3 top-0 bottom-0 w-px bg-danger/20" />
                      <div className="space-y-3 pl-8">
                        {alert.timeline.map((event, i) => (
                          <div key={i} className="relative">
                            <div className="absolute -left-5 top-1.5 w-3 h-3 rounded-full border-2 border-danger bg-background" />
                            <div className="bg-background rounded-lg px-4 py-3 border border-border">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-mono text-danger font-semibold">{event.date}</span>
                                <span className="text-xs text-muted-foreground">{event.event}</span>
                              </div>
                              <span className="text-xs font-mono text-foreground">{event.domain}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Predicted Next Domains */}
                  <div className="rounded-xl border border-warning/20 bg-warning/5 p-4">
                    <h4 className="text-xs font-mono text-warning uppercase tracking-wider mb-3 flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5" />
                      AI-Predicted Next Domains (Phase 9 — Pre-emptive Intel)
                    </h4>
                    <p className="text-xs text-muted-foreground mb-3">
                      Block these domains immediately — high probability of future registration based on campaign pattern analysis.
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {alert.predicted_next.map((domain, i) => (
                        <div
                          key={i}
                          className={cn(
                            "text-xs font-mono px-3 py-1.5 rounded-lg border",
                            "bg-warning/8 text-warning border-warning/20"
                          )}
                        >
                          ⚠ {domain}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
