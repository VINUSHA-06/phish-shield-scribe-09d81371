import { useEffect, useState } from "react";
import { getCampaignAlerts, CampaignAlert } from "@/lib/api";
import { Loader2, AlertTriangle, Globe, ExternalLink } from "lucide-react";

export default function CampaignAlerts() {
  const [alerts, setAlerts] = useState<CampaignAlert[]>([]);
  const [loading, setLoading] = useState(true);

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
          URLs clustered by shared infrastructure patterns — potential coordinated phishing campaigns
        </p>
      </div>

      <div className="rounded-xl border border-warning/20 bg-warning/5 p-4 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0 mt-0.5" />
        <div className="text-sm text-foreground">
          <strong className="text-warning">How campaign detection works:</strong> URLs sharing the same IP address, registrar, or structural similarity score &gt; 80% are clustered using unsupervised ML. This mimics real-world SOC threat hunting.
        </div>
      </div>

      <div className="space-y-4">
        {alerts.map(alert => (
          <div key={alert.id} className="rounded-xl border border-danger/30 bg-gradient-card overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-danger/20 flex items-center justify-center">
                  <AlertTriangle className="w-4 h-4 text-danger" />
                </div>
                <div>
                  <span className="text-sm font-semibold text-foreground">Campaign ID: </span>
                  <span className="text-sm font-mono text-danger">{alert.campaign_id}</span>
                </div>
                {alert.target_brand && (
                  <span className="text-xs bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 rounded font-mono">
                    Targeting: {alert.target_brand}
                  </span>
                )}
              </div>
              <div className="text-right text-xs text-muted-foreground">
                <div className="font-mono">Similarity: <span className="text-danger">{(alert.similarity_score * 100).toFixed(0)}%</span></div>
                <div>{new Date(alert.detected_at).toLocaleDateString()}</div>
              </div>
            </div>

            <div className="p-6 grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-3">
                <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Clustered URLs ({alert.urls.length})</h4>
                <div className="space-y-2">
                  {alert.urls.map((url, i) => (
                    <div key={i} className="flex items-center gap-2 bg-background rounded-lg px-3 py-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-danger flex-shrink-0" />
                      <span className="text-xs font-mono text-foreground truncate flex-1">{url}</span>
                      <a href={url} target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-primary transition-colors flex-shrink-0" />
                      </a>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <h4 className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Shared Infrastructure</h4>
                <div className="space-y-2.5">
                  {[
                    { label: "Common IP", value: alert.common_ip, icon: Globe },
                    { label: "Common Registrar", value: alert.common_registrar },
                    { label: "Cluster Similarity", value: `${(alert.similarity_score * 100).toFixed(0)}%` },
                    { label: "URLs in Cluster", value: alert.urls.length.toString() },
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{item.label}</span>
                      <span className="font-mono text-foreground">{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
