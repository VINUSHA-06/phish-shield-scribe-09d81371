import { useState } from "react";
import { Search, Globe, Loader2, Copy, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RiskMeter } from "@/components/RiskMeter";
import { ThreatBadge } from "@/components/ThreatBadge";
import { scanUrl, ScanResult } from "@/lib/api";
import { saveToHistory } from "@/lib/scanHistory";
import { cn } from "@/lib/utils";
import heroBg from "@/assets/hero-bg.jpg";

const SAMPLE_URLS = [
  "https://paypa1-verify-account.xyz/login",
  "https://google.com",
  "http://secure-bank-login.ml/verify",
];

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");

  async function handleScan() {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await scanUrl(url.trim());
      setResult(res);
    } catch {
      setError("Failed to connect to the analysis server. Ensure Flask backend is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-border">
        <img src={heroBg} alt="cybersecurity background" className="absolute inset-0 w-full h-full object-cover opacity-10" />
        <div className="relative px-8 py-12">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-mono mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              AI-Powered Threat Detection — XGBoost + SHAP + Domain Intelligence
            </div>
            <h1 className="text-4xl font-bold mb-2">
              <span className="text-gradient-primary">URL Threat</span> Intelligence
            </h1>
            <p className="text-muted-foreground">
              Multi-layer analysis: ML classification · Risk scoring · WHOIS · SSL · Brand spoofing detection · XAI explanations
            </p>
          </div>
        </div>
      </div>

      <div className="px-8 py-8 space-y-8">
        {/* Scanner input */}
        <div className="max-w-3xl">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleScan()}
                placeholder="Enter URL to analyze (e.g. https://suspicious-site.tk/login)"
                className="pl-10 bg-card border-border font-mono text-sm h-12 focus:border-primary/50 focus:ring-primary/20"
              />
            </div>
            <Button
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="h-12 px-6 bg-primary text-primary-foreground font-semibold hover:bg-primary/90 glow-primary transition-all"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Search className="w-4 h-4 mr-2" />}
              {loading ? "Analyzing..." : "Scan URL"}
            </Button>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-xs text-muted-foreground">Try:</span>
            {SAMPLE_URLS.map(s => (
              <button
                key={s}
                onClick={() => setUrl(s)}
                className="text-xs text-primary/70 hover:text-primary font-mono truncate max-w-[180px] transition-colors"
              >
                {s.replace(/https?:\/\//, "").substring(0, 30)}…
              </button>
            ))}
          </div>
        </div>

        {/* Scanning animation */}
        {loading && (
          <div className="max-w-3xl rounded-xl border border-primary/20 bg-card overflow-hidden">
            <div className="p-6 space-y-4">
              <div className="flex items-center gap-3">
                <Loader2 className="w-5 h-5 text-primary animate-spin" />
                <span className="text-primary font-mono text-sm">Deep scanning in progress...</span>
              </div>
              {["Extracting URL features", "Running XGBoost classifier", "Calculating risk score", "WHOIS & DNS lookup", "SSL certificate check", "Brand spoof detection", "Generating SHAP explanations"].map((step, i) => (
                <div key={step} className="flex items-center gap-3 text-sm" style={{ animationDelay: `${i * 0.3}s` }}>
                  <Loader2 className="w-3 h-3 text-primary/60 animate-spin flex-shrink-0" />
                  <span className="text-muted-foreground font-mono">{step}</span>
                </div>
              ))}
            </div>
            <div className="h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent animate-shimmer bg-[length:200%_100%]" />
          </div>
        )}

        {error && (
          <div className="max-w-3xl rounded-xl border border-danger/30 bg-danger/10 p-4 text-danger text-sm font-mono">
            ⚠ {error}
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="space-y-6 animate-fade-in-up">
            {/* Top result row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Risk meter card */}
              <div className="rounded-xl border border-glow bg-gradient-card p-6 flex flex-col items-center gap-4">
                <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Risk Score</h3>
                <RiskMeter score={result.risk_score} category={result.risk_category} size="lg" />
              </div>

              {/* Verdict */}
              <div className="lg:col-span-2 rounded-xl border border-border bg-gradient-card p-6 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest mb-2">Verdict</h3>
                    <ThreatBadge prediction={result.prediction} confidence={result.confidence} size="lg" />
                  </div>
                  <div className="text-right text-xs text-muted-foreground font-mono">
                    <div>{new Date(result.scanned_at).toLocaleString()}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2 bg-muted rounded-lg px-3 py-2">
                  <Globe className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                  <span className="text-sm font-mono text-foreground truncate flex-1">{result.url}</span>
                  <button onClick={() => navigator.clipboard.writeText(result.url)}>
                    <Copy className="w-3 h-3 text-muted-foreground hover:text-primary transition-colors" />
                  </button>
                </div>

                {/* Risk breakdown */}
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: "Model Confidence", value: `${(result.confidence * 100).toFixed(1)}%`, color: "text-primary" },
                    { label: "Domain Age", value: `${result.domain_intel.domain_age_days}d`, color: result.domain_intel.domain_age_days < 180 ? "text-danger" : "text-safe" },
                    { label: "SSL Valid", value: result.domain_intel.ssl_valid ? "Yes" : "No", color: result.domain_intel.ssl_valid ? "text-safe" : "text-danger" },
                  ].map(item => (
                    <div key={item.label} className="bg-background rounded-lg p-3 text-center">
                      <div className={cn("text-xl font-bold font-mono", item.color)}>{item.value}</div>
                      <div className="text-xs text-muted-foreground mt-1">{item.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Brand spoof alert */}
            {result.brand_spoof?.detected && (
              <div className="rounded-xl border border-danger/40 bg-danger/10 p-5 animate-fade-in-up">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-danger/20 flex items-center justify-center">
                    <span className="text-danger text-lg">⚠</span>
                  </div>
                  <h3 className="text-danger font-semibold text-sm uppercase tracking-wider">Brand Impersonation Detected</h3>
                </div>
                <p className="text-sm text-foreground">
                  This URL is attempting to impersonate <strong className="text-danger">{result.brand_spoof.target_brand}</strong>.
                  Levenshtein similarity score: <strong className="text-danger font-mono">{(result.brand_spoof.similarity * 100).toFixed(1)}%</strong> (threshold: 80%).
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  Brand spoofing is a common phishing technique where attackers register domains visually similar to legitimate brands.
                </p>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* SHAP Explanation */}
              <div className="rounded-xl border border-border bg-gradient-card p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">AI Explanation (SHAP)</span>
                  <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full font-mono">XAI</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Top factors influencing the <strong className="text-foreground">{result.prediction}</strong> classification:
                </p>
                <div className="space-y-2">
                  {result.shap_explanation.map((shap, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <span className={cn(
                        "text-xs w-2 h-2 rounded-full flex-shrink-0",
                        shap.impact === "positive" ? "bg-danger" : "bg-safe"
                      )} />
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-foreground">{shap.feature}</span>
                          <span className={cn("text-xs font-mono", shap.impact === "positive" ? "text-danger" : "text-safe")}>
                            {shap.impact === "positive" ? "↑ Risk" : "↓ Risk"}
                          </span>
                        </div>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", shap.impact === "positive" ? "bg-danger" : "bg-safe")}
                            style={{ width: `${(5 - i) * 20}%` }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Domain Intelligence */}
              <div className="rounded-xl border border-border bg-gradient-card p-5 space-y-3">
                <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Domain Intelligence</span>
                <div className="space-y-2">
                  {[
                    { label: "IP Address", value: result.domain_intel.ip_address, mono: true },
                    { label: "Country", value: `${result.domain_intel.country} (Risk: ${result.domain_intel.country_risk})`, warn: result.domain_intel.country_risk > 60 },
                    { label: "Registrar", value: result.domain_intel.registrar, mono: false },
                    { label: "Created", value: result.domain_intel.creation_date, mono: true, warn: result.domain_intel.domain_age_days < 180 },
                    { label: "Expires", value: result.domain_intel.expiry_date, mono: true },
                    { label: "SSL Certificate", value: result.domain_intel.ssl_valid ? `Valid until ${result.domain_intel.ssl_expiry}` : "INVALID / MISSING", warn: !result.domain_intel.ssl_valid },
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">{item.label}</span>
                      <span className={cn(
                        item.mono ? "font-mono text-xs" : "",
                        item.warn ? "text-danger" : "text-foreground"
                      )}>
                        {item.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Feature vector */}
            <div className="rounded-xl border border-border bg-gradient-card p-5">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Extracted Feature Vector</span>
                <span className="text-xs text-muted-foreground font-mono">Phase 1 & 2 Features</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
                {[
                  { label: "URL Length", value: result.features.url_length },
                  { label: "Dots", value: result.features.dot_count },
                  { label: "Hyphens", value: result.features.hyphen_count },
                  { label: "Has @", value: result.features.has_at ? "Yes" : "No", warn: result.features.has_at },
                  { label: "Has IP", value: result.features.has_ip ? "Yes" : "No", warn: result.features.has_ip },
                  { label: "HTTPS", value: result.features.https ? "Yes" : "No", ok: result.features.https },
                  { label: "Digits", value: result.features.digit_count },
                  { label: "Special Chars", value: result.features.special_char_count },
                  { label: "Subdomains", value: result.features.subdomain_count },
                  { label: "Entropy", value: result.features.entropy.toFixed(2), warn: result.features.entropy > 3.8 },
                  { label: "TLD Risk", value: result.features.tld_risk.toFixed(2), warn: result.features.tld_risk > 0.5 },
                  { label: "Digit Ratio", value: result.features.digit_ratio.toFixed(2), warn: result.features.digit_ratio > 0.2 },
                ].map(f => (
                  <div key={f.label} className="bg-background rounded-lg p-3 text-center">
                    <div className={cn(
                      "text-lg font-bold font-mono",
                      f.warn ? "text-danger" : f.ok ? "text-safe" : "text-primary"
                    )}>
                      {f.value}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">{f.label}</div>
                  </div>
                ))}
              </div>
              {result.features.suspicious_keywords.length > 0 && (
                <div className="mt-3 flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Suspicious keywords:</span>
                  {result.features.suspicious_keywords.map(kw => (
                    <span key={kw} className="text-xs bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 rounded font-mono">{kw}</span>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
