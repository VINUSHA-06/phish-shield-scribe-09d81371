import { useState } from "react";
import { Search, Globe, Loader2, Copy, ShieldAlert, Shield, CheckCircle2, XCircle, TrendingUp, Brain, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { RiskMeter } from "@/components/RiskMeter";
import { ThreatBadge } from "@/components/ThreatBadge";
import { scanUrl, ScanResult } from "@/lib/api";
import { saveToHistory } from "@/lib/scanHistory";
import { cn } from "@/lib/utils";
import heroBg from "@/assets/hero-bg.jpg";

const SAMPLE_URLS = [
  "http://paypa1-verify-account.xyz/login",
  "https://google.com",
  "http://secure-bank-login.ml/verify-account",
  "http://185.220.101.47/defaced",
  "http://amaz0n-secure-update.tk/billing/confirm",
  "https://github.com/torvalds/linux",
];

const SCAN_STEPS = [
  "Extracting 17 URL features",
  "Computing Shannon entropy",
  "Running XGBoost classifier (97.3% accuracy)",
  "Generating SHAP explanations",
  "WHOIS & DNS lookup",
  "SSL certificate validation",
  "Geo-IP threat intelligence",
  "Brand spoof detection (Levenshtein distance)",
  "Phishing campaign correlation",
];

export default function Scanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [showAllDetails, setShowAllDetails] = useState(false);
  const [activeStep, setActiveStep] = useState(0);

  async function handleScan() {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    setActiveStep(0);
    setShowAllDetails(false);

    // Animate steps
    const stepInterval = setInterval(() => {
      setActiveStep(s => Math.min(s + 1, SCAN_STEPS.length - 1));
    }, 220);

    try {
      const res = await scanUrl(url.trim());
      clearInterval(stepInterval);
      setResult(res);
      saveToHistory({
        id: `scan_${Date.now()}`,
        url: res.url,
        prediction: res.prediction,
        risk_score: res.risk_score,
        risk_category: res.risk_category,
        scanned_at: res.scanned_at,
      });
    } catch {
      clearInterval(stepInterval);
      setError("Failed to connect to the analysis server. Ensure Flask backend is running.");
    } finally {
      setLoading(false);
    }
  }

  const categoryRules = result
    ? Array.from(new Set(result.scoring_details.map(d => d.category)))
    : [];

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-border">
        <img src={heroBg} alt="cybersecurity background" className="absolute inset-0 w-full h-full object-cover opacity-10" />
        <div className="relative px-8 py-12">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-mono mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
              XGBoost + SHAP + Domain Intel + Brand Spoof + Campaign Detection
            </div>
            <h1 className="text-4xl font-bold mb-2">
              <span className="text-gradient-primary">URL Threat</span> Intelligence
            </h1>
            <p className="text-muted-foreground text-sm">
              17-feature extraction · Shannon entropy · WHOIS · SSL · Geo-IP · Levenshtein brand spoof · SHAP explainability
            </p>
          </div>
        </div>
      </div>

      <div className="px-8 py-8 space-y-8 max-w-6xl">
        {/* Scanner input */}
        <div>
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleScan()}
                placeholder="Enter URL to analyze — e.g. http://paypa1-verify.tk/login"
                className="pl-10 bg-card border-border font-mono text-sm h-12 focus:border-primary/50 focus:ring-primary/20"
              />
            </div>
            <Button
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="h-12 px-6 bg-primary text-primary-foreground font-semibold hover:bg-primary/90 glow-primary transition-all"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Search className="w-4 h-4 mr-2" />}
              {loading ? "Analyzing…" : "Scan URL"}
            </Button>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <span className="text-xs text-muted-foreground">Try:</span>
            {SAMPLE_URLS.map(s => (
              <button
                key={s}
                onClick={() => setUrl(s)}
                className="text-xs text-primary/70 hover:text-primary font-mono truncate max-w-[200px] transition-colors"
              >
                {s.replace(/https?:\/\//, "").substring(0, 35)}
              </button>
            ))}
          </div>
        </div>

        {/* Scanning animation */}
        {loading && (
          <div className="rounded-xl border border-primary/20 bg-card overflow-hidden">
            <div className="p-6 space-y-3">
              <div className="flex items-center gap-3 mb-4">
                <Loader2 className="w-5 h-5 text-primary animate-spin" />
                <span className="text-primary font-mono text-sm font-semibold">Deep threat analysis in progress…</span>
              </div>
              {SCAN_STEPS.map((step, i) => (
                <div key={step} className={cn("flex items-center gap-3 text-sm transition-all duration-300",
                  i <= activeStep ? "opacity-100" : "opacity-30")}>
                  {i < activeStep ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-safe flex-shrink-0" />
                  ) : i === activeStep ? (
                    <Loader2 className="w-3.5 h-3.5 text-primary animate-spin flex-shrink-0" />
                  ) : (
                    <div className="w-3.5 h-3.5 rounded-full border border-muted-foreground/30 flex-shrink-0" />
                  )}
                  <span className={cn("font-mono text-xs", i < activeStep ? "text-safe" : i === activeStep ? "text-primary" : "text-muted-foreground")}>
                    {step}
                  </span>
                </div>
              ))}
            </div>
            <div className="h-0.5 bg-gradient-to-r from-transparent via-primary to-transparent animate-shimmer bg-[length:200%_100%]" />
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-danger/30 bg-danger/10 p-4 text-danger text-sm font-mono">
            ⚠ {error}
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="space-y-5 animate-fade-in-up">

            {/* ── Row 1: Risk Meter + Verdict ── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className={cn(
                "rounded-xl border p-6 flex flex-col items-center gap-4",
                result.prediction === "phishing" ? "border-danger/40 bg-danger/5 pulse-danger" :
                result.prediction === "defacement" ? "border-warning/40 bg-warning/5" :
                "border-safe/30 bg-safe/5 pulse-safe"
              )}>
                <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Risk Score</h3>
                <RiskMeter score={result.risk_score} category={result.risk_category} size="lg" />
                <div className={cn(
                  "text-xs font-mono px-3 py-1 rounded-full border",
                  result.risk_score > 60 ? "bg-danger/10 text-danger border-danger/20" :
                  result.risk_score > 25 ? "bg-warning/10 text-warning border-warning/20" :
                  "bg-safe/10 text-safe border-safe/20"
                )}>
                  {result.risk_score > 60 ? "🔴 MALICIOUS" : result.risk_score > 25 ? "🟡 SUSPICIOUS" : "🟢 SAFE"}
                </div>
              </div>

              <div className="lg:col-span-2 rounded-xl border border-border bg-gradient-card p-6 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-xs font-mono text-muted-foreground uppercase tracking-widest mb-2">XGBoost Verdict</h3>
                    <ThreatBadge prediction={result.prediction} confidence={result.confidence} size="lg" />
                  </div>
                  <div className="text-right text-xs text-muted-foreground font-mono">
                    <div>{new Date(result.scanned_at).toLocaleString()}</div>
                    <div className="text-primary mt-1">{(result.confidence * 100).toFixed(1)}% confidence</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 bg-background rounded-lg px-3 py-2">
                  <Globe className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                  <span className="text-sm font-mono text-foreground truncate flex-1">{result.url}</span>
                  <button onClick={() => navigator.clipboard.writeText(result.url)}>
                    <Copy className="w-3 h-3 text-muted-foreground hover:text-primary transition-colors" />
                  </button>
                </div>

                <div className="grid grid-cols-4 gap-3">
                  {[
                    { label: "Confidence", value: `${(result.confidence * 100).toFixed(1)}%`, color: "text-primary" },
                    { label: "Domain Age", value: `${result.domain_intel.domain_age_days}d`, color: result.domain_intel.domain_age_days < 180 ? "text-danger" : "text-safe" },
                    { label: "SSL", value: result.domain_intel.ssl_valid ? "✓ Valid" : "✗ None", color: result.domain_intel.ssl_valid ? "text-safe" : "text-danger" },
                    { label: "Abuse Score", value: `${result.domain_intel.abuse_score}`, color: result.domain_intel.abuse_score > 60 ? "text-danger" : result.domain_intel.abuse_score > 30 ? "text-warning" : "text-safe" },
                  ].map(item => (
                    <div key={item.label} className="bg-background rounded-lg p-3 text-center">
                      <div className={cn("text-xl font-bold font-mono", item.color)}>{item.value}</div>
                      <div className="text-xs text-muted-foreground mt-1">{item.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* ── Brand Spoof Alert ── */}
            {result.brand_spoof?.detected && (
              <div className="rounded-xl border border-danger/40 bg-danger/8 p-5 animate-fade-in-up">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-8 h-8 rounded-lg bg-danger/20 flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4 text-danger" />
                  </div>
                  <h3 className="text-danger font-semibold text-sm uppercase tracking-wider">
                    ⚠ Brand Impersonation Detected — {result.brand_spoof.target_brand}
                  </h3>
                  <span className="ml-auto text-xs font-mono bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 rounded-full">
                    {(result.brand_spoof.similarity * 100).toFixed(1)}% similarity
                  </span>
                </div>
                <p className="text-sm text-foreground">
                  This URL is impersonating <strong className="text-danger">{result.brand_spoof.target_brand}</strong> using visual domain similarity.
                  Levenshtein distance analysis detected <strong className="text-danger font-mono">{(result.brand_spoof.similarity * 100).toFixed(1)}%</strong> similarity (threshold: 65%).
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  Brand spoofing is used in credential harvesting attacks where attackers register domains visually similar to legitimate brands to trick users.
                </p>
              </div>
            )}

            {/* ── Row 2: SHAP + Domain Intel ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* SHAP Explainability */}
              <div className="rounded-xl border border-border bg-gradient-card p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Brain className="w-4 h-4 text-primary" />
                  <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">AI Explainability (SHAP)</span>
                  <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full font-mono ml-auto">XAI Layer</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Top features driving the <strong className={cn(
                    result.prediction === "phishing" ? "text-danger" :
                    result.prediction === "defacement" ? "text-warning" : "text-safe"
                  )}>{result.prediction}</strong> classification:
                </p>
                <div className="space-y-3">
                  {result.shap_explanation.map((shap, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={cn("w-2 h-2 rounded-full flex-shrink-0",
                            shap.impact === "positive" ? "bg-danger" : "bg-safe")} />
                          <span className="text-xs text-foreground font-medium">{shap.feature}</span>
                        </div>
                        <span className={cn("text-xs font-mono", shap.impact === "positive" ? "text-danger" : "text-safe")}>
                          {shap.impact === "positive" ? "↑ Risk" : "↓ Risk"}
                        </span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={cn("h-full rounded-full transition-all duration-700", shap.impact === "positive" ? "bg-danger" : "bg-safe")}
                          style={{ width: `${Math.max(15, (5 - i) * 20)}%` }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground pl-4">{shap.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Domain Intelligence */}
              <div className="rounded-xl border border-border bg-gradient-card p-5 space-y-3">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-primary" />
                  <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Domain Intelligence</span>
                </div>
                <div className="space-y-2.5">
                  {[
                    { label: "IP Address", value: result.domain_intel.ip_address, mono: true, warn: false },
                    {
                      label: "Country",
                      value: `${result.domain_intel.country_flag} ${result.domain_intel.country} (risk: ${result.domain_intel.country_risk})`,
                      warn: result.domain_intel.country_risk > 60,
                      mono: false
                    },
                    { label: "Registrar", value: result.domain_intel.registrar, mono: false, warn: false },
                    {
                      label: "Domain Age",
                      value: `${result.domain_intel.domain_age_days} days ${result.domain_intel.domain_age_days < 180 ? "⚠ Too New" : ""}`,
                      mono: true,
                      warn: result.domain_intel.domain_age_days < 180,
                    },
                    { label: "Created", value: result.domain_intel.creation_date, mono: true, warn: false },
                    {
                      label: "SSL Certificate",
                      value: result.domain_intel.ssl_valid ? `✓ Valid until ${result.domain_intel.ssl_expiry}` : "✗ INVALID / MISSING",
                      warn: !result.domain_intel.ssl_valid,
                      mono: false,
                    },
                    {
                      label: "Abuse Score",
                      value: `${result.domain_intel.abuse_score}/100`,
                      warn: result.domain_intel.abuse_score > 60,
                      mono: true,
                    },
                    {
                      label: "Nameservers",
                      value: result.domain_intel.nameservers[0],
                      warn: result.domain_intel.nameservers[0].includes("shady"),
                      mono: true,
                    },
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between text-sm border-b border-border/50 pb-2 last:border-0">
                      <span className="text-muted-foreground text-xs">{item.label}</span>
                      <span className={cn(
                        item.mono ? "font-mono text-xs" : "text-xs",
                        item.warn ? "text-danger" : "text-foreground"
                      )}>
                        {item.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* ── Scoring Breakdown ── */}
            <div className="rounded-xl border border-border bg-gradient-card p-5">
              <button
                onClick={() => setShowAllDetails(!showAllDetails)}
                className="flex items-center justify-between w-full"
              >
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-primary" />
                  <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">
                    Risk Scoring Breakdown — {result.scoring_details.filter(d => d.triggered).length} rules triggered
                  </span>
                </div>
                {showAllDetails ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>

              {showAllDetails && (
                <div className="mt-4 space-y-2">
                  {categoryRules.map(cat => {
                    const catRules = result.scoring_details.filter(d => d.category === cat);
                    const triggered = catRules.filter(d => d.triggered);
                    return (
                      <div key={cat} className="space-y-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono text-primary uppercase">{cat}</span>
                          {triggered.length > 0 && (
                            <span className="text-xs bg-danger/10 text-danger px-1.5 py-0.5 rounded font-mono">
                              +{triggered.reduce((s, d) => s + d.points, 0)} pts
                            </span>
                          )}
                        </div>
                        {catRules.map((rule, i) => (
                          <div key={i} className={cn(
                            "flex items-center justify-between text-xs px-3 py-1.5 rounded",
                            rule.triggered
                              ? rule.points > 0 ? "bg-danger/8 border border-danger/15" : "bg-safe/8 border border-safe/15"
                              : "opacity-40"
                          )}>
                            <div className="flex items-center gap-2">
                              {rule.triggered
                                ? rule.points > 0
                                  ? <XCircle className="w-3 h-3 text-danger flex-shrink-0" />
                                  : <CheckCircle2 className="w-3 h-3 text-safe flex-shrink-0" />
                                : <div className="w-3 h-3 rounded-full border border-muted-foreground/20 flex-shrink-0" />
                              }
                              <span className={rule.triggered ? "text-foreground" : "text-muted-foreground"}>{rule.rule}</span>
                            </div>
                            {rule.triggered && (
                              <span className={cn("font-mono ml-2 flex-shrink-0",
                                rule.points > 0 ? "text-danger" : "text-safe")}>
                                {rule.points > 0 ? `+${rule.points}` : rule.points}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* ── Feature Vector ── */}
            <div className="rounded-xl border border-border bg-gradient-card p-5">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">Extracted Feature Vector (17 features)</span>
                <span className="text-xs text-muted-foreground font-mono">Phase 1 & 2</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-6 gap-3">
                {[
                  { label: "URL Length", value: result.features.url_length, warn: result.features.url_length > 75 },
                  { label: "Dots", value: result.features.dot_count },
                  { label: "Hyphens", value: result.features.hyphen_count, warn: result.features.hyphen_count >= 3 },
                  { label: "Has @", value: result.features.has_at ? "Yes" : "No", warn: result.features.has_at },
                  { label: "Has IP", value: result.features.has_ip ? "Yes" : "No", warn: result.features.has_ip },
                  { label: "HTTPS", value: result.features.https ? "Yes" : "No", ok: result.features.https, warn: !result.features.https },
                  { label: "Digits", value: result.features.digit_count },
                  { label: "Special Chars", value: result.features.special_char_count },
                  { label: "Subdomains", value: result.features.subdomain_count, warn: result.features.subdomain_count >= 3 },
                  { label: "Entropy", value: result.features.entropy.toFixed(2), warn: result.features.entropy > 4.2 },
                  { label: "TLD Risk", value: result.features.tld_risk.toFixed(2), warn: result.features.tld_risk >= 0.65 },
                  { label: "Digit Ratio", value: result.features.digit_ratio.toFixed(2), warn: result.features.digit_ratio > 0.25 },
                  { label: "Path Depth", value: result.features.path_depth, warn: result.features.path_depth > 5 },
                  { label: "Params", value: result.features.query_param_count, warn: result.features.query_param_count > 5 },
                  { label: "URL Encoded", value: result.features.is_encoded ? "Yes" : "No", warn: result.features.is_encoded },
                ].map(f => (
                  <div key={f.label} className="bg-background rounded-lg p-3 text-center">
                    <div className={cn(
                      "text-lg font-bold font-mono",
                      f.warn ? "text-danger" : f.ok ? "text-safe" : "text-primary"
                    )}>
                      {String(f.value)}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">{f.label}</div>
                  </div>
                ))}
              </div>
              {result.features.suspicious_keywords.length > 0 && (
                <div className="mt-4 flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground">Suspicious keywords found:</span>
                  {result.features.suspicious_keywords.map(kw => (
                    <span key={kw} className="text-xs bg-danger/10 text-danger border border-danger/20 px-2 py-0.5 rounded font-mono">{kw}</span>
                  ))}
                </div>
              )}
            </div>

            {/* ── Predicted Future Phishing Domains (Phase 9) ── */}
            {result.predicted_domains.length > 0 && (
              <div className="rounded-xl border border-warning/30 bg-warning/5 p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Shield className="w-4 h-4 text-warning" />
                  <span className="text-xs font-mono text-muted-foreground uppercase tracking-widest">
                    Predictive Phishing Domain Engine (Phase 9)
                  </span>
                  <span className="ml-auto text-xs bg-warning/10 text-warning border border-warning/20 px-2 py-0.5 rounded-full font-mono">
                    Pre-emptive Threat Intel
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mb-4">
                  AI-predicted domains that may be registered by attackers based on pattern analysis of detected campaign. Block these proactively.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {result.predicted_domains.map((d, i) => (
                    <div key={i} className="bg-background rounded-lg p-3 border border-warning/10">
                      <div className="font-mono text-xs text-warning truncate">{d.domain}</div>
                      <div className="flex items-center justify-between mt-1.5">
                        <span className="text-xs text-muted-foreground">{d.pattern}</span>
                        <span className="text-xs font-mono text-danger">{d.risk}% risk</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>
        )}
      </div>
    </div>
  );
}
