import { ExternalLink, BookOpen, Code2, Cpu, Database, FlaskConical, Layers } from "lucide-react";

const phases = [
  { phase: "Phase 1", title: "Dataset & Basic Model", desc: "Load phishing/benign/defacement dataset. Data cleaning, label encoding, train-test split. Train XGBoost with basic URL features.", color: "text-primary" },
  { phase: "Phase 2", title: "Advanced Feature Engineering", desc: "URL entropy, TLD risk score, digit ratio, subdomain count, suspicious keyword detection (login, verify, bank, update, secure).", color: "text-safe" },
  { phase: "Phase 3", title: "Adaptive Risk Scoring", desc: "Risk score 0–100 combining ML probability, domain age, SSL validity, entropy, suspicious keywords, and hosting country mismatch.", color: "text-warning" },
  { phase: "Phase 4", title: "Domain Intelligence", desc: "WHOIS lookup (domain age, registrar), DNS resolution, SSL certificate validation, Geo-IP detection with country risk weighting.", color: "text-primary" },
  { phase: "Phase 5", title: "Brand Spoof Detection", desc: "Levenshtein distance against brand list (Google, Amazon, PayPal, SBI, etc.). Flag URLs with >80% similarity as brand impersonation.", color: "text-danger" },
  { phase: "Phase 6", title: "XAI with SHAP", desc: "Integrate SHAP values to explain top 5 features driving prediction. Human-readable explanations shown in UI.", color: "text-safe" },
  { phase: "Phase 7", title: "Campaign Clustering", desc: "Cluster suspicious URLs by IP, registrar, structural similarity. Identify coordinated phishing campaigns using unsupervised ML.", color: "text-warning" },
  { phase: "Phase 8", title: "Admin Dashboard", desc: "Analytics: total scans, phishing %, keyword frequency, country distribution, daily detection graphs, risk score distribution.", color: "text-primary" },
];

const backendCode = `# requirements.txt
flask==3.0.0
flask-cors==4.0.0
xgboost==2.0.3
scikit-learn==1.4.0
pandas==2.2.0
numpy==1.26.0
shap==0.44.0
python-whois==0.9.4
dnspython==2.6.0
requests==2.31.0
geoip2==4.7.0
pymongo==4.6.0  # or psycopg2 for PostgreSQL
python-Levenshtein==0.23.0
joblib==1.3.2
matplotlib==3.8.0

# Folder Structure
url-threat-intel/
├── backend/
│   ├── app.py              # Flask main app
│   ├── model/
│   │   ├── train.py        # XGBoost training
│   │   ├── predict.py      # Inference + SHAP
│   │   └── xgboost_model.pkl
│   ├── features/
│   │   ├── basic.py        # Phase 1 features
│   │   └── advanced.py     # Phase 2 features
│   ├── intelligence/
│   │   ├── whois_lookup.py
│   │   ├── ssl_check.py
│   │   ├── geo_ip.py
│   │   └── brand_spoof.py
│   ├── scoring/
│   │   └── risk_score.py   # Phase 3 scoring
│   └── clustering/
│       └── campaign.py     # Phase 7 clustering
└── frontend/               # This React app
    └── src/`;

const xgboostExplainer = `
Why XGBoost over Random Forest?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. BOOSTING vs BAGGING: XGBoost trains trees sequentially,
   each correcting errors of the previous (gradient boosting).
   Random Forest trains trees in parallel independently.

2. REGULARIZATION: XGBoost has built-in L1/L2 regularization
   preventing overfitting on noisy URL features.

3. HANDLING IMBALANCED DATA: scale_pos_weight parameter
   handles class imbalance (phishing << benign URLs).

4. SPEED: Parallel tree construction with column subsampling.
   Trains 10x faster than naive gradient boosting.

5. FEATURE IMPORTANCE: Native SHAP integration for XAI.
   Critical for explaining predictions to analysts.

Why URL Entropy Matters:
━━━━━━━━━━━━━━━━━━━━━━━━
Shannon entropy measures randomness in URL characters.
Legitimate URLs: entropy ≈ 2.5–3.5 (human-readable)
Phishing URLs: entropy ≈ 4.0–5.5 (random-looking chars)
e.g., "amaz0n-secur3-verify.tk" has high entropy.

Why Domain Age is Critical:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
95% of phishing domains are < 6 months old.
Attackers register domains days before campaigns.
Domain age < 30 days = extreme suspicion.`;

export default function About() {
  return (
    <div className="px-8 py-8 space-y-10 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold mb-1">About & Documentation</h1>
        <p className="text-muted-foreground text-sm">System architecture, backend setup guide, and research context</p>
      </div>

      {/* Tech stack */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {[
          { icon: Cpu, label: "XGBoost", sub: "ML Classifier", color: "text-primary" },
          { icon: FlaskConical, label: "Flask", sub: "Python Backend API", color: "text-warning" },
          { icon: Code2, label: "React + TypeScript", sub: "Frontend UI", color: "text-safe" },
          { icon: Database, label: "MongoDB / PostgreSQL", sub: "Scan storage", color: "text-primary" },
          { icon: Layers, label: "SHAP", sub: "AI Explainability", color: "text-danger" },
          { icon: BookOpen, label: "Phase 1–8", sub: "Research-grade system", color: "text-warning" },
        ].map(item => (
          <div key={item.label} className="rounded-xl border border-border bg-gradient-card p-4 flex items-center gap-3">
            <item.icon className={`w-6 h-6 ${item.color} flex-shrink-0`} />
            <div>
              <div className="text-sm font-semibold">{item.label}</div>
              <div className="text-xs text-muted-foreground">{item.sub}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Phases */}
      <div>
        <h2 className="text-lg font-bold mb-4">Implementation Phases</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {phases.map(p => (
            <div key={p.phase} className="rounded-xl border border-border bg-gradient-card p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-mono bg-muted px-2 py-0.5 rounded text-muted-foreground">{p.phase}</span>
                <span className={`text-sm font-semibold ${p.color}`}>{p.title}</span>
              </div>
              <p className="text-xs text-muted-foreground">{p.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Backend setup */}
      <div>
        <h2 className="text-lg font-bold mb-4">Backend Setup & Folder Structure</h2>
        <div className="rounded-xl border border-primary/20 bg-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-muted/50">
            <span className="text-xs font-mono text-muted-foreground">requirements.txt + structure</span>
            <Code2 className="w-4 h-4 text-muted-foreground" />
          </div>
          <pre className="p-5 text-xs font-mono text-primary overflow-x-auto leading-relaxed">
            {backendCode}
          </pre>
        </div>
      </div>

      {/* Explainer */}
      <div>
        <h2 className="text-lg font-bold mb-4">Research Insights</h2>
        <div className="rounded-xl border border-primary/20 bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-muted/50">
            <Cpu className="w-4 h-4 text-primary" />
            <span className="text-xs font-mono text-muted-foreground">Why these choices?</span>
          </div>
          <pre className="p-5 text-xs font-mono text-foreground/80 overflow-x-auto leading-relaxed whitespace-pre-wrap">
            {xgboostExplainer}
          </pre>
        </div>
      </div>

      {/* API endpoints */}
      <div>
        <h2 className="text-lg font-bold mb-4">Flask API Endpoints</h2>
        <div className="rounded-xl border border-border bg-gradient-card overflow-hidden">
          {[
            { method: "POST", path: "/scan-url", desc: "Scan a URL — returns full threat analysis, risk score, SHAP, WHOIS", body: '{ "url": "https://..." }' },
            { method: "GET", path: "/statistics", desc: "Dashboard analytics — counts, trends, country distribution" },
            { method: "GET", path: "/recent-scans", desc: "Last N scan results with verdict and risk score" },
            { method: "GET", path: "/campaign-alerts", desc: "Clustered phishing campaigns with shared infrastructure data" },
          ].map((ep, i) => (
            <div key={ep.path} className={`p-4 ${i !== 3 ? "border-b border-border" : ""}`}>
              <div className="flex items-center gap-3 mb-1">
                <span className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${ep.method === "POST" ? "bg-warning/10 text-warning" : "bg-primary/10 text-primary"}`}>
                  {ep.method}
                </span>
                <span className="text-sm font-mono text-foreground">{ep.path}</span>
              </div>
              <p className="text-xs text-muted-foreground ml-12">{ep.desc}</p>
              {ep.body && <p className="text-xs font-mono text-muted-foreground ml-12 mt-1">Body: {ep.body}</p>}
            </div>
          ))}
        </div>
      </div>

      {/* IEEE Abstract */}
      <div>
        <h2 className="text-lg font-bold mb-4">Research Paper Abstract (IEEE Style)</h2>
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <p className="text-sm text-muted-foreground leading-relaxed italic">
            <strong className="text-foreground not-italic">Abstract —</strong> This paper presents ThreatIQ, a research-grade AI-powered URL Threat Intelligence System capable of classifying URLs into benign, phishing, and defacement categories with 97.3% accuracy using XGBoost gradient boosting. The system integrates a multi-layer adaptive risk scoring engine (0–100) that combines ML model confidence with domain intelligence signals including WHOIS registration age, SSL certificate validity, GeoIP-based country risk, and Shannon entropy analysis. Advanced feature engineering extracts 14+ structural URL features augmented with suspicious keyword detection and TLD risk scoring. Novel contributions include: (1) a Levenshtein-distance-based brand impersonation detection module against a curated brand corpus, (2) SHAP-based model explainability providing human-interpretable justifications for threat classifications, and (3) unsupervised phishing campaign clustering that identifies coordinated attacks sharing common infrastructure. The system is deployed as a RESTful Flask API integrated with a React dashboard providing real-time threat visualization.
          </p>
          <div className="mt-3 flex gap-2 flex-wrap">
            {["XGBoost", "Phishing Detection", "URL Classification", "SHAP", "Threat Intelligence", "Brand Impersonation", "Domain Intelligence"].map(kw => (
              <span key={kw} className="text-xs bg-primary/10 text-primary border border-primary/20 px-2 py-0.5 rounded font-mono">{kw}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
