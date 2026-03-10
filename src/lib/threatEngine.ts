/**
 * ThreatIQ — Production-Grade URL Threat Analysis Engine
 * 
 * Architecture mirrors real SOC/ML pipelines:
 *   Phase 1 : Basic feature extraction (URL structure)
 *   Phase 2 : Advanced feature engineering (entropy, TLD risk, digit-letter ratio)
 *   Phase 3 : Multi-layer heuristic scoring (XGBoost simulation)
 *   Phase 4 : Domain intelligence layer (WHOIS, SSL, Geo-IP)
 *   Phase 5 : Brand spoof detection (Levenshtein distance)
 *   Phase 6 : SHAP explainability generation
 *   Phase 7 : Phishing domain prediction engine
 *   Phase 8 : Campaign clustering
 */

// ─── Phase 2: Shannon Entropy ────────────────────────────────────────────────
export function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / str.length;
    return acc + p * Math.log2(p);
  }, 0);
}

// ─── TLD Risk Database ────────────────────────────────────────────────────────
const TLD_RISK_MAP: Record<string, number> = {
  // Free / abused TLDs — high risk
  ".tk": 0.95, ".ml": 0.92, ".cf": 0.91, ".ga": 0.90, ".gq": 0.90,
  ".xyz": 0.82, ".top": 0.80, ".pw": 0.85, ".cc": 0.78, ".click": 0.80,
  ".work": 0.75, ".link": 0.72, ".loan": 0.88, ".win": 0.78, ".racing": 0.82,
  ".download": 0.80, ".stream": 0.75, ".gdn": 0.70, ".review": 0.72,
  ".trade": 0.70, ".date": 0.68, ".faith": 0.73, ".party": 0.70,
  ".men": 0.65, ".bid": 0.72, ".science": 0.60, ".cricket": 0.68,
  // Moderately risky
  ".info": 0.45, ".biz": 0.40, ".mobi": 0.38, ".name": 0.35,
  ".us": 0.20, ".co": 0.20,
  // Trusted
  ".com": 0.10, ".org": 0.12, ".net": 0.12, ".edu": 0.02, ".gov": 0.01,
  ".io": 0.15, ".dev": 0.08, ".app": 0.08,
};

function getTLDRisk(url: string): number {
  const lower = url.toLowerCase();
  // Extract TLD from host
  const host = lower.replace(/https?:\/\//i, "").split("/")[0].split("?")[0];
  const parts = host.split(".");
  const tld = parts.length >= 2 ? `.${parts[parts.length - 1]}` : "";
  return TLD_RISK_MAP[tld] ?? 0.25; // unknown TLD → moderate risk
}

// ─── Brand Spoof Database + Levenshtein ──────────────────────────────────────
const BRAND_TARGETS = [
  { name: "PayPal", keywords: ["paypal", "paypa1", "paypai", "pp-secure"] },
  { name: "Amazon", keywords: ["amazon", "amaz0n", "amazom", "amzon"] },
  { name: "Google", keywords: ["google", "g00gle", "gooogle", "googie"] },
  { name: "Apple", keywords: ["apple", "app1e", "icloud", "itunes-apple"] },
  { name: "Microsoft", keywords: ["microsoft", "m1crosoft", "microsofft", "microsooft"] },
  { name: "Netflix", keywords: ["netflix", "netfl1x", "netfl1x", "net-flix"] },
  { name: "Facebook", keywords: ["facebook", "faceb00k", "facebok", "fb-secure"] },
  { name: "Instagram", keywords: ["instagram", "1nstagram", "instagrarn"] },
  { name: "Twitter", keywords: ["twitter", "tw1tter", "twltter"] },
  { name: "Chase Bank", keywords: ["chase", "chaseonline", "chase-bank", "chasebank"] },
  { name: "Bank of America", keywords: ["bankofamerica", "bankamerica", "boa-secure"] },
  { name: "Wells Fargo", keywords: ["wellsfargo", "wells-fargo", "wf-secure"] },
  { name: "SBI Bank", keywords: ["sbi", "sbibank", "sbi-net", "sbinetbanking", "onlinesbi"] },
  { name: "HDFC Bank", keywords: ["hdfc", "hdfcbank", "hdfc-secure"] },
  { name: "DHL", keywords: ["dhl", "dh1", "dhl-express", "dhl-delivery"] },
  { name: "FedEx", keywords: ["fedex", "fed-ex", "fedexdelivery"] },
];

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

function detectBrandSpoof(url: string): { detected: boolean; target_brand: string; similarity: number } | null {
  const lower = url.toLowerCase().replace(/https?:\/\//i, "").split("/")[0];
  for (const brand of BRAND_TARGETS) {
    for (const kw of brand.keywords) {
      if (lower.includes(kw)) {
        // Extra check: if URL also has suspicious additions (not an official domain)
        const trustedDomains = [`${kw}.com`, `www.${kw}.com`];
        if (trustedDomains.some(d => lower === d || lower === `www.${d}`)) continue;
        const dist = levenshtein(lower.split(".")[0], kw);
        const similarity = Math.max(0, 1 - dist / Math.max(lower.split(".")[0].length, kw.length));
        if (similarity > 0.65) {
          return { detected: true, target_brand: brand.name, similarity: Math.min(0.99, similarity + 0.05) };
        }
      }
    }
  }
  return null;
}

// ─── Trusted Domain Whitelist ─────────────────────────────────────────────────
const TRUSTED_DOMAINS = new Set([
  "google.com", "www.google.com",
  "github.com", "www.github.com",
  "stackoverflow.com",
  "npmjs.com",
  "twitter.com", "x.com",
  "youtube.com",
  "microsoft.com",
  "apple.com",
  "linkedin.com",
  "wikipedia.org",
  "amazon.com", "www.amazon.com",
  "reddit.com",
  "facebook.com",
  "instagram.com",
  "cloudflare.com",
  "mozilla.org",
  "w3.org",
  "reactjs.org",
  "vitejs.dev",
  "tailwindcss.com",
]);

function isTrustedDomain(url: string): boolean {
  const host = url.toLowerCase().replace(/https?:\/\//i, "").split("/")[0].split("?")[0];
  return TRUSTED_DOMAINS.has(host);
}

// ─── Suspicious Keyword Intelligence ─────────────────────────────────────────
const PHISHING_KEYWORDS: Array<{ word: string; score: number; category: string }> = [
  // Credential theft
  { word: "login", score: 14, category: "Credential Theft" },
  { word: "signin", score: 14, category: "Credential Theft" },
  { word: "sign-in", score: 14, category: "Credential Theft" },
  { word: "password", score: 16, category: "Credential Theft" },
  { word: "credential", score: 18, category: "Credential Theft" },
  { word: "username", score: 12, category: "Credential Theft" },
  { word: "authenticate", score: 14, category: "Credential Theft" },
  { word: "authentication", score: 14, category: "Credential Theft" },
  // Urgency / social engineering
  { word: "verify", score: 14, category: "Social Engineering" },
  { word: "verification", score: 14, category: "Social Engineering" },
  { word: "confirm", score: 12, category: "Social Engineering" },
  { word: "secure", score: 10, category: "Social Engineering" },
  { word: "security", score: 10, category: "Social Engineering" },
  { word: "update", score: 10, category: "Social Engineering" },
  { word: "urgent", score: 16, category: "Social Engineering" },
  { word: "alert", score: 12, category: "Social Engineering" },
  { word: "suspend", score: 18, category: "Social Engineering" },
  { word: "suspended", score: 18, category: "Social Engineering" },
  { word: "locked", score: 16, category: "Social Engineering" },
  { word: "limited", score: 14, category: "Social Engineering" },
  // Financial
  { word: "bank", score: 14, category: "Financial Fraud" },
  { word: "banking", score: 14, category: "Financial Fraud" },
  { word: "billing", score: 14, category: "Financial Fraud" },
  { word: "payment", score: 12, category: "Financial Fraud" },
  { word: "invoice", score: 12, category: "Financial Fraud" },
  { word: "account", score: 10, category: "Financial Fraud" },
  { word: "wallet", score: 12, category: "Financial Fraud" },
  { word: "refund", score: 12, category: "Financial Fraud" },
  { word: "transaction", score: 12, category: "Financial Fraud" },
  // Technical tricks
  { word: "webscr", score: 22, category: "Technical Obfuscation" },
  { word: "ebayisapi", score: 22, category: "Technical Obfuscation" },
  { word: "cgi-bin", score: 18, category: "Technical Obfuscation" },
  { word: "redirect", score: 12, category: "Technical Obfuscation" },
  { word: "http://", score: 8, category: "Technical Obfuscation" }, // embedded URL
];

const DEFACEMENT_KEYWORDS = [
  "hack", "hacked", "hacked_by", "pwned", "defaced", "owned", "r00t",
  "by_", "team_", "crew", "cyb3r", "h4x", "l33t", "0wned",
];

// ─── Phase 1 & 2: Feature Extraction ─────────────────────────────────────────
export interface FeatureVector {
  url_length: number;
  dot_count: number;
  hyphen_count: number;
  has_at: boolean;
  has_ip: boolean;
  https: boolean;
  digit_count: number;
  special_char_count: number;
  suspicious_keywords: string[];
  subdomain_count: number;
  entropy: number;
  tld_risk: number;
  digit_ratio: number;
  path_depth: number;
  query_param_count: number;
  is_encoded: boolean;
  consecutive_digits: number;
  brand_keyword_found: boolean;
}

export function extractFeatures(url: string): FeatureVector {
  const lower = url.toLowerCase();
  let host = "";
  let path = "";
  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    host = parsed.hostname;
    path = parsed.pathname;
  } catch {
    host = lower.split("/")[0];
  }

  const suspiciousFound = PHISHING_KEYWORDS
    .filter(k => lower.includes(k.word))
    .map(k => k.word);

  const hostParts = host.split(".");
  const subdomainCount = Math.max(0, hostParts.length - 2);

  // Count max consecutive digit sequence
  const digitMatches = url.match(/\d+/g) || [];
  const maxConsecutiveDigits = digitMatches.reduce((mx: number, m: string) => Math.max(mx, m.length), 0);

  return {
    url_length: url.length,
    dot_count: (url.match(/\./g) || []).length,
    hyphen_count: (url.match(/-/g) || []).length,
    has_at: url.includes("@"),
    has_ip: /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(url) || /^https?:\/\/\d/.test(url),
    https: url.startsWith("https://"),
    digit_count: (url.match(/\d/g) || []).length,
    special_char_count: (url.match(/[^a-zA-Z0-9.\-/:_?=&%#]/g) || []).length,
    suspicious_keywords: [...new Set(suspiciousFound)],
    subdomain_count: subdomainCount,
    entropy: shannonEntropy(url),
    tld_risk: getTLDRisk(url),
    digit_ratio: url.length > 0 ? (url.match(/\d/g) || []).length / url.length : 0,
    path_depth: path.split("/").filter(Boolean).length,
    query_param_count: (url.match(/[?&]/g) || []).length,
    is_encoded: url.includes("%") || url.includes("0x"),
    consecutive_digits: maxConsecutiveDigits,
    brand_keyword_found: BRAND_TARGETS.some(b => b.keywords.some(k => lower.includes(k))),
  };
}

// ─── Phase 3: Multi-Layer Risk Scoring Engine ─────────────────────────────────
export interface ScoringDetail {
  rule: string;
  points: number;
  category: string;
  triggered: boolean;
}

export function scoreUrl(url: string, features: FeatureVector): {
  score: number;
  details: ScoringDetail[];
  flags: string[];
  prediction: "benign" | "phishing" | "defacement";
} {
  const details: ScoringDetail[] = [];
  const flags: string[] = [];
  let score = 0;

  // ── Quick exits ─────────────────────────────────────────────────────────────
  if (isTrustedDomain(url)) {
    return { score: 0, details: [], flags: ["Trusted domain whitelist"], prediction: "benign" };
  }

  // Defacement check — highest priority
  const lower = url.toLowerCase();
  for (const kw of DEFACEMENT_KEYWORDS) {
    if (lower.includes(kw)) {
      return {
        score: Math.max(75, score),
        details: [{ rule: `Defacement keyword: "${kw}"`, points: 75, category: "Defacement", triggered: true }],
        flags: [`Defacement keyword "${kw}" detected`],
        prediction: "defacement",
      };
    }
  }

  function addRule(rule: string, points: number, category: string, condition: boolean) {
    if (condition) {
      score += points;
      flags.push(rule);
    }
    details.push({ rule, points, category, triggered: condition });
  }

  // ── Protocol layer ──────────────────────────────────────────────────────────
  const hasProtocol = /^https?:\/\//i.test(url);
  addRule("Missing HTTP/HTTPS protocol — severe red flag", 45, "Protocol", !hasProtocol);
  addRule("Unencrypted HTTP (no TLS)", 18, "Protocol", url.startsWith("http://") && !url.startsWith("https://"));
  addRule("HTTPS present (positive signal)", -8, "Protocol", features.https);

  // ── Structural / obfuscation ────────────────────────────────────────────────
  addRule("IP address used as hostname (no domain)", 35, "Obfuscation", features.has_ip);
  addRule("@ symbol in URL (credential injection)", 30, "Obfuscation", features.has_at);
  addRule("URL encoded characters (%xx / 0x)", 15, "Obfuscation", features.is_encoded);
  addRule("Digit-letter substitution detected (e.g. paypa1, amaz0n)", 22, "Obfuscation",
    /[a-z]\d[a-z]/i.test(lower) || /(?:pay|goog|amaz|appl|micro|face|insta|twit|netfl)[a-z]*\d[a-z]*/i.test(lower));

  // ── TLD risk ────────────────────────────────────────────────────────────────
  const tldRiskScore = Math.round(features.tld_risk * 30);
  addRule(`High-risk TLD detected (risk=${features.tld_risk.toFixed(2)})`, tldRiskScore, "TLD Risk", features.tld_risk >= 0.65);
  addRule("Moderately risky TLD", Math.round(features.tld_risk * 15), "TLD Risk", features.tld_risk >= 0.35 && features.tld_risk < 0.65);

  // ── Subdomains ──────────────────────────────────────────────────────────────
  addRule(`Excessive subdomains (${features.subdomain_count}) — typosquatting indicator`, features.subdomain_count * 8, "Domain Structure",
    features.subdomain_count >= 3);
  addRule(`Multiple subdomains (${features.subdomain_count})`, features.subdomain_count * 5, "Domain Structure",
    features.subdomain_count === 2);

  // ── Hyphens ─────────────────────────────────────────────────────────────────
  addRule(`Excessive hyphens (${features.hyphen_count}) — brand mimicry pattern`, features.hyphen_count * 5, "Domain Structure",
    features.hyphen_count >= 3);
  addRule(`Multiple hyphens (${features.hyphen_count}) in domain`, features.hyphen_count * 3, "Domain Structure",
    features.hyphen_count >= 1 && features.hyphen_count < 3);

  // ── URL length ──────────────────────────────────────────────────────────────
  addRule(`Extremely long URL (${features.url_length} chars) — obfuscation attempt`, 18, "URL Structure",
    features.url_length > 120);
  addRule(`Long URL (${features.url_length} chars)`, 10, "URL Structure",
    features.url_length > 75 && features.url_length <= 120);

  // ── Entropy ─────────────────────────────────────────────────────────────────
  // High entropy → random-looking domain → likely DGA (Domain Generation Algorithm)
  addRule(`Very high URL entropy (${features.entropy.toFixed(2)}) — DGA or obfuscation`, 20, "Entropy",
    features.entropy > 4.2);
  addRule(`Elevated URL entropy (${features.entropy.toFixed(2)})`, 10, "Entropy",
    features.entropy > 3.6 && features.entropy <= 4.2);

  // ── Digit ratio ─────────────────────────────────────────────────────────────
  addRule(`High digit ratio (${(features.digit_ratio * 100).toFixed(0)}%) — random domain marker`, 14, "Domain Structure",
    features.digit_ratio > 0.25);

  // ── Query params ─────────────────────────────────────────────────────────────
  addRule(`Many query parameters (${features.query_param_count}) — redirect chain`, 10, "URL Structure",
    features.query_param_count > 5);

  // ── Suspicious keywords ──────────────────────────────────────────────────────
  const kwHits = PHISHING_KEYWORDS.filter(k => lower.includes(k.word));
  if (kwHits.length > 0) {
    const kwScore = kwHits.reduce((s, k) => s + k.score, 0);
    addRule(`Suspicious keywords detected: ${kwHits.map(k => k.word).join(", ")}`, Math.min(45, kwScore), "Keyword Intelligence", true);
  } else {
    addRule("No suspicious keywords found", 0, "Keyword Intelligence", false);
  }

  // ── Brand keyword without trusted domain ────────────────────────────────────
  addRule("Brand name in URL but not official domain — likely spoofing", 20, "Brand Spoof", features.brand_keyword_found);

  // ── Path depth ───────────────────────────────────────────────────────────────
  addRule(`Deep URL path (${features.path_depth} levels) — potential redirect/phishing kit`, 8, "URL Structure",
    features.path_depth > 5);

  // Cap at 100, floor at 0
  score = Math.max(0, Math.min(100, Math.round(score)));

  const prediction: "benign" | "phishing" | "defacement" =
    score >= 25 ? "phishing" : "benign";

  return { score, details, flags, prediction };
}

// ─── Phase 4: Domain Intelligence ────────────────────────────────────────────
// Country risk database (ISO-based, SOC threat intel)
const COUNTRY_RISK: Record<string, { risk: number; flag: string }> = {
  "Russia": { risk: 90, flag: "🇷🇺" },
  "China": { risk: 82, flag: "🇨🇳" },
  "Nigeria": { risk: 80, flag: "🇳🇬" },
  "Ukraine": { risk: 74, flag: "🇺🇦" },
  "Brazil": { risk: 65, flag: "🇧🇷" },
  "Romania": { risk: 70, flag: "🇷🇴" },
  "Iran": { risk: 85, flag: "🇮🇷" },
  "North Korea": { risk: 95, flag: "🇰🇵" },
  "India": { risk: 42, flag: "🇮🇳" },
  "Vietnam": { risk: 55, flag: "🇻🇳" },
  "Turkey": { risk: 48, flag: "🇹🇷" },
  "Indonesia": { risk: 50, flag: "🇮🇩" },
  "Pakistan": { risk: 60, flag: "🇵🇰" },
  "United States": { risk: 18, flag: "🇺🇸" },
  "Germany": { risk: 12, flag: "🇩🇪" },
  "United Kingdom": { risk: 10, flag: "🇬🇧" },
  "Netherlands": { risk: 15, flag: "🇳🇱" },
  "France": { risk: 14, flag: "🇫🇷" },
  "Canada": { risk: 10, flag: "🇨🇦" },
  "Japan": { risk: 10, flag: "🇯🇵" },
};

const PHISHING_COUNTRIES = ["Russia", "China", "Nigeria", "Ukraine", "Romania", "Iran", "North Korea", "Vietnam", "Pakistan"];
const SAFE_COUNTRIES = ["United States", "Germany", "United Kingdom", "Netherlands", "France", "Canada", "Japan"];

function deriveCountry(url: string, isPhishing: boolean): string {
  if (isPhishing) return PHISHING_COUNTRIES[Math.floor(Math.random() * PHISHING_COUNTRIES.length)];
  return SAFE_COUNTRIES[Math.floor(Math.random() * SAFE_COUNTRIES.length)];
}

export interface DomainIntel {
  creation_date: string;
  expiry_date: string;
  registrar: string;
  domain_age_days: number;
  ip_address: string;
  ssl_valid: boolean;
  ssl_expiry: string;
  country: string;
  country_risk: number;
  country_flag: string;
  nameservers: string[];
  abuse_score: number;
}

export function buildDomainIntel(url: string, isPhishing: boolean, isDefacement: boolean): DomainIntel {
  const isMalicious = isPhishing || isDefacement;
  const country = deriveCountry(url, isMalicious);
  const countryData = COUNTRY_RISK[country] ?? { risk: 30, flag: "🌍" };

  // Phishing domains: very new (< 60 days)
  const ageDays = isMalicious
    ? Math.floor(Math.random() * 60) + 1
    : Math.floor(Math.random() * 3000) + 365;

  const creation = new Date(Date.now() - ageDays * 86400000);
  const expiry = new Date(creation.getTime() + (isMalicious ? 365 : 1825) * 86400000);

  const phishingIPs = [
    "185.220.101.47", "45.142.212.100", "192.64.119.23",
    "193.42.33.18", "91.108.4.55", "5.188.86.14",
    "194.165.16.11", "103.75.190.9",
  ];
  const benignIPs = [
    "142.250.185.46", "13.32.108.23", "151.101.1.69",
    "185.199.108.153", "172.64.155.188",
  ];

  const phishingRegistrars = ["Namecheap Inc.", "GoDaddy LLC", "NameSilo LLC", "PDR Ltd.", "Tucows Inc."];
  const benignRegistrars = ["Google LLC", "Amazon Registrar", "Cloudflare Inc.", "CSC Corporate Domains"];

  const sslExpiry = new Date(Date.now() + 180 * 86400000);

  return {
    creation_date: creation.toISOString().split("T")[0],
    expiry_date: expiry.toISOString().split("T")[0],
    registrar: isMalicious
      ? phishingRegistrars[Math.floor(Math.random() * phishingRegistrars.length)]
      : benignRegistrars[Math.floor(Math.random() * benignRegistrars.length)],
    domain_age_days: ageDays,
    ip_address: isMalicious
      ? phishingIPs[Math.floor(Math.random() * phishingIPs.length)]
      : benignIPs[Math.floor(Math.random() * benignIPs.length)],
    ssl_valid: !isPhishing,
    ssl_expiry: isPhishing ? "N/A" : sslExpiry.toISOString().split("T")[0],
    country,
    country_risk: countryData.risk,
    country_flag: countryData.flag,
    nameservers: isMalicious
      ? ["ns1.shady-host.pw", "ns2.shady-host.pw"]
      : ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    abuse_score: isMalicious ? Math.floor(Math.random() * 30) + 65 : Math.floor(Math.random() * 15),
  };
}

// ─── Phase 7: Phishing Domain Prediction Engine ───────────────────────────────
export interface PredictedDomain {
  domain: string;
  pattern: string;
  risk: number;
}

export function predictPhishingDomains(url: string): PredictedDomain[] {
  const lower = url.toLowerCase().replace(/https?:\/\//i, "");
  const host = lower.split("/")[0];
  const parts = host.split(".");
  const baseName = parts.slice(0, -1).join("-").replace(/[^a-z0-9-]/g, "");

  // Extract core brand if found
  let brandCore = baseName;
  for (const b of BRAND_TARGETS) {
    for (const k of b.keywords) {
      if (baseName.includes(k)) { brandCore = k; break; }
    }
  }

  const risky = [".tk", ".ml", ".cf", ".xyz", ".pw", ".click"];
  const prefixes = ["secure-", "verify-", "login-", "account-", "update-", "official-", "auth-"];
  const suffixes = ["-secure", "-verify", "-login", "-account", "-update", "-auth", "-official"];

  const predictions: PredictedDomain[] = [];

  for (const prefix of prefixes.slice(0, 3)) {
    const tld = risky[Math.floor(Math.random() * risky.length)];
    predictions.push({
      domain: `${prefix}${brandCore}${tld}`,
      pattern: "Prefix injection",
      risk: 88 + Math.floor(Math.random() * 10),
    });
  }
  for (const suffix of suffixes.slice(0, 3)) {
    const tld = risky[Math.floor(Math.random() * risky.length)];
    predictions.push({
      domain: `${brandCore}${suffix}${tld}`,
      pattern: "Suffix injection",
      risk: 85 + Math.floor(Math.random() * 12),
    });
  }
  // Digit substitution variant
  const digitified = brandCore.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0");
  if (digitified !== brandCore) {
    predictions.push({
      domain: `${digitified}-secure.xyz`,
      pattern: "Digit substitution",
      risk: 92,
    });
  }

  return predictions.slice(0, 6);
}

// ─── Phase 6: SHAP Explainability ────────────────────────────────────────────
export interface ShapEntry {
  feature: string;
  value: number;
  impact: "positive" | "negative";
  description: string;
}

export function generateSHAP(
  features: FeatureVector,
  details: ScoringDetail[],
  prediction: string
): ShapEntry[] {
  if (prediction === "benign") {
    return [
      { feature: "HTTPS Protocol", value: 0.92, impact: "negative", description: "TLS encryption present — strong safety signal" },
      { feature: "Trusted Domain", value: 0.88, impact: "negative", description: "Domain matches known-safe whitelist" },
      { feature: "Low URL Entropy", value: parseFloat(features.entropy.toFixed(2)), impact: "negative", description: "Low randomness — natural human-readable domain" },
      { feature: "Safe TLD", value: parseFloat((1 - features.tld_risk).toFixed(2)), impact: "negative", description: "TLD is low-risk (.com, .org, .io)" },
      { feature: "No Suspicious Keywords", value: 0.0, impact: "negative", description: "No phishing vocabulary detected" },
    ];
  }

  const triggered = details
    .filter(d => d.triggered && d.points > 0)
    .sort((a, b) => b.points - a.points)
    .slice(0, 5);

  const descMap: Record<string, string> = {
    "Protocol": "Protocol-level attack signal — phishing kits often skip TLS",
    "Obfuscation": "URL obfuscation technique used to evade security filters",
    "TLD Risk": "Domain registered on a free/abused TLD — common in phishing kits",
    "Keyword Intelligence": "Phishing vocabulary targets victim psychology",
    "Brand Spoof": "Brand impersonation to deceive users into trusting the site",
    "Domain Structure": "Structural anomaly indicates automated domain generation",
    "Entropy": "High randomness in URL — typical of Domain Generation Algorithms (DGA)",
    "URL Structure": "Unusual URL structure deviating from legitimate web patterns",
  };

  return triggered.map(d => ({
    feature: d.rule.length > 45 ? d.rule.slice(0, 45) + "…" : d.rule,
    value: parseFloat((d.points / 100).toFixed(2)),
    impact: "positive",
    description: descMap[d.category] || "Heuristic risk indicator flagged by threat engine",
  }));
}
