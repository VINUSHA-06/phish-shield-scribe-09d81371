// Mock API client — wire to real Flask backend by changing BASE_URL
const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

export interface ScanResult {
  url: string;
  prediction: "benign" | "phishing" | "defacement";
  confidence: number;
  risk_score: number;
  risk_category: "Safe" | "Suspicious" | "High Risk";
  features: {
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
  };
  shap_explanation: Array<{ feature: string; value: number; impact: "positive" | "negative" }>;
  domain_intel: {
    creation_date: string;
    expiry_date: string;
    registrar: string;
    domain_age_days: number;
    ip_address: string;
    ssl_valid: boolean;
    ssl_expiry: string;
    country: string;
    country_risk: number;
  };
  brand_spoof: {
    detected: boolean;
    target_brand: string;
    similarity: number;
  } | null;
  scanned_at: string;
}

export interface Statistics {
  total_scanned: number;
  phishing_count: number;
  benign_count: number;
  defacement_count: number;
  phishing_percentage: number;
  top_keywords: Array<{ keyword: string; count: number }>;
  country_distribution: Array<{ country: string; count: number; risk: number }>;
  daily_detections: Array<{ date: string; phishing: number; benign: number; defacement: number }>;
  risk_distribution: Array<{ category: string; count: number }>;
}

export interface RecentScan {
  id: string;
  url: string;
  prediction: string;
  risk_score: number;
  risk_category: string;
  scanned_at: string;
}

export interface CampaignAlert {
  id: string;
  campaign_id: string;
  urls: string[];
  common_ip: string;
  common_registrar: string;
  similarity_score: number;
  detected_at: string;
  target_brand?: string;
}

// ─── Heuristic URL Risk Engine ───────────────────────────────────────────────
function analyzeUrl(url: string): { prediction: "benign" | "phishing" | "defacement"; risk_score: number; flags: string[] } {
  let score = 0;
  const flags: string[] = [];
  const lower = url.toLowerCase();

  // 1. No protocol → strong phishing signal
  if (!/^https?:\/\//i.test(url)) {
    score += 40;
    flags.push("No HTTP/HTTPS protocol");
  }

  // 2. HTTP (not HTTPS) → moderate risk
  if (/^http:\/\//i.test(url)) {
    score += 15;
    flags.push("Unencrypted HTTP");
  }

  // 3. Suspicious keywords
  const suspiciousKeywords = ["login", "verify", "secure", "bank", "update", "account", "password", "confirm", "billing", "signin", "credential", "webscr", "ebayisapi", "authentication"];
  const found = suspiciousKeywords.filter(k => lower.includes(k));
  if (found.length > 0) {
    score += found.length * 12;
    flags.push(`Suspicious keywords: ${found.join(", ")}`);
  }

  // 4. IP address used as host
  if (/https?:\/\/\d{1,3}(\.\d{1,3}){3}/i.test(url)) {
    score += 30;
    flags.push("IP address used instead of domain");
  }

  // 5. Risky TLDs
  const riskyTlds = [".tk", ".ml", ".cf", ".ga", ".xyz", ".top", ".pw", ".cc", ".click", ".gq", ".work", ".link"];
  if (riskyTlds.some(t => lower.includes(t))) {
    score += 20;
    flags.push("High-risk TLD detected");
  }

  // 6. @ symbol in URL (credential spoofing)
  if (url.includes("@")) {
    score += 25;
    flags.push("@ symbol detected (credential spoof)");
  }

  // 7. Excessive hyphens (brand mimicry)
  const hyphens = (url.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += hyphens * 5;
    flags.push(`Excessive hyphens (${hyphens})`);
  }

  // 8. Excessive subdomains
  const host = url.replace(/https?:\/\//i, "").split("/")[0];
  const subdomains = host.split(".").length - 2;
  if (subdomains >= 2) {
    score += subdomains * 8;
    flags.push(`Too many subdomains (${subdomains})`);
  }

  // 9. Unusually long URL
  if (url.length > 75) {
    score += 10;
    flags.push(`Long URL (${url.length} chars)`);
  }
  if (url.length > 120) {
    score += 10;
    flags.push("Extremely long URL");
  }

  // 10. Digits replacing letters (e.g. paypa1, amaz0n)
  if (/[a-z]\d[a-z]/i.test(lower) || /[a-z]\d$/i.test(lower)) {
    score += 18;
    flags.push("Digit-letter substitution (e.g. paypa1)");
  }

  // 11. Known defacement patterns
  const defacementKeywords = ["hack", "pwned", "defaced", "owned", "hacked_by", "r00t"];
  if (defacementKeywords.some(k => lower.includes(k))) {
    score = Math.max(score, 65);
    flags.push("Defacement keyword detected");
    return { prediction: "defacement", risk_score: Math.min(100, score), flags };
  }

  // 12. Trusted domain whitelist → reduce score
  const trustedDomains = ["google.com", "github.com", "stackoverflow.com", "npmjs.com", "twitter.com", "youtube.com", "microsoft.com", "apple.com", "linkedin.com", "wikipedia.org"];
  if (trustedDomains.some(d => lower.includes(d))) {
    score = Math.max(0, score - 50);
  }

  score = Math.min(100, Math.round(score));
  const prediction: "benign" | "phishing" | "defacement" = score >= 31 ? "phishing" : "benign";
  return { prediction, risk_score: score, flags };
}

// Mock data generators
function mockScanResult(url: string): ScanResult {
  const { prediction, risk_score, flags } = analyzeUrl(url);
  const isPhishing = prediction === "phishing";
  const isDefacement = prediction === "defacement";
  const risk_category: "Safe" | "Suspicious" | "High Risk" = risk_score > 60 ? "High Risk" : risk_score > 30 ? "Suspicious" : "Safe";

  const hasBrandSpoof = (url.toLowerCase().includes("paypal") || url.toLowerCase().includes("amazon") || url.toLowerCase().includes("google")) && isPhishing;

  return {
    url,
    prediction,
    confidence: isPhishing ? 0.87 + Math.random() * 0.1 : 0.92 + Math.random() * 0.07,
    risk_score: Math.round(risk_score),
    risk_category,
    features: {
      url_length: url.length,
      dot_count: (url.match(/\./g) || []).length,
      hyphen_count: (url.match(/-/g) || []).length,
      has_at: url.includes("@"),
      has_ip: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url),
      https: url.startsWith("https"),
      digit_count: (url.match(/\d/g) || []).length,
      special_char_count: (url.match(/[^a-zA-Z0-9./:_-]/g) || []).length,
      suspicious_keywords: isPhishing ? ["login", "verify", "secure"].filter(k => url.includes(k)) : [],
      subdomain_count: (url.replace(/https?:\/\//, "").split(".").length - 2),
      entropy: isPhishing ? 4.2 + Math.random() * 0.8 : 2.8 + Math.random() * 0.6,
      tld_risk: isPhishing ? 0.7 : 0.1,
      digit_ratio: isPhishing ? 0.35 : 0.05,
    },
    shap_explanation: (isPhishing || isDefacement)
      ? flags.slice(0, 5).map((f, i) => ({ feature: f, value: +(risk_score / (i + 2)).toFixed(1), impact: "positive" as const })).concat(
          !url.startsWith("https") ? [] : [{ feature: "HTTPS Present", value: 1, impact: "negative" as const }]
        ).slice(0, 5)
      : [
          { feature: "HTTPS Present", value: 1, impact: "negative" as const },
          { feature: "Domain Age (days)", value: 1820, impact: "negative" as const },
          { feature: "URL Entropy", value: 2.9, impact: "negative" as const },
          { feature: "TLD Risk Score", value: 0.1, impact: "negative" as const },
          { feature: "Suspicious Keywords", value: 0, impact: "negative" as const },
        ],
    domain_intel: {
      creation_date: isPhishing ? "2024-11-15" : "2010-03-22",
      expiry_date: isPhishing ? "2025-11-15" : "2028-03-22",
      registrar: isPhishing ? "NameCheap, Inc." : "Google LLC",
      domain_age_days: isPhishing ? 12 : 5420,
      ip_address: isPhishing ? "185.220.101.47" : "142.250.185.46",
      ssl_valid: !isPhishing,
      ssl_expiry: isPhishing ? "N/A" : "2025-12-31",
      country: isPhishing ? "Russia" : "United States",
      country_risk: isPhishing ? 85 : 10,
    },
    brand_spoof: hasBrandSpoof
      ? {
          detected: true,
          target_brand: url.includes("paypal") ? "PayPal" : url.includes("amazon") ? "Amazon" : "Google",
          similarity: 0.87 + Math.random() * 0.1,
        }
      : null,
    scanned_at: new Date().toISOString(),
  };
}

function mockStatistics(): Statistics {
  return {
    total_scanned: 15847,
    phishing_count: 4231,
    benign_count: 9842,
    defacement_count: 1774,
    phishing_percentage: 26.7,
    top_keywords: [
      { keyword: "login", count: 1842 },
      { keyword: "verify", count: 1234 },
      { keyword: "secure", count: 987 },
      { keyword: "bank", count: 743 },
      { keyword: "update", count: 621 },
    ],
    country_distribution: [
      { country: "Russia", count: 1823, risk: 90 },
      { country: "China", count: 1456, risk: 82 },
      { country: "Nigeria", count: 987, risk: 78 },
      { country: "Brazil", count: 654, risk: 65 },
      { country: "Ukraine", count: 543, risk: 72 },
      { country: "United States", count: 321, risk: 25 },
    ],
    daily_detections: Array.from({ length: 14 }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (13 - i));
      return {
        date: d.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
        phishing: Math.floor(Math.random() * 300 + 150),
        benign: Math.floor(Math.random() * 600 + 400),
        defacement: Math.floor(Math.random() * 100 + 50),
      };
    }),
    risk_distribution: [
      { category: "Safe (0-30)", count: 9842 },
      { category: "Suspicious (31-60)", count: 1774 },
      { category: "High Risk (61-100)", count: 4231 },
    ],
  };
}

function mockRecentScans(): RecentScan[] {
  const samples = [
    { url: "https://paypa1-verify-account.xyz/login", prediction: "phishing", risk_score: 89 },
    { url: "https://google.com/search?q=react", prediction: "benign", risk_score: 5 },
    { url: "http://amaz0n-secure.tk/update-billing", prediction: "phishing", risk_score: 94 },
    { url: "https://github.com/facebook/react", prediction: "benign", risk_score: 8 },
    { url: "http://sbi-netbanking.ml/verify", prediction: "phishing", risk_score: 91 },
    { url: "https://stackoverflow.com/questions", prediction: "benign", risk_score: 3 },
    { url: "http://185.220.101.47/defaced/index.html", prediction: "defacement", risk_score: 76 },
    { url: "https://npmjs.com/package/react", prediction: "benign", risk_score: 7 },
    { url: "http://secure-login-chase-bank.cf/auth", prediction: "phishing", risk_score: 97 },
    { url: "https://twitter.com/elonmusk", prediction: "benign", risk_score: 6 },
  ];
  return samples.map((s, i) => ({
    id: `scan_${i + 1}`,
    ...s,
    risk_category: s.risk_score > 60 ? "High Risk" : s.risk_score > 30 ? "Suspicious" : "Safe",
    scanned_at: new Date(Date.now() - i * 3600000).toISOString(),
  }));
}

function mockCampaignAlerts(): CampaignAlert[] {
  return [
    {
      id: "ca_001",
      campaign_id: "CAMP-2024-001",
      urls: ["http://paypa1-verify.xyz", "http://paypal-secure.ml", "http://paypa1.cf/login"],
      common_ip: "185.220.101.47",
      common_registrar: "Namecheap",
      similarity_score: 0.91,
      detected_at: new Date(Date.now() - 86400000).toISOString(),
      target_brand: "PayPal",
    },
    {
      id: "ca_002",
      campaign_id: "CAMP-2024-002",
      urls: ["http://amaz0n-deals.tk", "http://amazon-secure.ml", "http://amaz0n.cf/update"],
      common_ip: "192.168.45.23",
      common_registrar: "GoDaddy",
      similarity_score: 0.88,
      detected_at: new Date(Date.now() - 172800000).toISOString(),
      target_brand: "Amazon",
    },
    {
      id: "ca_003",
      campaign_id: "CAMP-2024-003",
      urls: ["http://sbi-netbanking.cf", "http://sbi-secure-login.ml", "http://sbibanking.tk"],
      common_ip: "45.142.212.100",
      common_registrar: "NameSilo",
      similarity_score: 0.85,
      detected_at: new Date(Date.now() - 259200000).toISOString(),
      target_brand: "SBI Bank",
    },
  ];
}

// API functions — swap mock with real fetch when backend is ready
export async function scanUrl(url: string): Promise<ScanResult> {
  // Real API call:
  // const res = await fetch(`${BASE_URL}/scan-url`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({url}) });
  // return res.json();
  await new Promise(r => setTimeout(r, 2000 + Math.random() * 1000));
  return mockScanResult(url);
}

export async function getStatistics(): Promise<Statistics> {
  // const res = await fetch(`${BASE_URL}/statistics`);
  // return res.json();
  await new Promise(r => setTimeout(r, 500));
  return mockStatistics();
}

export async function getRecentScans(): Promise<RecentScan[]> {
  // const res = await fetch(`${BASE_URL}/recent-scans`);
  // return res.json();
  await new Promise(r => setTimeout(r, 500));
  return mockRecentScans();
}

export async function getCampaignAlerts(): Promise<CampaignAlert[]> {
  // const res = await fetch(`${BASE_URL}/campaign-alerts`);
  // return res.json();
  await new Promise(r => setTimeout(r, 500));
  return mockCampaignAlerts();
}
