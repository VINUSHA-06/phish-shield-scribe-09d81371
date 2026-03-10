/**
 * ThreatIQ API Client — wires the threat engine to React UI
 * Production mode: swap BASE_URL + uncomment real fetch calls
 */
import {
  extractFeatures,
  scoreUrl,
  buildDomainIntel,
  detectBrandSpoof,
  generateSHAP,
  predictPhishingDomains,
  type PredictedDomain,
} from "./threatEngine";

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
    path_depth: number;
    query_param_count: number;
    is_encoded: boolean;
  };
  shap_explanation: Array<{
    feature: string;
    value: number;
    impact: "positive" | "negative";
    description: string;
  }>;
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
    country_flag: string;
    nameservers: string[];
    abuse_score: number;
  };
  brand_spoof: {
    detected: boolean;
    target_brand: string;
    similarity: number;
  } | null;
  scoring_details: Array<{
    rule: string;
    points: number;
    category: string;
    triggered: boolean;
  }>;
  predicted_domains: PredictedDomain[];
  scanned_at: string;
}

export interface Statistics {
  total_scanned: number;
  phishing_count: number;
  benign_count: number;
  defacement_count: number;
  phishing_percentage: number;
  top_keywords: Array<{ keyword: string; count: number }>;
  country_distribution: Array<{ country: string; count: number; risk: number; flag: string }>;
  daily_detections: Array<{ date: string; phishing: number; benign: number; defacement: number }>;
  risk_distribution: Array<{ category: string; count: number }>;
  keyword_trend: Array<{ month: string; login: number; verify: number; secure: number; bank: number }>;
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
  timeline: Array<{ date: string; domain: string; event: string }>;
  predicted_next: string[];
}

// ─── Core Scan Engine ────────────────────────────────────────────────────────
function runScan(url: string): ScanResult {
  const features = extractFeatures(url);
  const { score, details, prediction } = scoreUrl(url, features);
  const isPhishing = prediction === "phishing";
  const isDefacement = prediction === "defacement";
  const isMalicious = isPhishing || isDefacement;

  const risk_category: "Safe" | "Suspicious" | "High Risk" =
    score > 60 ? "High Risk" : score > 25 ? "Suspicious" : "Safe";

  const brandSpoof = isMalicious ? detectBrandSpoof(url) : null;
  const domainIntel = buildDomainIntel(url, isPhishing, isDefacement);
  const shapValues = generateSHAP(features, details, prediction);

  // Confidence: higher score → higher confidence in malicious label
  const confidence = isMalicious
    ? Math.min(0.99, 0.72 + (score / 100) * 0.25)
    : Math.min(0.99, 0.88 + Math.random() * 0.1);

  const predictedDomains = isMalicious ? predictPhishingDomains(url) : [];

  return {
    url,
    prediction,
    confidence,
    risk_score: score,
    risk_category,
    features: {
      url_length: features.url_length,
      dot_count: features.dot_count,
      hyphen_count: features.hyphen_count,
      has_at: features.has_at,
      has_ip: features.has_ip,
      https: features.https,
      digit_count: features.digit_count,
      special_char_count: features.special_char_count,
      suspicious_keywords: features.suspicious_keywords,
      subdomain_count: features.subdomain_count,
      entropy: features.entropy,
      tld_risk: features.tld_risk,
      digit_ratio: features.digit_ratio,
      path_depth: features.path_depth,
      query_param_count: features.query_param_count,
      is_encoded: features.is_encoded,
    },
    shap_explanation: shapValues,
    domain_intel: domainIntel,
    brand_spoof: brandSpoof,
    scoring_details: details,
    predicted_domains: predictedDomains,
    scanned_at: new Date().toISOString(),
  };
}

// ─── Mock Statistics ──────────────────────────────────────────────────────────
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
      { keyword: "account", count: 534 },
      { keyword: "password", count: 412 },
      { keyword: "confirm", count: 389 },
    ],
    country_distribution: [
      { country: "Russia", count: 1823, risk: 90, flag: "🇷🇺" },
      { country: "China", count: 1456, risk: 82, flag: "🇨🇳" },
      { country: "Nigeria", count: 987, risk: 80, flag: "🇳🇬" },
      { country: "Ukraine", count: 654, risk: 74, flag: "🇺🇦" },
      { country: "Romania", count: 543, risk: 70, flag: "🇷🇴" },
      { country: "Brazil", count: 489, risk: 65, flag: "🇧🇷" },
      { country: "United States", count: 321, risk: 18, flag: "🇺🇸" },
      { country: "Iran", count: 298, risk: 85, flag: "🇮🇷" },
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
      { category: "Safe (0-25)", count: 9842 },
      { category: "Suspicious (26-60)", count: 1774 },
      { category: "High Risk (61-100)", count: 4231 },
    ],
    keyword_trend: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"].map(month => ({
      month,
      login: Math.floor(Math.random() * 400 + 250),
      verify: Math.floor(Math.random() * 300 + 150),
      secure: Math.floor(Math.random() * 200 + 100),
      bank: Math.floor(Math.random() * 180 + 80),
    })),
  };
}

function mockRecentScans(): RecentScan[] {
  const samples = [
    { url: "https://paypa1-verify-account.xyz/login", prediction: "phishing", risk_score: 89 },
    { url: "https://google.com/search?q=react", prediction: "benign", risk_score: 0 },
    { url: "http://amaz0n-secure.tk/update-billing", prediction: "phishing", risk_score: 94 },
    { url: "https://github.com/facebook/react", prediction: "benign", risk_score: 0 },
    { url: "http://sbi-netbanking.ml/verify", prediction: "phishing", risk_score: 91 },
    { url: "https://stackoverflow.com/questions", prediction: "benign", risk_score: 0 },
    { url: "http://185.220.101.47/defaced/index.html", prediction: "defacement", risk_score: 76 },
    { url: "https://npmjs.com/package/react", prediction: "benign", risk_score: 0 },
    { url: "http://secure-login-chase-bank.cf/auth", prediction: "phishing", risk_score: 97 },
    { url: "https://twitter.com/elonmusk", prediction: "benign", risk_score: 0 },
  ];
  return samples.map((s, i) => ({
    id: `scan_${i + 1}`,
    ...s,
    risk_category: s.risk_score > 60 ? "High Risk" : s.risk_score > 25 ? "Suspicious" : "Safe",
    scanned_at: new Date(Date.now() - i * 3600000).toISOString(),
  }));
}

function mockCampaignAlerts(): CampaignAlert[] {
  return [
    {
      id: "ca_001",
      campaign_id: "CAMP-2024-001",
      urls: [
        "http://paypa1-verify.xyz",
        "http://paypal-secure.ml",
        "http://paypa1.cf/login",
        "http://paypal-account-verify.tk",
        "http://secure-paypal-login.pw",
      ],
      common_ip: "185.220.101.47",
      common_registrar: "Namecheap",
      similarity_score: 0.91,
      detected_at: new Date(Date.now() - 86400000).toISOString(),
      target_brand: "PayPal",
      timeline: [
        { date: "Mar 8", domain: "paypa1-verify.xyz", event: "Initial domain registered" },
        { date: "Mar 9", domain: "paypal-secure.ml", event: "Variant launched with HTTPS" },
        { date: "Mar 10", domain: "paypa1.cf/login", event: "Login page deployed" },
        { date: "Mar 11", domain: "paypal-account-verify.tk", event: "New IP cluster added" },
        { date: "Mar 12", domain: "secure-paypal-login.pw", event: "Mass phishing emails sent" },
      ],
      predicted_next: ["verify-paypal-secure.tk", "paypal-auth-update.ml", "paypa1-confirm.xyz"],
    },
    {
      id: "ca_002",
      campaign_id: "CAMP-2024-002",
      urls: [
        "http://amaz0n-deals.tk",
        "http://amazon-secure.ml",
        "http://amaz0n.cf/update",
        "http://amazon-account-verify.pw",
      ],
      common_ip: "192.64.119.23",
      common_registrar: "GoDaddy",
      similarity_score: 0.88,
      detected_at: new Date(Date.now() - 172800000).toISOString(),
      target_brand: "Amazon",
      timeline: [
        { date: "Mar 6", domain: "amaz0n-deals.tk", event: "Campaign launched during sale season" },
        { date: "Mar 7", domain: "amazon-secure.ml", event: "SSL spoofing attempt detected" },
        { date: "Mar 8", domain: "amaz0n.cf/update", event: "Credential harvesting page live" },
        { date: "Mar 9", domain: "amazon-account-verify.pw", event: "2FA bypass page added" },
      ],
      predicted_next: ["secure-amazon-update.xyz", "amaz0n-account.cf", "amazon-verify-billing.ml"],
    },
    {
      id: "ca_003",
      campaign_id: "CAMP-2024-003",
      urls: [
        "http://sbi-netbanking.cf",
        "http://sbi-secure-login.ml",
        "http://sbibanking.tk",
      ],
      common_ip: "45.142.212.100",
      common_registrar: "NameSilo",
      similarity_score: 0.85,
      detected_at: new Date(Date.now() - 259200000).toISOString(),
      target_brand: "SBI Bank",
      timeline: [
        { date: "Mar 4", domain: "sbi-netbanking.cf", event: "Domain registered, idle" },
        { date: "Mar 5", domain: "sbi-secure-login.ml", event: "Phishing kit deployed" },
        { date: "Mar 7", domain: "sbibanking.tk", event: "Targeted SMS phishing (smishing) started" },
      ],
      predicted_next: ["onlinesbi-secure.xyz", "sbi-login-verify.tk", "sbi-account-update.ml"],
    },
  ];
}

// ─── Exported API Functions ───────────────────────────────────────────────────
export async function scanUrl(url: string): Promise<ScanResult> {
  // Real: const res = await fetch(`${BASE_URL}/scan-url`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
  // return res.json();
  void BASE_URL;
  await new Promise(r => setTimeout(r, 1800 + Math.random() * 800));
  return runScan(url);
}

export async function getStatistics(): Promise<Statistics> {
  await new Promise(r => setTimeout(r, 400));
  return mockStatistics();
}

export async function getRecentScans(): Promise<RecentScan[]> {
  await new Promise(r => setTimeout(r, 300));
  return mockRecentScans();
}

export async function getCampaignAlerts(): Promise<CampaignAlert[]> {
  await new Promise(r => setTimeout(r, 400));
  return mockCampaignAlerts();
}
