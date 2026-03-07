import { RecentScan } from "./api";

const KEY = "threatiq_recent_scans";
const MAX = 50;

export function saveToHistory(scan: RecentScan) {
  const existing = getHistory();
  // Avoid duplicates for same URL scanned closely
  const filtered = existing.filter(s => s.url !== scan.url);
  const updated = [scan, ...filtered].slice(0, MAX);
  localStorage.setItem(KEY, JSON.stringify(updated));
}

export function getHistory(): RecentScan[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}

export function clearHistory() {
  localStorage.removeItem(KEY);
}
