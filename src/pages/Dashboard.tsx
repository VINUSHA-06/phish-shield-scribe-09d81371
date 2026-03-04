import { useEffect, useState } from "react";
import { getStatistics, Statistics } from "@/lib/api";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import { Shield, ShieldAlert, Globe, TrendingUp, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

const COLORS = {
  phishing: "hsl(0 75% 58%)",
  benign: "hsl(142 70% 45%)",
  defacement: "hsl(45 95% 55%)",
  primary: "hsl(180 100% 40%)",
};

function StatCard({ icon: Icon, label, value, sub, color }: { icon: any; label: string; value: string; sub?: string; color: string }) {
  return (
    <div className="rounded-xl border border-border bg-gradient-card p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{label}</span>
        <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center", `bg-[${color}]/10`)}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getStatistics().then(s => { setStats(s); setLoading(false); });
  }, []);

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <Loader2 className="w-8 h-8 text-primary animate-spin" />
    </div>
  );

  if (!stats) return null;

  return (
    <div className="px-8 py-8 space-y-8">
      <div>
        <h1 className="text-2xl font-bold mb-1">Admin Dashboard</h1>
        <p className="text-muted-foreground text-sm">Real-time threat intelligence analytics</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Shield} label="Total Scanned" value={stats.total_scanned.toLocaleString()} sub="All time" color={COLORS.primary} />
        <StatCard icon={ShieldAlert} label="Phishing Detected" value={stats.phishing_count.toLocaleString()} sub={`${stats.phishing_percentage}% of scans`} color={COLORS.phishing} />
        <StatCard icon={Shield} label="Benign" value={stats.benign_count.toLocaleString()} sub="Safe URLs" color={COLORS.benign} />
        <StatCard icon={TrendingUp} label="Defacement" value={stats.defacement_count.toLocaleString()} sub="Defaced sites" color={COLORS.defacement} />
      </div>

      {/* Daily detections chart */}
      <div className="rounded-xl border border-border bg-gradient-card p-6">
        <h3 className="text-sm font-semibold mb-4">Daily Detection Trend (14 days)</h3>
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={stats.daily_detections} margin={{ top: 5, right: 20, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.phishing} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.phishing} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.benign} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.benign} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="defaceGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.defacement} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.defacement} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(220 20% 14%)" />
            <XAxis dataKey="date" tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
            <YAxis tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "hsl(220 25% 7%)", border: "1px solid hsl(220 20% 14%)", borderRadius: "8px", color: "hsl(210 40% 95%)" }} />
            <Legend />
            <Area type="monotone" dataKey="phishing" stroke={COLORS.phishing} fill="url(#phishGrad)" strokeWidth={2} />
            <Area type="monotone" dataKey="benign" stroke={COLORS.benign} fill="url(#benignGrad)" strokeWidth={2} />
            <Area type="monotone" dataKey="defacement" stroke={COLORS.defacement} fill="url(#defaceGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Risk distribution pie */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">Risk Score Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={stats.risk_distribution} cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="count" paddingAngle={4}>
                {stats.risk_distribution.map((_, i) => (
                  <Cell key={i} fill={[COLORS.benign, COLORS.defacement, COLORS.phishing][i]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "hsl(220 25% 7%)", border: "1px solid hsl(220 20% 14%)", borderRadius: "8px" }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5 mt-2">
            {stats.risk_distribution.map((d, i) => (
              <div key={d.category} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ background: [COLORS.benign, COLORS.defacement, COLORS.phishing][i] }} />
                  <span className="text-muted-foreground">{d.category}</span>
                </div>
                <span className="font-mono text-foreground">{d.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top keywords */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">Most Common Suspicious Keywords</h3>
          <div className="space-y-3">
            {stats.top_keywords.map((kw, i) => (
              <div key={kw.keyword}>
                <div className="flex items-center justify-between mb-1 text-sm">
                  <span className="font-mono text-warning">{kw.keyword}</span>
                  <span className="text-muted-foreground font-mono">{kw.count}</span>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-warning rounded-full"
                    style={{ width: `${(kw.count / stats.top_keywords[0].count) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Country distribution */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">
            <Globe className="w-4 h-4 inline mr-2 text-primary" />
            Country-Wise Attack Origin
          </h3>
          <div className="space-y-2.5">
            {stats.country_distribution.map(c => (
              <div key={c.country}>
                <div className="flex items-center justify-between mb-1 text-xs">
                  <span className="text-foreground">{c.country}</span>
                  <span className={cn("font-mono", c.risk > 70 ? "text-danger" : c.risk > 50 ? "text-warning" : "text-safe")}>
                    Risk {c.risk}
                  </span>
                </div>
                <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(c.count / stats.country_distribution[0].count) * 100}%`,
                      background: c.risk > 70 ? COLORS.phishing : c.risk > 50 ? COLORS.defacement : COLORS.benign,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Keyword bar chart */}
      <div className="rounded-xl border border-border bg-gradient-card p-6">
        <h3 className="text-sm font-semibold mb-4">Attack Count by Country</h3>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.country_distribution} margin={{ top: 5, right: 20, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(220 20% 14%)" />
            <XAxis dataKey="country" tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
            <YAxis tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
            <Tooltip contentStyle={{ background: "hsl(220 25% 7%)", border: "1px solid hsl(220 20% 14%)", borderRadius: "8px" }} />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {stats.country_distribution.map((c, i) => (
                <Cell key={i} fill={c.risk > 70 ? COLORS.phishing : c.risk > 50 ? COLORS.defacement : COLORS.benign} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
