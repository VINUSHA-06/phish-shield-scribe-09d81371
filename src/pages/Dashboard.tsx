import { useEffect, useState } from "react";
import { getStatistics, Statistics } from "@/lib/api";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  LineChart, Line,
} from "recharts";
import { Shield, ShieldAlert, Globe, TrendingUp, Loader2, Brain, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

const COLORS = {
  phishing: "hsl(0 75% 58%)",
  benign: "hsl(142 70% 45%)",
  defacement: "hsl(45 95% 55%)",
  primary: "hsl(180 100% 40%)",
};

function StatCard({
  icon: Icon, label, value, sub, color, pct,
}: {
  icon: any; label: string; value: string; sub?: string; color: string; pct?: number;
}) {
  return (
    <div className="rounded-xl border border-border bg-gradient-card p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">{label}</span>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${color}18` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
      {pct !== undefined && (
        <div className="mt-3">
          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
          </div>
        </div>
      )}
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

  const totalMalicious = stats.phishing_count + stats.defacement_count;
  const benignPct = Math.round((stats.benign_count / stats.total_scanned) * 100);
  const phishPct = Math.round((stats.phishing_count / stats.total_scanned) * 100);
  const defacePct = Math.round((stats.defacement_count / stats.total_scanned) * 100);

  return (
    <div className="px-8 py-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Threat Intelligence Dashboard</h1>
        <p className="text-muted-foreground text-sm">Real-time SOC-grade analytics — updated live</p>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Total Scanned" value={stats.total_scanned.toLocaleString()} sub="All time" color={COLORS.primary} pct={100} />
        <StatCard icon={ShieldAlert} label="Phishing" value={stats.phishing_count.toLocaleString()} sub={`${phishPct}% of scans`} color={COLORS.phishing} pct={phishPct} />
        <StatCard icon={Shield} label="Benign (Safe)" value={stats.benign_count.toLocaleString()} sub={`${benignPct}% of scans`} color={COLORS.benign} pct={benignPct} />
        <StatCard icon={TrendingUp} label="Defacement" value={stats.defacement_count.toLocaleString()} sub={`${defacePct}% of scans`} color={COLORS.defacement} pct={defacePct} />
      </div>

      {/* ── Daily Trend ── */}
      <div className="rounded-xl border border-border bg-gradient-card p-6">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-semibold">Daily Detection Trend (14 days)</h3>
        </div>
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={stats.daily_detections} margin={{ top: 5, right: 20, left: -20, bottom: 0 }}>
            <defs>
              {[
                { id: "phishGrad", color: COLORS.phishing },
                { id: "benignGrad", color: COLORS.benign },
                { id: "defaceGrad", color: COLORS.defacement },
              ].map(g => (
                <linearGradient key={g.id} id={g.id} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={g.color} stopOpacity={0.35} />
                  <stop offset="95%" stopColor={g.color} stopOpacity={0} />
                </linearGradient>
              ))}
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

      {/* ── Row: Pie + Keywords + Country ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Risk Pie */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie
                data={stats.risk_distribution}
                cx="50%" cy="50%"
                innerRadius={50} outerRadius={75}
                dataKey="count" paddingAngle={4}
              >
                {stats.risk_distribution.map((_, i) => (
                  <Cell key={i} fill={[COLORS.benign, COLORS.defacement, COLORS.phishing][i]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "hsl(220 25% 7%)", border: "1px solid hsl(220 20% 14%)", borderRadius: "8px" }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-2 mt-2">
            {stats.risk_distribution.map((d, i) => (
              <div key={d.category} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: [COLORS.benign, COLORS.defacement, COLORS.phishing][i] }} />
                  <span className="text-muted-foreground">{d.category}</span>
                </div>
                <span className="font-mono text-foreground">{d.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Keyword Intelligence */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="w-4 h-4 text-warning" />
            <h3 className="text-sm font-semibold">Phishing Keyword Intelligence</h3>
          </div>
          <div className="space-y-3">
            {stats.top_keywords.map((kw, i) => {
              const pct = Math.round((kw.count / stats.top_keywords[0].count) * 100);
              return (
                <div key={kw.keyword}>
                  <div className="flex items-center justify-between mb-1 text-sm">
                    <span className="font-mono text-warning text-xs">{kw.keyword}</span>
                    <span className="text-muted-foreground font-mono text-xs">{kw.count.toLocaleString()} ({pct}%)</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${pct}%`,
                        background: i === 0
                          ? COLORS.phishing
                          : i <= 2
                          ? COLORS.defacement
                          : "hsl(180 100% 40%)",
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Country Distribution */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold">Country-Wise Attack Origin</h3>
          </div>
          <div className="space-y-2.5">
            {stats.country_distribution.map(c => (
              <div key={c.country}>
                <div className="flex items-center justify-between mb-1 text-xs">
                  <span className="text-foreground">{c.flag} {c.country}</span>
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

      {/* ── Keyword Trend + Country Bar ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Keyword monthly trend */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">Phishing Keyword Monthly Trend</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={stats.keyword_trend} margin={{ top: 5, right: 20, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220 20% 14%)" />
              <XAxis dataKey="month" tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
              <YAxis tick={{ fill: "hsl(210 20% 50%)", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "hsl(220 25% 7%)", border: "1px solid hsl(220 20% 14%)", borderRadius: "8px", color: "hsl(210 40% 95%)" }} />
              <Legend />
              <Line type="monotone" dataKey="login" stroke={COLORS.phishing} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="verify" stroke={COLORS.defacement} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="secure" stroke={COLORS.primary} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="bank" stroke={COLORS.benign} strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Attack count by country */}
        <div className="rounded-xl border border-border bg-gradient-card p-6">
          <h3 className="text-sm font-semibold mb-4">Attack Volume by Country</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={stats.country_distribution} margin={{ top: 5, right: 20, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(220 20% 14%)" />
              <XAxis dataKey="country" tick={{ fill: "hsl(210 20% 50%)", fontSize: 10 }} />
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

      {/* ── Threat summary row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Detection Rate", value: `${phishPct + defacePct}%`, desc: "Malicious URL rate", color: COLORS.phishing },
          { label: "Total Malicious", value: totalMalicious.toLocaleString(), desc: "Phishing + Defacement", color: COLORS.phishing },
          { label: "Top Attack Country", value: `${stats.country_distribution[0].flag} ${stats.country_distribution[0].country}`, desc: `Risk score: ${stats.country_distribution[0].risk}`, color: COLORS.defacement },
          { label: "Top Keyword", value: `"${stats.top_keywords[0].keyword}"`, desc: `${stats.top_keywords[0].count.toLocaleString()} detections`, color: COLORS.defacement },
        ].map(item => (
          <div key={item.label} className="rounded-xl border border-border bg-gradient-card p-4">
            <div className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-2">{item.label}</div>
            <div className="text-xl font-bold font-mono" style={{ color: item.color }}>{item.value}</div>
            <div className="text-xs text-muted-foreground mt-1">{item.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
