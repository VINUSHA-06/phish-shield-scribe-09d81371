import { Shield, ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

interface RiskMeterProps {
  score: number;
  category: "Safe" | "Suspicious" | "High Risk";
  size?: "sm" | "md" | "lg";
}

export function RiskMeter({ score, category, size = "md" }: RiskMeterProps) {
  const color = category === "Safe" ? "safe" : category === "Suspicious" ? "warning" : "danger";
  const Icon = category === "Safe" ? ShieldCheck : category === "Suspicious" ? AlertTriangle : ShieldAlert;

  const sizeClasses = {
    sm: { container: "w-24 h-24", text: "text-xl", label: "text-xs" },
    md: { container: "w-36 h-36", text: "text-3xl", label: "text-sm" },
    lg: { container: "w-48 h-48", text: "text-5xl", label: "text-base" },
  };

  const s = sizeClasses[size];
  const strokeColor = category === "Safe" ? "#22c55e" : category === "Suspicious" ? "#eab308" : "#ef4444";

  // SVG arc calculation
  const radius = size === "lg" ? 80 : size === "md" ? 60 : 38;
  const cx = size === "lg" ? 96 : size === "md" ? 72 : 48;
  const cy = cx;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference * 0.75; // 270 degrees
  const strokeDashoffset = circumference * 0.75 - progress;

  return (
    <div className={cn("relative flex items-center justify-center", s.container)}>
      <svg className="absolute inset-0 -rotate-[135deg]" viewBox={`0 0 ${cx * 2} ${cy * 2}`}>
        {/* Background track */}
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth="8"
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
          strokeLinecap="round"
        />
        {/* Progress */}
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="8"
          strokeDasharray={`${progress} ${circumference - progress}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${strokeColor})` }}
        />
      </svg>
      <div className="relative z-10 flex flex-col items-center gap-1">
        <Icon
          className={cn(
            "mb-1",
            size === "lg" ? "w-8 h-8" : size === "md" ? "w-6 h-6" : "w-4 h-4",
            color === "safe" ? "text-safe" : color === "warning" ? "text-warning" : "text-danger"
          )}
        />
        <span className={cn("font-bold font-mono", s.text,
          color === "safe" ? "text-safe" : color === "warning" ? "text-warning" : "text-danger"
        )}>
          {score}
        </span>
        <span className={cn("font-semibold", s.label,
          color === "safe" ? "text-safe" : color === "warning" ? "text-warning" : "text-danger"
        )}>
          {category}
        </span>
      </div>
    </div>
  );
}
