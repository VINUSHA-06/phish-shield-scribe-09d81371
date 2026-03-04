import { cn } from "@/lib/utils";

interface ThreatBadgeProps {
  prediction: "benign" | "phishing" | "defacement";
  confidence?: number;
  size?: "sm" | "md" | "lg";
}

const CONFIG = {
  benign: {
    label: "BENIGN",
    bg: "bg-safe/10",
    border: "border-safe/30",
    text: "text-safe",
    dot: "bg-safe",
    glow: "shadow-[0_0_12px_hsl(142_70%_45%/0.4)]",
  },
  phishing: {
    label: "PHISHING",
    bg: "bg-danger/10",
    border: "border-danger/30",
    text: "text-danger",
    dot: "bg-danger",
    glow: "shadow-[0_0_12px_hsl(0_75%_58%/0.4)]",
  },
  defacement: {
    label: "DEFACEMENT",
    bg: "bg-warning/10",
    border: "border-warning/30",
    text: "text-warning",
    dot: "bg-warning",
    glow: "shadow-[0_0_12px_hsl(45_95%_55%/0.4)]",
  },
};

export function ThreatBadge({ prediction, confidence, size = "md" }: ThreatBadgeProps) {
  const c = CONFIG[prediction];
  const sizeClass = size === "lg" ? "px-4 py-2 text-base" : size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-1.5 text-sm";

  return (
    <span className={cn(
      "inline-flex items-center gap-2 rounded-full border font-mono font-semibold tracking-wider",
      sizeClass, c.bg, c.border, c.text, c.glow
    )}>
      <span className={cn("w-2 h-2 rounded-full animate-pulse", c.dot)} />
      {c.label}
      {confidence !== undefined && (
        <span className="text-muted-foreground text-xs">
          {(confidence * 100).toFixed(1)}%
        </span>
      )}
    </span>
  );
}
