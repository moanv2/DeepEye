import { Globe, Radar, Shield, Timer } from "lucide-react";
import { useInView } from "../../hooks/useInView";
import { useCountUp } from "../../hooks/useCountUp";

const stats = [
  { icon: Globe, label: "Domains Monitored", value: 1247, suffix: "" },
  { icon: Radar, label: "Subdomains Discovered", value: 53891, suffix: "" },
  { icon: Shield, label: "Vulnerabilities Detected", value: 3204, suffix: "" },
  { icon: Timer, label: "Avg. Scan Time", value: 4.2, suffix: "s", decimals: 1 },
];

export default function Stats() {
  const { ref, isInView } = useInView(0.3);

  return (
    <section ref={ref} className="py-12">
      <div className="mx-auto max-w-7xl px-6">
        <div className="glass-strong rounded-2xl p-6 grid grid-cols-2 lg:grid-cols-4 gap-6">
          {stats.map((s) => (
            <StatItem key={s.label} {...s} trigger={isInView} />
          ))}
        </div>
      </div>
    </section>
  );
}

function StatItem({
  icon: Icon,
  label,
  value,
  suffix,
  decimals = 0,
  trigger,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  suffix: string;
  decimals?: number;
  trigger: boolean;
}) {
  const count = useCountUp(value, 2, trigger, decimals);

  return (
    <div className="text-center space-y-2">
      <Icon className="h-5 w-5 mx-auto text-cyan-accent" />
      <p className="text-2xl sm:text-3xl font-bold font-mono text-white">
        {count.toLocaleString()}
        {suffix}
      </p>
      <p className="text-xs text-muted">{label}</p>
      <div className="mx-auto h-0.5 w-10 bg-gradient-to-r from-cyan-accent to-violet-accent rounded-full" />
    </div>
  );
}
