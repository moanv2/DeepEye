import { Search, Globe, Radar, Database, Server, Monitor } from "lucide-react";
import { useInView } from "../../hooks/useInView";

const steps = [
  { icon: Search, label: "Input Domain" },
  { icon: Globe, label: "DNS Enumeration" },
  { icon: Radar, label: "Port & Service Scan" },
  { icon: Database, label: "Data Enrichment" },
  { icon: Server, label: "Redis Storage" },
  { icon: Monitor, label: "Dashboard" },
];

export default function Pipeline() {
  const { ref, isInView } = useInView(0.15);

  return (
    <section id="how-it-works" className="py-24" ref={ref}>
      <div className="mx-auto max-w-7xl px-6">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-3xl sm:text-4xl font-bold">
            From Domain to Intelligence{" "}
            <span className="text-gradient-cyan">in Seconds</span>
          </h2>
          <p className="text-muted max-w-2xl mx-auto">
            Our automated pipeline takes a domain and delivers actionable
            reconnaissance data through six streamlined stages.
          </p>
        </div>

        {/* Desktop horizontal pipeline */}
        <div className="hidden lg:flex items-center justify-between gap-2">
          {steps.map((s, i) => (
            <div key={s.label} className="flex items-center flex-1">
              <div
                className={`flex flex-col items-center gap-3 ${
                  isInView ? "animate-fade-in-up" : "opacity-0"
                }`}
                style={{ animationDelay: `${i * 150}ms` }}
              >
                <div className="glass rounded-xl h-20 w-20 flex items-center justify-center group hover:border-cyan-accent/40 hover:shadow-[0_0_20px_rgba(0,240,255,0.12)] transition-all">
                  <s.icon className="h-8 w-8 text-cyan-accent" />
                </div>
                <span className="text-xs font-medium text-muted text-center whitespace-nowrap">
                  {s.label}
                </span>
              </div>

              {i < steps.length - 1 && (
                <div className="flex-1 mx-3 relative h-[2px]">
                  <div className="absolute inset-0 border-t-2 border-dashed border-white/10" />
                  {isInView && (
                    <span
                      className="absolute top-1/2 -translate-y-1/2 h-2 w-2 rounded-full bg-cyan-accent shadow-[0_0_8px_rgba(0,240,255,0.8)]"
                      style={{
                        animation: `flow-dot 2s ${0.3 * i}s linear infinite`,
                      }}
                    />
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Mobile vertical pipeline */}
        <div className="lg:hidden space-y-6">
          {steps.map((s, i) => (
            <div key={s.label} className="flex items-center gap-4">
              <div
                className={`glass rounded-xl h-14 w-14 flex-shrink-0 flex items-center justify-center ${
                  isInView ? "animate-fade-in-up" : "opacity-0"
                }`}
                style={{ animationDelay: `${i * 120}ms` }}
              >
                <s.icon className="h-6 w-6 text-cyan-accent" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">{s.label}</p>
                <p className="text-xs text-muted">Step {i + 1}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
