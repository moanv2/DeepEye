import {
  Globe,
  Server,
  Wifi,
  Monitor,
  Radar,
  Shield,
} from "lucide-react";
import { useInView } from "../../hooks/useInView";

const features = [
  {
    icon: Globe,
    title: "Subdomain Discovery",
    desc: "Enumerate all subdomains using passive and active techniques including certificate transparency, DNS brute-forcing, and web crawling.",
  },
  {
    icon: Server,
    title: "ASN & IP Mapping",
    desc: "Map complete network infrastructure with ASN ownership, IP ranges, geolocation, and reverse DNS lookups.",
  },
  {
    icon: Wifi,
    title: "Port Scanning",
    desc: "Identify open ports and running services across discovered hosts with configurable scan profiles.",
  },
  {
    icon: Monitor,
    title: "Technology Fingerprinting",
    desc: "Detect web technologies, frameworks, CDNs, and server software powering each asset.",
  },
  {
    icon: Radar,
    title: "Real-Time Monitoring",
    desc: "Continuous scanning with Redis-powered data pipeline for instant change detection and alerting.",
  },
  {
    icon: Shield,
    title: "Attack Surface Scoring",
    desc: "Quantified risk scoring based on exposure metrics, outdated software, and misconfiguration signals.",
  },
];

export default function Features() {
  const { ref, isInView } = useInView(0.1);

  return (
    <section id="features" className="py-24" ref={ref}>
      <div className="mx-auto max-w-7xl px-6">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-3xl sm:text-4xl font-bold">
            Reconnaissance <span className="text-gradient-cyan">Intelligence</span>
          </h2>
          <p className="text-muted max-w-2xl mx-auto">
            Everything you need to discover, map, and monitor your external
            attack surface in one platform.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f, i) => (
            <div
              key={f.title}
              className={`glass rounded-xl p-6 space-y-4 group hover:-translate-y-1 hover:border-cyan-accent/30 hover:shadow-[0_0_30px_rgba(0,240,255,0.08)] transition-all duration-300 ${
                isInView ? "animate-fade-in-up" : "opacity-0"
              }`}
              style={{ animationDelay: `${i * 100}ms` }}
            >
              <div className="inline-flex items-center justify-center h-10 w-10 rounded-lg bg-cyan-accent/10 text-cyan-accent group-hover:animate-pulse-glow transition-all">
                <f.icon className="h-5 w-5" />
              </div>
              <h3 className="text-lg font-semibold text-white">{f.title}</h3>
              <p className="text-sm text-muted leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
