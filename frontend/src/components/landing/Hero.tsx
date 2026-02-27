import { lazy, Suspense } from "react";
import { Link } from "react-router-dom";
import { ChevronRight, ExternalLink } from "lucide-react";

const Globe = lazy(() => import("./Globe"));

export default function Hero() {
  return (
    <section className="relative min-h-screen flex items-center pt-16 overflow-hidden">
      {/* Background gradient */}
      <div
        className="absolute inset-0 -z-10"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% 40%, rgba(0,240,255,0.06) 0%, transparent 60%), radial-gradient(ellipse 60% 50% at 80% 50%, rgba(123,47,255,0.05) 0%, transparent 50%)",
        }}
      />

      <div className="mx-auto max-w-7xl px-6 w-full grid lg:grid-cols-5 gap-12 items-center">
        {/* Left — text (3 cols) */}
        <div className="lg:col-span-3 space-y-8">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 glass rounded-full px-4 py-1.5 text-xs font-medium text-cyan-accent shimmer-bg">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-accent animate-pulse" />
            v2.0 — Real-Time Attack Surface Monitoring
          </div>

          {/* Headline */}
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold leading-[1.1] tracking-tight">
            See Every{" "}
            <span className="text-gradient-cyan">Attack Surface.</span>
          </h1>

          {/* Subtitle */}
          <p className="text-muted text-lg max-w-xl leading-relaxed">
            DeepEye continuously maps your external attack surface — discovering
            subdomains, IPs, open ports, ASNs, and technologies before attackers
            do. Powered by real-time reconnaissance and Redis-backed
            intelligence.
          </p>

          {/* CTAs */}
          <div className="flex flex-wrap gap-4">
            <Link
              to="/dashboard"
              className="group inline-flex items-center gap-2 rounded-lg bg-cyan-accent px-6 py-3 text-sm font-semibold text-deep-dark hover:shadow-[0_0_30px_rgba(0,240,255,0.35)] transition-all"
            >
              Launch Dashboard
              <ChevronRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 glass rounded-lg px-6 py-3 text-sm font-medium text-white hover:bg-white/[0.06] transition-all"
            >
              View on GitHub
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>

          {/* Trust metrics */}
          <div className="flex flex-wrap gap-6 text-xs text-muted font-mono">
            <span>
              <span className="text-cyan-accent font-semibold">1,200+</span>{" "}
              Domains Scanned
            </span>
            <span>
              <span className="text-cyan-accent font-semibold">50K+</span>{" "}
              Subdomains Found
            </span>
            <span>
              <span className="text-cyan-accent font-semibold">Real-Time</span>{" "}
              Monitoring
            </span>
          </div>
        </div>

        {/* Right — Globe (2 cols) */}
        <div className="lg:col-span-2 h-[350px] sm:h-[450px] lg:h-[520px]">
          <Suspense fallback={<div className="w-full h-full" />}>
            <Globe />
          </Suspense>
        </div>
      </div>
    </section>
  );
}
