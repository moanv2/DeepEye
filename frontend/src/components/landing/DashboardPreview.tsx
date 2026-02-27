import { useInView } from "../../hooks/useInView";

const subdomains = [
  { name: "api.example.com", ip: "104.21.55.12", status: "alive" },
  { name: "staging.example.com", ip: "104.21.55.14", status: "alive" },
  { name: "mail.example.com", ip: "172.67.182.31", status: "alive" },
  { name: "dev.example.com", ip: "104.21.55.16", status: "dead" },
  { name: "cdn.example.com", ip: "13.225.103.88", status: "alive" },
  { name: "admin.example.com", ip: "104.21.55.20", status: "alive" },
];

const ports = [
  { port: 80, service: "HTTP", state: "open" },
  { port: 443, service: "HTTPS", state: "open" },
  { port: 22, service: "SSH", state: "open" },
  { port: 8080, service: "HTTP-Proxy", state: "open" },
];

export default function DashboardPreview() {
  const { ref, isInView } = useInView(0.1);

  return (
    <section id="dashboard-preview" className="py-24" ref={ref}>
      <div className="mx-auto max-w-7xl px-6">
        <div className="text-center mb-16 space-y-4">
          <h2 className="text-3xl sm:text-4xl font-bold">
            Your <span className="text-gradient-cyan">Command Center</span>
          </h2>
          <p className="text-muted max-w-2xl mx-auto">
            A powerful dashboard that puts your entire attack surface at your
            fingertips.
          </p>
        </div>

        {/* Browser frame */}
        <div
          className={`glass-strong rounded-2xl overflow-hidden shadow-2xl shadow-black/40 animate-float ${
            isInView ? "animate-fade-in-up" : "opacity-0"
          }`}
        >
          {/* Title bar */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] bg-white/[0.02]">
            <span className="h-3 w-3 rounded-full bg-red-500/70" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
            <span className="h-3 w-3 rounded-full bg-green-500/70" />
            <span className="ml-4 text-xs text-muted font-mono">
              deepeye — example.com
            </span>
          </div>

          {/* Dashboard content */}
          <div className="p-4 sm:p-6 space-y-4">
            {/* Top stats row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: "Subdomains", val: "6" },
                { label: "Alive Hosts", val: "5" },
                { label: "Open Ports", val: "4" },
                { label: "Threat Score", val: "72", accent: true },
              ].map((s) => (
                <div
                  key={s.label}
                  className="glass rounded-lg p-3 text-center"
                >
                  <p
                    className={`text-xl font-bold font-mono ${
                      s.accent ? "text-red-400" : "text-cyan-accent"
                    }`}
                  >
                    {s.val}
                  </p>
                  <p className="text-[10px] text-muted mt-1">{s.label}</p>
                </div>
              ))}
            </div>

            <div className="grid lg:grid-cols-3 gap-4">
              {/* Subdomains panel */}
              <div className="lg:col-span-2 glass rounded-lg p-4">
                <h4 className="text-xs font-semibold text-muted uppercase tracking-wide mb-3">
                  Discovered Subdomains
                </h4>
                <div className="space-y-1.5">
                  {subdomains.map((s) => (
                    <div
                      key={s.name}
                      className="flex items-center justify-between text-xs py-1.5 px-2 rounded hover:bg-white/[0.03]"
                    >
                      <span className="font-mono text-white">{s.name}</span>
                      <div className="flex items-center gap-3">
                        <span className="text-muted font-mono">{s.ip}</span>
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            s.status === "alive"
                              ? "bg-green-400"
                              : "bg-red-400"
                          }`}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right column */}
              <div className="space-y-4">
                {/* Domain info */}
                <div className="glass rounded-lg p-4">
                  <h4 className="text-xs font-semibold text-muted uppercase tracking-wide mb-3">
                    Domain Info
                  </h4>
                  <dl className="space-y-2 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-muted">Registrar</dt>
                      <dd className="font-mono text-white">Cloudflare Inc.</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-muted">Created</dt>
                      <dd className="font-mono text-white">2004-08-12</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-muted">Expires</dt>
                      <dd className="font-mono text-white">2026-08-12</dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-muted">ASN</dt>
                      <dd className="font-mono text-cyan-accent">
                        AS13335 — Cloudflare
                      </dd>
                    </div>
                  </dl>
                </div>

                {/* Ports */}
                <div className="glass rounded-lg p-4">
                  <h4 className="text-xs font-semibold text-muted uppercase tracking-wide mb-3">
                    Open Ports
                  </h4>
                  <div className="space-y-1.5">
                    {ports.map((p) => (
                      <div
                        key={p.port}
                        className="flex items-center justify-between text-xs"
                      >
                        <span className="font-mono text-cyan-accent">
                          :{p.port}
                        </span>
                        <span className="text-muted">{p.service}</span>
                        <span className="text-green-400 text-[10px] uppercase">
                          {p.state}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
