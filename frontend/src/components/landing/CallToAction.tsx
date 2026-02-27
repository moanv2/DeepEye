import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";

export default function CallToAction() {
  return (
    <section className="py-32 relative">
      {/* Background glow */}
      <div
        className="absolute inset-0 -z-10"
        style={{
          background:
            "radial-gradient(ellipse 50% 50% at 50% 50%, rgba(0,240,255,0.08) 0%, transparent 70%)",
        }}
      />

      <div className="mx-auto max-w-3xl px-6 text-center space-y-6">
        <h2 className="text-3xl sm:text-5xl font-bold leading-tight">
          Ready to Map Your{" "}
          <span className="text-gradient-cyan">Attack Surface?</span>
        </h2>
        <p className="text-muted text-lg max-w-xl mx-auto">
          Deploy DeepEye and gain full visibility into your external
          infrastructure.
        </p>
        <div className="pt-4">
          <Link
            to="/dashboard"
            className="gradient-border inline-flex items-center gap-2 rounded-xl bg-deep-dark px-8 py-4 text-base font-semibold text-white hover:shadow-[0_0_40px_rgba(0,240,255,0.2)] transition-shadow"
          >
            Get Started
            <ChevronRight className="h-5 w-5" />
          </Link>
        </div>
      </div>
    </section>
  );
}
