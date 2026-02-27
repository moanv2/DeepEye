import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Eye } from "lucide-react";

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled ? "glass-strong shadow-lg shadow-black/30" : "bg-transparent"
      }`}
    >
      <div className="mx-auto max-w-7xl px-6 flex h-16 items-center justify-between">
        <a href="#" className="flex items-center gap-2 group">
          <Eye
            className="h-6 w-6 text-cyan-accent animate-pulse-glow"
            strokeWidth={2.5}
          />
          <span className="text-lg font-bold text-white tracking-tight">
            Deep<span className="text-cyan-accent">Eye</span>
          </span>
        </a>

        <div className="hidden md:flex items-center gap-8 text-sm">
          <a
            href="#features"
            className="text-muted hover:text-white transition-colors"
          >
            Features
          </a>
          <a
            href="#how-it-works"
            className="text-muted hover:text-white transition-colors"
          >
            How It Works
          </a>
          <a
            href="#dashboard-preview"
            className="text-muted hover:text-white transition-colors"
          >
            Dashboard Preview
          </a>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted hover:text-white transition-colors"
          >
            GitHub
          </a>
          <Link
            to="/dashboard"
            className="rounded-lg bg-cyan-accent/10 border border-cyan-accent/30 px-4 py-2 text-cyan-accent font-medium hover:bg-cyan-accent/20 hover:shadow-[0_0_20px_rgba(0,240,255,0.2)] transition-all"
          >
            Start Scanning
          </Link>
        </div>
      </div>
    </nav>
  );
}
