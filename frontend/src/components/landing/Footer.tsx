import { Eye, Github, Linkedin, Twitter } from "lucide-react";

export default function Footer() {
  return (
    <footer className="glass border-t border-white/[0.06]">
      <div className="mx-auto max-w-7xl px-6 py-10">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Eye className="h-5 w-5 text-cyan-accent" />
            <span className="text-sm font-semibold text-white">
              Deep<span className="text-cyan-accent">Eye</span>
            </span>
            <span className="text-xs text-muted ml-2">
              &copy; {new Date().getFullYear()} DeepEye. Open-source
              reconnaissance intelligence.
            </span>
          </div>

          {/* Links */}
          <div className="flex items-center gap-6 text-xs text-muted">
            <a href="#features" className="hover:text-white transition-colors">
              Features
            </a>
            <a
              href="#how-it-works"
              className="hover:text-white transition-colors"
            >
              How It Works
            </a>
            <a
              href="#dashboard-preview"
              className="hover:text-white transition-colors"
            >
              Preview
            </a>
          </div>

          {/* Socials */}
          <div className="flex items-center gap-4">
            {[Github, Twitter, Linkedin].map((Icon, i) => (
              <a
                key={i}
                href="#"
                className="text-muted hover:text-white transition-colors"
              >
                <Icon className="h-4 w-4" />
              </a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
