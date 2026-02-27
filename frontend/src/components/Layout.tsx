import { Link, Outlet } from "react-router-dom";
import { Eye } from "lucide-react";

export default function Layout() {
  return (
    <div className="min-h-screen bg-deep-dark text-gray-100">
      <nav className="border-b border-white/[0.06] glass-strong">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-14 items-center justify-between">
            <Link to="/" className="flex items-center gap-2">
              <Eye className="h-5 w-5 text-cyan-accent" />
              <span className="text-lg font-bold text-white">
                Deep<span className="text-cyan-accent">Eye</span>
              </span>
            </Link>
            <div className="flex gap-4 text-sm">
              <Link
                to="/"
                className="text-muted hover:text-white transition-colors"
              >
                Home
              </Link>
              <Link
                to="/dashboard"
                className="text-muted hover:text-white transition-colors"
              >
                Dashboard
              </Link>
            </div>
          </div>
        </div>
      </nav>
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  );
}
