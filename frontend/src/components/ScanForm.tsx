import { useState } from "react";
import { startScan } from "../api/client";
import type { ScanResponse } from "../types";

interface ScanFormProps {
  onScanComplete: (scan: ScanResponse) => void;
}

export default function ScanForm({ onScanComplete }: ScanFormProps) {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const scan = await startScan(domain.trim());
      onScanComplete(scan);
      setDomain("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-3 items-start">
      <div className="flex-1">
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter domain (e.g. example.com)"
          disabled={loading}
          className="w-full rounded-md border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
        />
        {error && <p className="mt-1 text-sm text-red-400">{error}</p>}
      </div>
      <button
        type="submit"
        disabled={loading || !domain.trim()}
        className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? "Scanning..." : "Start Scan"}
      </button>
    </form>
  );
}
