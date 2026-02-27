import { useEffect, useState, useCallback } from "react";
import { getScans } from "../api/client";
import type { Scan, ScanResponse } from "../types";
import ScanForm from "../components/ScanForm";
import ScanList from "../components/ScanList";

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const data = await getScans();
      setScans(data);
    } catch {
      // silently fail — list stays empty
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  function handleScanComplete(_scan: ScanResponse) {
    fetchScans();
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-400">
          Start a new scan or view past results.
        </p>
      </div>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300 uppercase tracking-wide">
          New Scan
        </h2>
        <ScanForm onScanComplete={handleScanComplete} />
      </section>

      <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        <h2 className="mb-3 text-sm font-semibold text-gray-300 uppercase tracking-wide">
          Scan History
        </h2>
        <ScanList scans={scans} loading={loading} />
      </section>
    </div>
  );
}
