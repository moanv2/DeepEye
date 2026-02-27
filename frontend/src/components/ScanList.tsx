import { Link } from "react-router-dom";
import type { Scan } from "../types";

interface ScanListProps {
  scans: Scan[];
  loading: boolean;
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    completed: "bg-green-900 text-green-300",
    running: "bg-yellow-900 text-yellow-300",
    pending: "bg-gray-700 text-gray-300",
    failed: "bg-red-900 text-red-300",
  };
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${colors[status] ?? colors.pending}`}
    >
      {status}
    </span>
  );
}

export default function ScanList({ scans, loading }: ScanListProps) {
  if (loading) {
    return <p className="text-gray-400 text-sm">Loading scans...</p>;
  }

  if (scans.length === 0) {
    return (
      <p className="text-gray-500 text-sm">
        No scans yet. Start one above.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-gray-700 text-gray-400">
          <tr>
            <th className="pb-2 pr-4 font-medium">Domain</th>
            <th className="pb-2 pr-4 font-medium">Status</th>
            <th className="pb-2 pr-4 font-medium">Subdomains</th>
            <th className="pb-2 pr-4 font-medium">Endpoints</th>
            <th className="pb-2 pr-4 font-medium">Sensitive</th>
            <th className="pb-2 font-medium">Created</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {scans.map((scan) => (
            <tr key={scan.id} className="hover:bg-gray-800/50">
              <td className="py-2 pr-4">
                <Link
                  to={`/scan/${scan.id}`}
                  className="text-indigo-400 hover:text-indigo-300"
                >
                  {scan.domain}
                </Link>
              </td>
              <td className="py-2 pr-4">{statusBadge(scan.status)}</td>
              <td className="py-2 pr-4">{scan.subdomains_count}</td>
              <td className="py-2 pr-4">{scan.endpoints_count}</td>
              <td className="py-2 pr-4">
                {scan.sensitive_count > 0 ? (
                  <span className="text-red-400">{scan.sensitive_count}</span>
                ) : (
                  0
                )}
              </td>
              <td className="py-2 text-gray-400">
                {new Date(scan.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
