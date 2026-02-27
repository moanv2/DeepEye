import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getSubdomains, getEndpoints, getSensitiveEndpoints } from "../api/client";
import type { SubdomainResponse, EndpointResponse, SensitiveEndpoint } from "../types";
import SubdomainTable from "../components/SubdomainTable";
import EndpointTable from "../components/EndpointTable";

type Tab = "subdomains" | "endpoints" | "sensitive";

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const [tab, setTab] = useState<Tab>("subdomains");

  const [subdomains, setSubdomains] = useState<SubdomainResponse[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointResponse[]>([]);
  const [sensitive, setSensitive] = useState<SensitiveEndpoint[]>([]);

  const [loadingSub, setLoadingSub] = useState(true);
  const [loadingEp, setLoadingEp] = useState(true);
  const [loadingSens, setLoadingSens] = useState(true);

  useEffect(() => {
    if (!scanId) return;

    getSubdomains(scanId)
      .then(setSubdomains)
      .catch(() => {})
      .finally(() => setLoadingSub(false));

    getEndpoints(scanId)
      .then(setEndpoints)
      .catch(() => {})
      .finally(() => setLoadingEp(false));

    getSensitiveEndpoints(scanId)
      .then(setSensitive)
      .catch(() => {})
      .finally(() => setLoadingSens(false));
  }, [scanId]);

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "subdomains", label: "Subdomains", count: subdomains.length },
    { key: "endpoints", label: "Endpoints", count: endpoints.length },
    { key: "sensitive", label: "Sensitive", count: sensitive.length },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          to="/"
          className="text-sm text-gray-400 hover:text-gray-200 transition-colors"
        >
          &larr; Back
        </Link>
        <h1 className="text-2xl font-bold">Scan {scanId?.slice(0, 8)}...</h1>
      </div>

      <div className="flex gap-1 border-b border-gray-800">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === t.key
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t.label}
            <span className="ml-1.5 text-xs text-gray-500">({t.count})</span>
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
        {tab === "subdomains" && (
          <SubdomainTable subdomains={subdomains} loading={loadingSub} />
        )}

        {tab === "endpoints" && (
          <EndpointTable endpoints={endpoints} loading={loadingEp} />
        )}

        {tab === "sensitive" && (
          <SensitiveTab sensitive={sensitive} loading={loadingSens} />
        )}
      </div>
    </div>
  );
}

function SensitiveTab({
  sensitive,
  loading,
}: {
  sensitive: SensitiveEndpoint[];
  loading: boolean;
}) {
  if (loading) {
    return <p className="text-gray-400 text-sm">Loading...</p>;
  }

  if (sensitive.length === 0) {
    return <p className="text-gray-500 text-sm">No sensitive endpoints found.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-gray-700 text-gray-400">
          <tr>
            <th className="pb-2 pr-4 font-medium">URL</th>
            <th className="pb-2 pr-4 font-medium">Path</th>
            <th className="pb-2 pr-4 font-medium">Reason</th>
            <th className="pb-2 font-medium">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {sensitive.map((ep, i) => (
            <tr key={i} className="hover:bg-red-950/30">
              <td className="py-2 pr-4 font-mono text-xs max-w-md truncate">
                {ep.url}
              </td>
              <td className="py-2 pr-4 font-mono text-xs">{ep.path ?? "-"}</td>
              <td className="py-2 pr-4">
                <span className="rounded-full bg-red-900 px-2 py-0.5 text-xs text-red-300">
                  {ep.reason}
                </span>
              </td>
              <td className="py-2">{ep.status_code ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
