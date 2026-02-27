import type { EndpointResponse } from "../types";

interface EndpointTableProps {
  endpoints: EndpointResponse[];
  loading: boolean;
}

export default function EndpointTable({
  endpoints,
  loading,
}: EndpointTableProps) {
  if (loading) {
    return <p className="text-gray-400 text-sm">Loading endpoints...</p>;
  }

  if (endpoints.length === 0) {
    return <p className="text-gray-500 text-sm">No endpoints found.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-gray-700 text-gray-400">
          <tr>
            <th className="pb-2 pr-4 font-medium">#</th>
            <th className="pb-2 pr-4 font-medium">URL</th>
            <th className="pb-2 pr-4 font-medium">Method</th>
            <th className="pb-2 pr-4 font-medium">Status</th>
            <th className="pb-2 font-medium">Sensitive</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {endpoints.map((ep) => (
            <tr
              key={ep.id}
              className={
                ep.is_sensitive
                  ? "bg-red-950/30 hover:bg-red-950/50"
                  : "hover:bg-gray-800/50"
              }
            >
              <td className="py-2 pr-4 text-gray-500">{ep.row_num}</td>
              <td className="py-2 pr-4 font-mono text-xs max-w-md truncate">
                {ep.url}
              </td>
              <td className="py-2 pr-4">{ep.method}</td>
              <td className="py-2 pr-4">{ep.status_code ?? "-"}</td>
              <td className="py-2">
                {ep.is_sensitive ? (
                  <span className="rounded-full bg-red-900 px-2 py-0.5 text-xs text-red-300">
                    {ep.sensitivity_reason}
                  </span>
                ) : (
                  "-"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
