import type { SubdomainResponse } from "../types";

interface SubdomainTableProps {
  subdomains: SubdomainResponse[];
  loading: boolean;
}

function hostStatusLabel(status: number) {
  switch (status) {
    case 1:
      return <span className="text-green-400">Alive</span>;
    case 0:
      return <span className="text-red-400">Dead</span>;
    default:
      return <span className="text-gray-500">Unknown</span>;
  }
}

export default function SubdomainTable({
  subdomains,
  loading,
}: SubdomainTableProps) {
  if (loading) {
    return <p className="text-gray-400 text-sm">Loading subdomains...</p>;
  }

  if (subdomains.length === 0) {
    return <p className="text-gray-500 text-sm">No subdomains found.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-gray-700 text-gray-400">
          <tr>
            <th className="pb-2 pr-4 font-medium">#</th>
            <th className="pb-2 pr-4 font-medium">Subdomain</th>
            <th className="pb-2 pr-4 font-medium">IP Address</th>
            <th className="pb-2 pr-4 font-medium">Status</th>
            <th className="pb-2 pr-4 font-medium">ASN</th>
            <th className="pb-2 font-medium">Organization</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {subdomains.map((sub) => (
            <tr key={sub.id} className="hover:bg-gray-800/50">
              <td className="py-2 pr-4 text-gray-500">{sub.row_num}</td>
              <td className="py-2 pr-4 font-mono text-xs">{sub.subdomain}</td>
              <td className="py-2 pr-4 font-mono text-xs">
                {sub.ip_address ?? "-"}
              </td>
              <td className="py-2 pr-4">{hostStatusLabel(sub.host_status)}</td>
              <td className="py-2 pr-4">{sub.asn ?? "-"}</td>
              <td className="py-2">{sub.asn_org ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
