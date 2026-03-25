import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Search, Loader2, AlertCircle, FileX2 } from 'lucide-react';
import { listPolicies } from '../../api/cspm';
import type { CspmPolicy } from '../../api/types';
import SeverityBadge from '../common/SeverityBadge';

export default function PolicyList() {
  const [search, setSearch] = useState('');
  const navigate = useNavigate();

  const { data: policies, isLoading, isError } = useQuery<CspmPolicy[]>({
    queryKey: ['cspm', 'policies'],
    queryFn: () => listPolicies().then((res) => res.data),
  });

  const filtered = useMemo(() => {
    if (!policies) return [];
    if (!search.trim()) return policies;
    const term = search.toLowerCase();
    return policies.filter(
      (p) =>
        p.name.toLowerCase().includes(term) ||
        p.description.toLowerCase().includes(term) ||
        (p.resource_types[0]?.resource_type ?? '').toLowerCase().includes(term),
    );
  }, [policies, search]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Loader2 size={32} className="mb-3 animate-spin text-[#ED1C24]" />
        <span className="text-sm">Loading policies...</span>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-red-400">
        <AlertCircle size={32} className="mb-3" />
        <span className="text-sm">Failed to load policies. Please try again.</span>
      </div>
    );
  }

  return (
    <div>
      {/* Search / Filter */}
      <div className="mb-4">
        <div className="relative">
          <Search
            size={16}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
          />
          <input
            type="text"
            placeholder="Search by name, description, or resource type..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-[#2e2b3a] bg-[#23202e] py-2 pl-9 pr-4 text-sm text-gray-200 placeholder-gray-500 outline-none transition-colors focus:border-[#ED1C24]/60"
          />
        </div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-gray-500">
          <FileX2 size={32} className="mb-3" />
          <span className="text-sm">
            {policies && policies.length > 0
              ? 'No policies match your search.'
              : 'No policies found.'}
          </span>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[#2e2b3a]">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-[#2e2b3a] bg-[#23202e]">
                <th className="px-4 py-3 font-medium text-gray-400">Name</th>
                <th className="px-4 py-3 font-medium text-gray-400">Resource Type</th>
                <th className="px-4 py-3 font-medium text-gray-400">Severity</th>
                <th className="px-4 py-3 font-medium text-gray-400">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2e2b3a]">
              {filtered.map((policy) => (
                <tr
                  key={policy.uuid}
                  onClick={() => navigate(`/cspm/${policy.uuid}`)}
                  className="cursor-pointer bg-[#171520] transition-colors hover:bg-[#23202e]"
                >
                  <td className="px-4 py-3 font-medium text-gray-200">{policy.name}</td>
                  <td className="px-4 py-3 text-gray-400">
                    {policy.resource_types[0]?.resource_type ?? '--'}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={policy.severity} />
                  </td>
                  <td className="px-4 py-3 text-gray-400">
                    {new Date(policy.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
