import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Loader2, AlertCircle, ShieldOff, CheckCircle, XCircle } from 'lucide-react';
import * as kacApi from '../../api/kac';
import type { KacPolicy } from '../../api/types';

export default function KacPolicyList() {
  const navigate = useNavigate();

  const { data: policies, isLoading, isError, error } = useQuery<KacPolicy[]>({
    queryKey: ['kac', 'policies'],
    queryFn: () => kacApi.listPolicies().then((res) => res.data),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={28} className="animate-spin text-gray-400" />
        <span className="ml-3 text-sm text-gray-400">Loading policies...</span>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center justify-center gap-2 py-20 text-red-400">
        <AlertCircle size={20} />
        <span className="text-sm">
          Failed to load policies{error instanceof Error ? `: ${error.message}` : ''}
        </span>
      </div>
    );
  }

  if (!policies || policies.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <ShieldOff size={40} className="mb-3 opacity-50" />
        <p className="text-sm">No KAC policies found.</p>
        <p className="mt-1 text-xs text-gray-500">
          Create a new policy to get started.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-[#2e2b3a]">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-[#2e2b3a] bg-[#23202e]">
            <th className="px-4 py-3 font-medium text-gray-400">Name</th>
            <th className="px-4 py-3 font-medium text-gray-400">Enabled</th>
            <th className="px-4 py-3 font-medium text-gray-400">Precedence</th>
            <th className="px-4 py-3 font-medium text-gray-400">Rule Groups</th>
          </tr>
        </thead>
        <tbody>
          {policies.map((policy) => (
            <tr
              key={policy.id}
              onClick={() => navigate(`/kac/${policy.id}`)}
              className="cursor-pointer border-b border-[#2e2b3a] bg-[#23202e]/50 transition-colors hover:bg-[#2e2b3a]/60"
            >
              <td className="px-4 py-3 font-medium text-gray-200">{policy.name}</td>
              <td className="px-4 py-3">
                {policy.is_enabled ? (
                  <CheckCircle size={18} className="text-green-400" />
                ) : (
                  <XCircle size={18} className="text-gray-500" />
                )}
              </td>
              <td className="px-4 py-3 text-gray-300">{policy.precedence}</td>
              <td className="px-4 py-3 text-gray-300">
                {policy.rule_groups?.length ?? 0}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
