import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, Loader2, AlertCircle } from 'lucide-react';
import { listPolicies } from '../api/cspm';
import type { CspmPolicy } from '../api/types';
import PolicyDetail from '../components/cspm/PolicyDetail';

export default function CspmPolicyDetailPage() {
  const { uuid } = useParams<{ uuid: string }>();

  const { data: policies, isLoading, isError } = useQuery<CspmPolicy[]>({
    queryKey: ['cspm', 'policies'],
    queryFn: () => listPolicies().then((res) => res.data),
  });

  const policy = policies?.find((p) => p.uuid === uuid);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Loader2 size={32} className="mb-3 animate-spin text-[#ED1C24]" />
        <span className="text-sm">Loading policy...</span>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-red-400">
        <AlertCircle size={32} className="mb-3" />
        <span className="text-sm">Failed to load policy. Please try again.</span>
      </div>
    );
  }

  if (!policy) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-10">
        <div className="flex flex-col items-center justify-center py-16 text-gray-500">
          <AlertCircle size={32} className="mb-3" />
          <span className="text-sm">Policy not found.</span>
          <Link
            to="/cspm"
            className="mt-4 text-sm text-[#ED1C24] hover:underline"
          >
            Back to policies
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      {/* Back link & header */}
      <div className="mb-6">
        <Link
          to="/cspm"
          className="mb-3 inline-flex items-center gap-1 text-sm text-gray-400 transition-colors hover:text-gray-200"
        >
          <ChevronLeft size={16} />
          Back to policies
        </Link>
        <h1 className="text-2xl font-bold text-gray-100">{policy.name}</h1>
      </div>

      <PolicyDetail policy={policy} />
    </div>
  );
}
