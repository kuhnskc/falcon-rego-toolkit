import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Loader2, AlertCircle } from 'lucide-react';
import * as kacApi from '../api/kac';
import type { KacPolicy } from '../api/types';
import KacPolicyDetail from '../components/kac/KacPolicyDetail';

export default function KacPolicyDetailPage() {
  const { id } = useParams<{ id: string }>();

  const {
    data: policy,
    isLoading,
    isError,
    error,
  } = useQuery<KacPolicy>({
    queryKey: ['kac', 'policy', id],
    queryFn: () => kacApi.getPolicy(id!).then((res) => res.data),
    enabled: !!id,
  });

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      {/* Back link */}
      <Link
        to="/kac"
        className="mb-6 inline-flex items-center gap-1.5 text-sm text-gray-400 transition-colors hover:text-gray-200"
      >
        <ArrowLeft size={16} />
        Back to KAC Policies
      </Link>

      {isLoading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 size={28} className="animate-spin text-gray-400" />
          <span className="ml-3 text-sm text-gray-400">Loading policy...</span>
        </div>
      )}

      {isError && (
        <div className="flex items-center justify-center gap-2 py-20 text-red-400">
          <AlertCircle size={20} />
          <span className="text-sm">
            Failed to load policy{error instanceof Error ? `: ${error.message}` : ''}
          </span>
        </div>
      )}

      {policy && <KacPolicyDetail policy={policy} />}
    </div>
  );
}
