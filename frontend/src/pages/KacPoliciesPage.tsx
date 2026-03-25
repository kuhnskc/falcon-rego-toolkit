import { Link } from 'react-router-dom';
import { Plus } from 'lucide-react';
import KacPolicyList from '../components/kac/KacPolicyList';

export default function KacPoliciesPage() {
  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">KAC Policies</h1>
          <p className="mt-1 text-sm text-gray-400">
            Manage Kubernetes Admission Controller policies.
          </p>
        </div>
        <Link
          to="/kac/create"
          className="inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d]"
        >
          <Plus size={16} />
          Create Policy
        </Link>
      </div>

      <KacPolicyList />
    </div>
  );
}
