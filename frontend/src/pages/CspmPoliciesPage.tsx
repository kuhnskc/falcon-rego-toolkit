import { Link } from 'react-router-dom';
import { Plus } from 'lucide-react';
import PolicyList from '../components/cspm/PolicyList';

export default function CspmPoliciesPage() {
  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">CSPM IOM Policies</h1>
          <p className="mt-1 text-sm text-gray-400">
            Manage your cloud security posture management policies.
          </p>
        </div>
        <Link
          to="/cspm/create"
          className="inline-flex items-center gap-1.5 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d]"
        >
          <Plus size={16} />
          Create Policy
        </Link>
      </div>

      <PolicyList />
    </div>
  );
}
