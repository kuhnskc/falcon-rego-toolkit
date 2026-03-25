import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import KacPolicyCreate from '../components/kac/KacPolicyCreate';

export default function KacCreatePolicyPage() {
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

      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-100">Create KAC Policy</h1>
        <p className="mt-1 text-sm text-gray-400">
          Define a new Kubernetes Admission Controller policy.
        </p>
      </div>

      <KacPolicyCreate />
    </div>
  );
}
