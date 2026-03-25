import { Link } from 'react-router-dom';
import { ChevronLeft } from 'lucide-react';
import PolicyCreateWizard from '../components/cspm/PolicyCreateWizard';

export default function CspmCreatePolicyPage() {
  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <div className="mb-6">
        <Link
          to="/cspm"
          className="mb-3 inline-flex items-center gap-1 text-sm text-gray-400 transition-colors hover:text-gray-200"
        >
          <ChevronLeft size={16} />
          Back to policies
        </Link>
        <h1 className="text-2xl font-bold text-gray-100">Create CSPM IOM Policy</h1>
        <p className="mt-1 text-sm text-gray-400">
          Follow the wizard to define and test a new custom IOM policy.
        </p>
      </div>

      <PolicyCreateWizard />
    </div>
  );
}
