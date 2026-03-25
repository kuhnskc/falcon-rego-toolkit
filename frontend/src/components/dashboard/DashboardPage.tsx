import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Cloud, Container, ArrowRight, Loader2, AlertCircle } from 'lucide-react';
import { listPolicies as listCspmPolicies } from '../../api/cspm';
import { listPolicies as listKacPolicies } from '../../api/kac';

export default function DashboardPage() {
  const cspmQuery = useQuery({
    queryKey: ['cspm', 'policies'],
    queryFn: () => listCspmPolicies().then((res) => res.data),
  });

  const kacQuery = useQuery({
    queryKey: ['kac', 'policies'],
    queryFn: () => listKacPolicies().then((res) => res.data),
  });

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-100">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-400">
          Overview of your CrowdStrike policy inventory.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        {/* CSPM IOM Policies Card */}
        <StatCard
          icon={<Cloud size={28} className="text-[#ED1C24]" />}
          title="CSPM IOM Policies"
          count={Array.isArray(cspmQuery.data) ? cspmQuery.data.length : undefined}
          isLoading={cspmQuery.isLoading}
          isError={cspmQuery.isError}
          linkTo="/cspm"
          linkLabel="View Policies"
        />

        {/* KAC Policies Card */}
        <StatCard
          icon={<Container size={28} className="text-[#ED1C24]" />}
          title="KAC Policies"
          count={Array.isArray(kacQuery.data) ? kacQuery.data.length : undefined}
          isLoading={kacQuery.isLoading}
          isError={kacQuery.isError}
          linkTo="/kac"
          linkLabel="View Policies"
        />
      </div>
    </div>
  );
}

interface StatCardProps {
  icon: React.ReactNode;
  title: string;
  count: number | undefined;
  isLoading: boolean;
  isError: boolean;
  linkTo: string;
  linkLabel: string;
}

function StatCard({
  icon,
  title,
  count,
  isLoading,
  isError,
  linkTo,
  linkLabel,
}: StatCardProps) {
  return (
    <div className="group rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6 transition-all duration-200 hover:border-[#ED1C24]/40 hover:shadow-lg hover:shadow-[#ED1C24]/5">
      <div className="mb-4 flex items-center gap-3">
        <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-[#ED1C24]/10">
          {icon}
        </div>
        <h2 className="text-base font-semibold text-gray-200">{title}</h2>
      </div>

      <div className="mb-5">
        {isLoading && (
          <div className="flex items-center gap-2 text-gray-400">
            <Loader2 size={20} className="animate-spin" />
            <span className="text-sm">Loading...</span>
          </div>
        )}
        {isError && (
          <div className="flex items-center gap-2 text-red-400">
            <AlertCircle size={20} />
            <span className="text-sm">Failed to load</span>
          </div>
        )}
        {!isLoading && !isError && count !== undefined && (
          <span className="text-4xl font-bold tracking-tight text-gray-100">
            {count}
          </span>
        )}
      </div>

      <Link
        to={linkTo}
        className="inline-flex items-center gap-1.5 text-sm font-medium text-[#ED1C24] transition-colors hover:text-[#ff3d45] group-hover:underline"
      >
        {linkLabel}
        <ArrowRight size={16} className="transition-transform group-hover:translate-x-0.5" />
      </Link>
    </div>
  );
}
