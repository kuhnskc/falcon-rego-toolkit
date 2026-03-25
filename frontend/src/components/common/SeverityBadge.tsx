import { SEVERITY_MAP } from '../../api/types';

interface SeverityBadgeProps {
  severity: number;
}

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const info = SEVERITY_MAP[severity] ?? { label: 'Unknown', color: '#6b7280' };

  const colorClasses: Record<number, string> = {
    0: 'bg-red-500/20 text-red-400 border-red-500/40',
    1: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    2: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    3: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  };

  const classes = colorClasses[severity] ?? 'bg-gray-500/20 text-gray-400 border-gray-500/40';

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${classes}`}
    >
      {info.label}
    </span>
  );
}
