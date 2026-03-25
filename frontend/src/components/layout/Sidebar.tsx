import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Cloud, Container } from 'lucide-react';

const links = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/cspm', label: 'CSPM IOM', icon: Cloud },
  { to: '/kac', label: 'KAC', icon: Container },
] as const;

export default function Sidebar() {
  return (
    <aside className="flex w-[220px] shrink-0 flex-col border-r border-[#2e2b3a] bg-[#23202e]">
      <nav className="flex flex-col gap-1 p-3">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-[#ED1C24]/10 text-[#ED1C24]'
                  : 'text-gray-400 hover:bg-[#2e2b3a] hover:text-white'
              }`
            }
          >
            <Icon className="h-4.5 w-4.5" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
