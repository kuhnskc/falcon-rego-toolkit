import { Shield, LogOut } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

export default function Header() {
  const { cloud_environment, logout } = useAuth();

  return (
    <header className="border-t-2 border-t-[#ED1C24] bg-[#23202e]">
      <div className="flex items-center justify-between px-5 py-3">
        {/* Left: Brand */}
        <div className="flex items-center gap-2.5">
          <Shield className="h-6 w-6 text-[#ED1C24]" />
          <span className="text-lg font-semibold tracking-wide text-white">
            Falcon Rego Toolkit
          </span>
        </div>

        {/* Right: Cloud env + logout */}
        <div className="flex items-center gap-4">
          {cloud_environment && (
            <span className="rounded bg-[#2e2b3a] px-3 py-1 text-sm text-gray-300">
              {cloud_environment}
            </span>
          )}
          <button
            onClick={logout}
            className="flex items-center gap-1.5 rounded px-3 py-1.5 text-sm text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-white"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </button>
        </div>
      </div>
    </header>
  );
}
