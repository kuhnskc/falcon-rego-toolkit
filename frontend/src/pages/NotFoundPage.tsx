import { Link } from 'react-router-dom';
import { Home } from 'lucide-react';

export default function NotFoundPage() {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-4 bg-[#171520] text-gray-400">
      <span className="text-6xl font-bold text-gray-600">404</span>
      <p className="text-sm">The page you're looking for doesn't exist.</p>
      <Link
        to="/"
        className="mt-2 inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d]"
      >
        <Home size={16} />
        Go Home
      </Link>
    </div>
  );
}
