import { useState, type FormEvent } from 'react';
import { Shield } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { CLOUD_ENVIRONMENTS } from '../../api/types';

export default function LoginForm() {
  const { login } = useAuth();

  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [cloudEnv, setCloudEnv] = useState(Object.keys(CLOUD_ENVIRONMENTS)[0]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      await login({
        client_id: clientId,
        client_secret: clientSecret,
        base_url: CLOUD_ENVIRONMENTS[cloudEnv],
      });
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Authentication failed. Please check your credentials.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#171520] px-4">
      <div className="w-full max-w-md rounded-xl border border-[#2e2b3a] bg-[#23202e] p-8 shadow-2xl">
        {/* Header */}
        <div className="mb-8 flex flex-col items-center gap-3">
          <Shield className="h-10 w-10 text-[#ED1C24]" />
          <h1 className="text-2xl font-bold text-white">Falcon Rego Toolkit</h1>
          <p className="text-sm text-gray-400">
            Sign in with your CrowdStrike API credentials
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="mb-5 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-5">
          {/* Client ID */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="client-id" className="text-sm font-medium text-gray-300">
              Client ID
            </label>
            <input
              id="client-id"
              type="text"
              required
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="rounded-md border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-[#ED1C24]"
              placeholder="Enter your Client ID"
            />
          </div>

          {/* Client Secret */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="client-secret" className="text-sm font-medium text-gray-300">
              Client Secret
            </label>
            <input
              id="client-secret"
              type="password"
              required
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              className="rounded-md border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-white placeholder-gray-500 outline-none transition-colors focus:border-[#ED1C24]"
              placeholder="Enter your Client Secret"
            />
          </div>

          {/* Cloud Environment */}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="cloud-env" className="text-sm font-medium text-gray-300">
              Cloud Environment
            </label>
            <select
              id="cloud-env"
              value={cloudEnv}
              onChange={(e) => setCloudEnv(e.target.value)}
              className="rounded-md border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-white outline-none transition-colors focus:border-[#ED1C24]"
            >
              {Object.keys(CLOUD_ENVIRONMENTS).map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={submitting}
            className="mt-2 rounded-md bg-[#ED1C24] px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#c4161d] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
