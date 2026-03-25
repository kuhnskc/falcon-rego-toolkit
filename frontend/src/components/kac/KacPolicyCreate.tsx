import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import * as kacApi from '../../api/kac';

export default function KacPolicyCreate() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const createMutation = useMutation({
    mutationFn: () => kacApi.createPolicy(name, description),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kac', 'policies'] });
      navigate('/kac');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    createMutation.mutate();
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="mx-auto max-w-lg space-y-5 rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6"
    >
      <div>
        <label
          htmlFor="policy-name"
          className="mb-1 block text-xs font-medium text-gray-400"
        >
          Name <span className="text-[#ED1C24]">*</span>
        </label>
        <input
          id="policy-name"
          type="text"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Production cluster policy"
          className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
        />
      </div>

      <div>
        <label
          htmlFor="policy-description"
          className="mb-1 block text-xs font-medium text-gray-400"
        >
          Description
        </label>
        <textarea
          id="policy-description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={4}
          placeholder="Optional description of this policy..."
          className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
        />
      </div>

      {createMutation.isError && (
        <p className="text-sm text-red-400">
          {createMutation.error instanceof Error
            ? createMutation.error.message
            : 'Failed to create policy.'}
        </p>
      )}

      <div className="flex items-center gap-3 pt-2">
        <button
          type="submit"
          disabled={createMutation.isPending || !name.trim()}
          className="inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
        >
          {createMutation.isPending && (
            <Loader2 size={16} className="animate-spin" />
          )}
          Create Policy
        </button>
        <button
          type="button"
          onClick={() => navigate('/kac')}
          className="rounded-lg border border-[#2e2b3a] px-5 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a]"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
