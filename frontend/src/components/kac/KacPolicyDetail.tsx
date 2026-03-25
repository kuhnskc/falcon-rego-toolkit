import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle,
  XCircle,
  Pencil,
  Trash2,
  ToggleLeft,
  ToggleRight,
  Server,
} from 'lucide-react';
import * as kacApi from '../../api/kac';
import type { KacPolicy } from '../../api/types';
import ConfirmDialog from '../common/ConfirmDialog';
import RuleGroupPanel from './RuleGroupPanel';

interface KacPolicyDetailProps {
  policy: KacPolicy;
}

export default function KacPolicyDetail({ policy }: KacPolicyDetailProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState(policy.name);
  const [editDescription, setEditDescription] = useState(policy.description);

  const toggleMutation = useMutation({
    mutationFn: () =>
      kacApi.updatePolicy(policy.id, { is_enabled: !policy.is_enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kac', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['kac', 'policy', policy.id] });
    },
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      kacApi.updatePolicy(policy.id, {
        name: editName,
        description: editDescription,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kac', 'policies'] });
      queryClient.invalidateQueries({ queryKey: ['kac', 'policy', policy.id] });
      setIsEditing(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => kacApi.deletePolicy(policy.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['kac', 'policies'] });
      navigate('/kac');
    },
  });

  return (
    <div className="space-y-6">
      {/* Header / Info Card */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        {isEditing ? (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">
                Name
              </label>
              <input
                type="text"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-gray-400">
                Description
              </label>
              <textarea
                value={editDescription}
                onChange={(e) => setEditDescription(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => updateMutation.mutate()}
                disabled={updateMutation.isPending}
                className="rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
              >
                {updateMutation.isPending ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={() => {
                  setIsEditing(false);
                  setEditName(policy.name);
                  setEditDescription(policy.description);
                }}
                className="rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a]"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h2 className="text-xl font-bold text-gray-100">
                  {policy.name}
                </h2>
                {policy.description && (
                  <p className="mt-1 text-sm text-gray-400">
                    {policy.description}
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => toggleMutation.mutate()}
                  disabled={toggleMutation.isPending}
                  title={policy.is_enabled ? 'Disable policy' : 'Enable policy'}
                  className="rounded-lg border border-[#2e2b3a] p-2 text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-gray-200 disabled:opacity-50"
                >
                  {policy.is_enabled ? (
                    <ToggleRight size={18} className="text-green-400" />
                  ) : (
                    <ToggleLeft size={18} />
                  )}
                </button>
                <button
                  onClick={() => setIsEditing(true)}
                  title="Edit policy"
                  className="rounded-lg border border-[#2e2b3a] p-2 text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-gray-200"
                >
                  <Pencil size={18} />
                </button>
                <button
                  onClick={() => setShowDeleteDialog(true)}
                  title="Delete policy"
                  className="rounded-lg border border-[#2e2b3a] p-2 text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-red-400"
                >
                  <Trash2 size={18} />
                </button>
              </div>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <MetaItem
                label="Status"
                value={
                  <span className="flex items-center gap-1.5">
                    {policy.is_enabled ? (
                      <>
                        <CheckCircle size={14} className="text-green-400" />
                        <span className="text-green-400">Enabled</span>
                      </>
                    ) : (
                      <>
                        <XCircle size={14} className="text-gray-500" />
                        <span className="text-gray-500">Disabled</span>
                      </>
                    )}
                  </span>
                }
              />
              <MetaItem
                label="Precedence"
                value={<span className="text-gray-200">{policy.precedence}</span>}
              />
              <MetaItem
                label="Policy Type"
                value={<span className="text-gray-200">{policy.policy_type}</span>}
              />
              <MetaItem
                label="Default"
                value={
                  <span className="text-gray-200">
                    {policy.is_default ? 'Yes' : 'No'}
                  </span>
                }
              />
            </div>

            {/* Host Groups */}
            {policy.host_groups && policy.host_groups.length > 0 && (
              <div className="mt-4">
                <h3 className="mb-2 text-xs font-medium text-gray-400">
                  Host Groups
                </h3>
                <div className="flex flex-wrap gap-2">
                  {policy.host_groups.map((hg) => (
                    <span
                      key={hg}
                      className="inline-flex items-center gap-1.5 rounded-full border border-[#2e2b3a] bg-[#171520] px-2.5 py-1 text-xs text-gray-300"
                    >
                      <Server size={12} className="text-gray-500" />
                      {hg}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Rule Groups Panel */}
      <RuleGroupPanel policyId={policy.id} ruleGroups={policy.rule_groups ?? []} />

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        title="Delete Policy"
        message={`Are you sure you want to delete "${policy.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={() => {
          deleteMutation.mutate();
          setShowDeleteDialog(false);
        }}
        onCancel={() => setShowDeleteDialog(false)}
      />
    </div>
  );
}

function MetaItem({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs font-medium text-gray-500">{label}</dt>
      <dd className="mt-0.5 text-sm">{value}</dd>
    </div>
  );
}
