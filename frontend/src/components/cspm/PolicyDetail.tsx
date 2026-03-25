import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Pencil,
  FlaskConical,
  Trash2,
  Save,
  X,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import type { CspmPolicy, CspmPolicyUpdate, TestResult } from '../../api/types';
import { SEVERITY_MAP } from '../../api/types';
import { updatePolicy, deletePolicy, testPolicy } from '../../api/cspm';
import SeverityBadge from '../common/SeverityBadge';
import RegoEditor from '../common/RegoEditor';
import ConfirmDialog from '../common/ConfirmDialog';

interface PolicyDetailProps {
  policy: CspmPolicy;
}

export default function PolicyDetail({ policy }: PolicyDetailProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Edit state
  const [isEditing, setIsEditing] = useState(false);
  const [editDesc, setEditDesc] = useState(policy.description);
  const [editSeverity, setEditSeverity] = useState(policy.severity);
  const [editLogic, setEditLogic] = useState(
    policy.rule_logic_list[0]?.logic ?? '',
  );
  const [editAlertInfo, setEditAlertInfo] = useState(policy.alert_info ?? '');
  const [editRemediation, setEditRemediation] = useState(
    policy.rule_logic_list[0]?.remediation_info ?? '',
  );

  // Test state
  const [showTestPanel, setShowTestPanel] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  // Delete dialog
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  // Mutations
  const updateMutation = useMutation({
    mutationFn: (data: CspmPolicyUpdate) => updatePolicy(policy.uuid, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cspm', 'policies'] });
      setIsEditing(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deletePolicy(policy.uuid),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cspm', 'policies'] });
      navigate('/cspm');
    },
  });

  const testMutation = useMutation({
    mutationFn: () =>
      testPolicy({
        logic: isEditing ? editLogic : (policy.rule_logic_list[0]?.logic ?? ''),
        resource_type: policy.resource_types[0]?.resource_type ?? '',
        num_assets: 5,
      }).then((res) => res.data),
    onSuccess: (data) => setTestResult(data),
  });

  const handleSave = useCallback(() => {
    updateMutation.mutate({
      description: editDesc,
      severity: editSeverity,
      logic: editLogic,
      platform: policy.rule_logic_list[0]?.platform,
      alert_info: editAlertInfo,
      remediation_info: editRemediation,
    });
  }, [
    updateMutation,
    editDesc,
    editSeverity,
    editLogic,
    editAlertInfo,
    editRemediation,
    policy.rule_logic_list,
  ]);

  const handleCancelEdit = useCallback(() => {
    setEditDesc(policy.description);
    setEditSeverity(policy.severity);
    setEditLogic(policy.rule_logic_list[0]?.logic ?? '');
    setEditAlertInfo(policy.alert_info ?? '');
    setEditRemediation(policy.rule_logic_list[0]?.remediation_info ?? '');
    setIsEditing(false);
  }, [policy]);

  const handleTest = useCallback(() => {
    setShowTestPanel(true);
    setTestResult(null);
    testMutation.mutate();
  }, [testMutation]);

  const handleConfirmDelete = useCallback(() => {
    setShowDeleteDialog(false);
    deleteMutation.mutate();
  }, [deleteMutation]);

  const resourceType = policy.resource_types[0]?.resource_type ?? '--';
  const logic = policy.rule_logic_list[0]?.logic ?? '';
  const remediation = policy.rule_logic_list[0]?.remediation_info ?? '';

  return (
    <div className="space-y-6">
      {/* Action Bar */}
      <div className="flex items-center gap-3">
        {isEditing ? (
          <>
            <button
              onClick={handleSave}
              disabled={updateMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
            >
              {updateMutation.isPending ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Save size={14} />
              )}
              Save Changes
            </button>
            <button
              onClick={handleCancelEdit}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a]"
            >
              <X size={14} />
              Cancel
            </button>
          </>
        ) : (
          <>
            <button
              onClick={() => setIsEditing(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a]"
            >
              <Pencil size={14} />
              Edit
            </button>
            <button
              onClick={handleTest}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a]"
            >
              <FlaskConical size={14} />
              Test
            </button>
            <button
              onClick={() => setShowDeleteDialog(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/40 px-4 py-2 text-sm font-medium text-red-400 transition-colors hover:bg-red-500/10"
            >
              <Trash2 size={14} />
              Delete
            </button>
          </>
        )}
      </div>

      {/* Update error */}
      {updateMutation.isError && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Failed to update policy. Please try again.
        </div>
      )}

      {/* Metadata Card */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        <h2 className="mb-4 text-lg font-semibold text-gray-100">Policy Details</h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {/* Name */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Name
            </label>
            <p className="text-sm text-gray-200">{policy.name}</p>
          </div>

          {/* Resource Type */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Resource Type
            </label>
            <p className="text-sm text-gray-200">{resourceType}</p>
          </div>

          {/* Severity */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Severity
            </label>
            {isEditing ? (
              <div className="flex gap-2">
                {Object.entries(SEVERITY_MAP).map(([val, info]) => {
                  const numVal = Number(val);
                  return (
                    <button
                      key={val}
                      onClick={() => setEditSeverity(numVal)}
                      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                        editSeverity === numVal
                          ? 'border-[#ED1C24] bg-[#ED1C24]/20 text-white'
                          : 'border-[#2e2b3a] text-gray-400 hover:border-gray-500'
                      }`}
                    >
                      {info.label}
                    </button>
                  );
                })}
              </div>
            ) : (
              <SeverityBadge severity={policy.severity} />
            )}
          </div>

          {/* Origin */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Origin
            </label>
            <p className="text-sm text-gray-200">{policy.origin}</p>
          </div>

          {/* Created At */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Created
            </label>
            <p className="text-sm text-gray-200">
              {new Date(policy.created_at).toLocaleString()}
            </p>
          </div>

          {/* Updated At */}
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Updated
            </label>
            <p className="text-sm text-gray-200">
              {new Date(policy.updated_at).toLocaleString()}
            </p>
          </div>

          {/* Description */}
          <div className="md:col-span-2">
            <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
              Description
            </label>
            {isEditing ? (
              <textarea
                value={editDesc}
                onChange={(e) => setEditDesc(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            ) : (
              <p className="text-sm leading-relaxed text-gray-300">
                {policy.description || '--'}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Alert Info */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        <h2 className="mb-3 text-lg font-semibold text-gray-100">Alert Info</h2>
        {isEditing ? (
          <textarea
            value={editAlertInfo}
            onChange={(e) => setEditAlertInfo(e.target.value)}
            rows={4}
            placeholder="Pipe-separated alert info..."
            className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
          />
        ) : (
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">
            {policy.alert_info || '--'}
          </p>
        )}
      </div>

      {/* Remediation Info */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        <h2 className="mb-3 text-lg font-semibold text-gray-100">Remediation</h2>
        {isEditing ? (
          <textarea
            value={editRemediation}
            onChange={(e) => setEditRemediation(e.target.value)}
            rows={4}
            placeholder="Pipe-separated remediation info..."
            className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
          />
        ) : (
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-gray-300">
            {remediation || '--'}
          </p>
        )}
      </div>

      {/* Rego Logic */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        <h2 className="mb-3 text-lg font-semibold text-gray-100">Rego Logic</h2>
        <RegoEditor
          value={isEditing ? editLogic : logic}
          onChange={(val) => setEditLogic(val)}
          readOnly={!isEditing}
          height="400px"
        />
      </div>

      {/* Test Panel */}
      {showTestPanel && (
        <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-100">Test Results</h2>
            <button
              onClick={() => setShowTestPanel(false)}
              className="rounded-md p-1 text-gray-400 hover:bg-[#2e2b3a] hover:text-gray-200 transition-colors"
            >
              <X size={18} />
            </button>
          </div>

          {testMutation.isPending && (
            <div className="flex items-center gap-2 py-8 text-gray-400">
              <Loader2 size={20} className="animate-spin" />
              <span className="text-sm">Running tests...</span>
            </div>
          )}

          {testMutation.isError && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              Test execution failed. Please check your Rego logic and try again.
            </div>
          )}

          {testResult && (
            <div className="space-y-4">
              {/* Summary */}
              <div className="grid grid-cols-3 gap-4">
                <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-3 text-center">
                  <CheckCircle2 size={20} className="mx-auto mb-1 text-green-400" />
                  <p className="text-lg font-bold text-green-400">{testResult.pass_count}</p>
                  <p className="text-xs text-green-400/70">Passed</p>
                </div>
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-center">
                  <XCircle size={20} className="mx-auto mb-1 text-red-400" />
                  <p className="text-lg font-bold text-red-400">{testResult.fail_count}</p>
                  <p className="text-xs text-red-400/70">Failed</p>
                </div>
                <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-center">
                  <AlertTriangle size={20} className="mx-auto mb-1 text-yellow-400" />
                  <p className="text-lg font-bold text-yellow-400">{testResult.error_count}</p>
                  <p className="text-xs text-yellow-400/70">Errors</p>
                </div>
              </div>

              {/* Summary text */}
              <p className="text-sm text-gray-400">{testResult.summary}</p>

              {/* Individual results */}
              <div className="divide-y divide-[#2e2b3a] rounded-lg border border-[#2e2b3a]">
                {testResult.test_results.map((tr, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between px-4 py-2 text-sm"
                  >
                    <span className="text-gray-300">{tr.asset_id}</span>
                    <span
                      className={
                        tr.result === 'pass'
                          ? 'text-green-400'
                          : tr.result === 'fail'
                            ? 'text-red-400'
                            : 'text-yellow-400'
                      }
                    >
                      {tr.result}
                      {tr.error ? `: ${tr.error}` : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        title="Delete Policy"
        message={`Are you sure you want to delete "${policy.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={handleConfirmDelete}
        onCancel={() => setShowDeleteDialog(false)}
      />
    </div>
  );
}
