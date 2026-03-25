import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  Loader2,
  Tag,
  Box,
  ShieldAlert,
  Image,
  Code2,
  FlaskConical,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Eye,
  Pencil,
  Save,
  X,
} from 'lucide-react';
import * as kacApi from '../../api/kac';
import type { KacRuleGroup, KacCustomRule, KacDefaultRule, KacEvaluateResult } from '../../api/types';
import ConfirmDialog from '../common/ConfirmDialog';
import RegoEditor from '../common/RegoEditor';

interface RuleGroupPanelProps {
  policyId: string;
  ruleGroups: KacRuleGroup[];
}

const SEVERITY_OPTIONS = [
  { value: 0, label: 'Critical' },
  { value: 1, label: 'High' },
  { value: 2, label: 'Medium' },
  { value: 3, label: 'Informational' },
];

const ACTION_OPTIONS = [
  { value: 'Prevent', label: 'Prevent' },
  { value: 'Alert', label: 'Alert' },
  { value: 'Disabled', label: 'Disabled' },
];

const DEFAULT_KAC_REGO = `package customrule

import rego.v1

workload_kinds := {
\t"Deployment", "DaemonSet", "StatefulSet",
\t"ReplicaSet", "ReplicationController", "Job",
}

pod_spec := input.request.object.spec if {
\tinput.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
\tinput.request.kind.kind in workload_kinds
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
\tinput.request.kind.kind == "CronJob"
}

# Deny message returned when rule is violated.
# Empty result = allow, non-empty string = deny.
result := msg if {
\t# Your deny logic here
\tfalse
\tmsg := "Violation: describe the issue"
}
`;

export default function RuleGroupPanel({
  policyId,
  ruleGroups,
}: RuleGroupPanelProps) {
  const queryClient = useQueryClient();
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [showAddForm, setShowAddForm] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<KacRuleGroup | null>(null);
  const [addRuleGroupId, setAddRuleGroupId] = useState<string | null>(null);

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['kac', 'policies'] });
    queryClient.invalidateQueries({ queryKey: ['kac', 'policy', policyId] });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      kacApi.createRuleGroups(policyId, [
        { name: newName, description: newDescription },
      ]),
    onSuccess: () => {
      invalidate();
      setShowAddForm(false);
      setNewName('');
      setNewDescription('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (groupId: string) =>
      kacApi.deleteRuleGroups(policyId, [groupId]),
    onSuccess: () => {
      invalidate();
      setDeleteTarget(null);
    },
  });

  return (
    <div className="space-y-3">
      {/* Section Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300">
          Rule Groups ({ruleGroups.length})
        </h3>
        <button
          onClick={() => setShowAddForm((v) => !v)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] hover:text-white"
        >
          <Plus size={14} />
          Add Rule Group
        </button>
      </div>

      {/* Add Form */}
      {showAddForm && (
        <div className="rounded-xl border border-[#2e2b3a] bg-[#1c1928] p-5 space-y-4">
          <h4 className="text-sm font-semibold text-gray-100 border-b border-[#2e2b3a] pb-2">
            New Rule Group
          </h4>
          <div>
            <label className="mb-1.5 block text-xs font-semibold text-gray-200">
              Name <span className="text-[#ED1C24]">*</span>
            </label>
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Rule group name"
              className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-semibold text-gray-200">
              Description
            </label>
            <input
              type="text"
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Optional description"
              className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
            />
          </div>
          <div className="flex items-center gap-3 border-t border-[#2e2b3a] pt-3">
            <button
              onClick={() => createMutation.mutate()}
              disabled={!newName.trim() || createMutation.isPending}
              className="inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-5 py-2 text-xs font-semibold text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
            >
              {createMutation.isPending && (
                <Loader2 size={14} className="animate-spin" />
              )}
              Create
            </button>
            <button
              onClick={() => {
                setShowAddForm(false);
                setNewName('');
                setNewDescription('');
              }}
              className="rounded-lg border border-[#3a3650] px-5 py-2 text-xs font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] hover:text-white"
            >
              Cancel
            </button>
          </div>
          {createMutation.isError && (
            <p className="text-xs text-red-400">
              {createMutation.error instanceof Error
                ? createMutation.error.message
                : 'Failed to create rule group.'}
            </p>
          )}
        </div>
      )}

      {/* Accordion Cards */}
      {ruleGroups.length === 0 && !showAddForm && (
        <p className="py-6 text-center text-xs text-gray-500">
          No rule groups configured.
        </p>
      )}

      {ruleGroups.map((group) => {
        const isExpanded = expandedIds.has(group.id);
        return (
          <div
            key={group.id}
            className="rounded-xl border border-[#2e2b3a] bg-[#23202e] overflow-hidden"
          >
            {/* Card Header */}
            <button
              onClick={() => toggleExpanded(group.id)}
              className="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-[#2e2b3a]/40"
            >
              <div className="flex items-center gap-2">
                {isExpanded ? (
                  <ChevronDown size={16} className="text-gray-500" />
                ) : (
                  <ChevronRight size={16} className="text-gray-500" />
                )}
                <span className="text-sm font-medium text-gray-200">
                  {group.name}
                </span>
                {group.is_default && (
                  <span className="rounded-full bg-[#ED1C24]/10 px-2 py-0.5 text-[10px] font-semibold text-[#ED1C24]">
                    DEFAULT
                  </span>
                )}
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setDeleteTarget(group);
                }}
                title="Delete rule group"
                className="rounded-md p-1 text-gray-500 transition-colors hover:bg-[#2e2b3a] hover:text-red-400"
              >
                <Trash2 size={14} />
              </button>
            </button>

            {/* Card Body */}
            {isExpanded && (
              <div className="border-t border-[#2e2b3a] px-4 py-4 space-y-4">
                {/* Description */}
                {group.description && (
                  <p className="text-xs text-gray-400">{group.description}</p>
                )}

                {/* Custom Rules */}
                <div>
                  <div className="mb-1.5 flex items-center justify-between">
                    <h4 className="text-xs font-semibold text-gray-300">
                      Custom Rules
                    </h4>
                    <button
                      onClick={() =>
                        setAddRuleGroupId(
                          addRuleGroupId === group.id ? null : group.id
                        )
                      }
                      className="inline-flex items-center gap-1 rounded-md border border-[#2e2b3a] px-2 py-1 text-[11px] font-medium text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-white"
                    >
                      <Code2 size={12} />
                      Add Custom Rule
                    </button>
                  </div>

                  {/* Add Custom Rule Form */}
                  {addRuleGroupId === group.id && (
                    <AddCustomRuleForm
                      policyId={policyId}
                      groupId={group.id}
                      onClose={() => setAddRuleGroupId(null)}
                      onSuccess={invalidate}
                    />
                  )}

                  {group.custom_rules.length === 0 &&
                    addRuleGroupId !== group.id && (
                      <p className="text-[11px] text-gray-500">
                        No custom rules
                      </p>
                    )}
                  {group.custom_rules.length > 0 && (
                    <div className="space-y-1.5">
                      {group.custom_rules.map((rule: KacCustomRule) => (
                        <CustomRuleRow
                          key={rule.id}
                          rule={rule}
                          policyId={policyId}
                          onDeleted={invalidate}
                        />
                      ))}
                    </div>
                  )}
                </div>

                {/* Default Rules */}
                <RuleList
                  title="Default Rules"
                  rules={group.default_rules}
                  emptyText="No default rules"
                  renderRule={(rule: KacDefaultRule) => (
                    <div
                      key={rule.code}
                      className="flex items-center justify-between rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium text-gray-200">
                          {rule.name || `IOM Rule ${rule.code}`}
                        </p>
                        {rule.description && (
                          <p className="text-[11px] text-gray-400">
                            {rule.description}
                          </p>
                        )}
                        {!rule.name && (
                          <p className="text-[10px] font-mono text-gray-500">
                            Code: {rule.code}
                          </p>
                        )}
                      </div>
                      <ActionBadge action={rule.action} />
                    </div>
                  )}
                />

                {/* Labels */}
                {group.labels && group.labels.length > 0 && (
                  <div>
                    <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-gray-400">
                      <Tag size={12} /> Labels
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {group.labels.map((l, i) => (
                        <span
                          key={i}
                          className="rounded-full border border-[#2e2b3a] bg-[#171520] px-2 py-0.5 text-[11px] text-gray-300"
                        >
                          {l.key} {l.operator} {l.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Namespaces */}
                {group.namespaces && group.namespaces.length > 0 && (
                  <div>
                    <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-gray-400">
                      <Box size={12} /> Namespaces
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {group.namespaces.map((ns, i) => (
                        <span
                          key={i}
                          className="rounded-full border border-[#2e2b3a] bg-[#171520] px-2 py-0.5 text-[11px] text-gray-300"
                        >
                          {ns.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Deny on Error & Image Assessment */}
                <div className="flex flex-wrap gap-4">
                  {group.deny_on_error !== undefined && (
                    <div className="flex items-center gap-1.5 text-xs text-gray-400">
                      <ShieldAlert size={12} />
                      Deny on Error:{' '}
                      <span
                        className={
                          group.deny_on_error.deny
                            ? 'text-red-400'
                            : 'text-gray-300'
                        }
                      >
                        {group.deny_on_error.deny ? 'Yes' : 'No'}
                      </span>
                    </div>
                  )}
                  {group.image_assessment !== undefined && (
                    <div className="flex items-center gap-1.5 text-xs text-gray-400">
                      <Image size={12} />
                      Image Assessment:{' '}
                      <span
                        className={
                          group.image_assessment.enabled
                            ? 'text-green-400'
                            : 'text-gray-300'
                        }
                      >
                        {group.image_assessment.enabled
                          ? 'Enabled'
                          : 'Disabled'}
                      </span>
                      {group.image_assessment.enabled && (
                        <span className="text-gray-500">
                          (unassessed: {group.image_assessment.unassessed_handling})
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      })}

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={deleteTarget !== null}
        title="Delete Rule Group"
        message={`Are you sure you want to delete "${deleteTarget?.name ?? ''}"? This action cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={() => {
          if (deleteTarget) deleteMutation.mutate(deleteTarget.id);
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}

/* ─── Add Custom Rule Form ─────────────────────────────────── */

function AddCustomRuleForm({
  policyId,
  groupId,
  onClose,
  onSuccess,
}: {
  policyId: string;
  groupId: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [ruleName, setRuleName] = useState('');
  const [ruleDescription, setRuleDescription] = useState('');
  const [regoLogic, setRegoLogic] = useState(DEFAULT_KAC_REGO);
  const [severity, setSeverity] = useState(3);
  const [action, setAction] = useState('Prevent');
  const [error, setError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  // Test panel state
  const [showTestPanel, setShowTestPanel] = useState(false);
  const [manifestYaml, setManifestYaml] = useState('');
  const [evalResult, setEvalResult] = useState<KacEvaluateResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);

  const handleEvaluate = async () => {
    if (!regoLogic.trim() || !manifestYaml.trim()) return;
    setEvalResult(null);
    setEvalError(null);
    setIsEvaluating(true);
    try {
      const res = await kacApi.evaluateRule({ logic: regoLogic, manifest_yaml: manifestYaml });
      setEvalResult(res.data);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setEvalError(axiosErr.response?.data?.detail ?? 'Evaluation request failed.');
      } else if (err instanceof Error) {
        setEvalError(err.message);
      } else {
        setEvalError('Evaluation request failed.');
      }
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleCreate = async () => {
    if (!ruleName.trim() || !regoLogic.trim()) return;
    setError(null);
    setIsCreating(true);

    try {
      // Step 1: Create the custom Rego rule (uploads logic to CrowdStrike)
      const createRes = await kacApi.createCustomRegoRule({
        name: ruleName.trim(),
        description: ruleDescription.trim(),
        logic: regoLogic,
        severity,
      });

      // Extract UUID from response
      const resources = createRes.data?.resources ?? [];
      const ruleUuid = resources[0]?.uuid ?? resources[0]?.id;
      if (!ruleUuid) {
        setError('Rule created but no UUID returned. Check the API response.');
        setIsCreating(false);
        return;
      }

      // Step 2: Attach the rule to the rule group
      await kacApi.addCustomRules(policyId, groupId, [
        { rule_id: ruleUuid, action },
      ]);

      onSuccess();
      onClose();
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: unknown } } };
        const detail = axiosErr.response?.data?.detail;
        if (typeof detail === 'string') {
          setError(detail);
        } else if (detail && typeof detail === 'object') {
          const csErrors = (detail as Record<string, unknown>).errors;
          if (Array.isArray(csErrors) && csErrors.length > 0) {
            setError(
              csErrors.map((e: Record<string, unknown>) => e.message ?? e.code ?? 'Unknown error').join('; ')
            );
          } else {
            setError(JSON.stringify(detail).slice(0, 300));
          }
        } else {
          setError('Failed to create rule.');
        }
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Failed to create rule.');
      }
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="mb-3 space-y-4 rounded-xl border border-[#ED1C24]/30 bg-[#1c1928] p-5">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-[#2e2b3a] pb-3">
        <Code2 size={16} className="text-[#ED1C24]" />
        <h4 className="text-sm font-semibold text-gray-100">
          New Custom Rego Rule
        </h4>
      </div>

      {/* Name */}
      <div>
        <label className="mb-1.5 block text-xs font-semibold text-gray-200">
          Rule Name <span className="text-[#ED1C24]">*</span>
        </label>
        <input
          type="text"
          value={ruleName}
          onChange={(e) => setRuleName(e.target.value)}
          placeholder="e.g. Deny Privileged Containers"
          className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
        />
      </div>

      {/* Description */}
      <div>
        <label className="mb-1.5 block text-xs font-semibold text-gray-200">
          Description
        </label>
        <input
          type="text"
          value={ruleDescription}
          onChange={(e) => setRuleDescription(e.target.value)}
          placeholder="What does this rule enforce?"
          className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
        />
      </div>

      {/* Severity + Action row */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-gray-200">
            Severity
          </label>
          <select
            value={severity}
            onChange={(e) => setSeverity(Number(e.target.value))}
            className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-gray-200">
            Action
          </label>
          <select
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
          >
            {ACTION_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rego Editor */}
      <div>
        <label className="mb-1.5 block text-xs font-semibold text-gray-200">
          Rego Policy <span className="text-[#ED1C24]">*</span>
        </label>
        <p className="mb-2 text-[11px] text-gray-400">
          Must use <code className="rounded bg-[#2e2b3a] px-1 py-0.5 text-gray-300">package customrule</code>,
          tabs for indentation,{' '}
          <code className="rounded bg-[#2e2b3a] px-1 py-0.5 text-gray-300">some X in Y</code> for iteration,
          and max 120 chars per line.
        </p>
        <div className="overflow-hidden rounded-lg border border-[#3a3650]">
          <RegoEditor
            value={regoLogic}
            onChange={setRegoLogic}
            height="280px"
          />
        </div>
      </div>

      {/* Test Rule Panel */}
      <div>
        <button
          type="button"
          onClick={() => setShowTestPanel((v) => !v)}
          className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 transition-colors hover:text-gray-200"
        >
          <FlaskConical size={13} />
          {showTestPanel ? 'Hide Test Panel' : 'Test Rule Locally'}
        </button>

        {showTestPanel && (
          <div className="mt-2 space-y-3 rounded-lg border border-[#3a3650] bg-[#171520] p-4">
            <div>
              <label className="mb-1.5 block text-xs font-semibold text-gray-200">
                Kubernetes Manifest (YAML)
              </label>
              <textarea
                value={manifestYaml}
                onChange={(e) => setManifestYaml(e.target.value)}
                rows={10}
                placeholder={`apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\n  namespace: default\nspec:\n  containers:\n  - name: nginx\n    image: nginx:latest\n    securityContext:\n      privileged: true`}
                className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 font-mono text-xs text-gray-100 placeholder-gray-600 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
              />
            </div>

            <button
              type="button"
              onClick={handleEvaluate}
              disabled={!regoLogic.trim() || !manifestYaml.trim() || isEvaluating}
              className="inline-flex items-center gap-2 rounded-lg border border-[#3a3650] bg-[#23202e] px-4 py-2 text-xs font-semibold text-gray-200 transition-colors hover:bg-[#2e2b3a] hover:text-white disabled:opacity-50"
            >
              {isEvaluating ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <FlaskConical size={14} />
              )}
              Evaluate
            </button>

            {/* OPA not available warning */}
            {evalResult && !evalResult.opa_available && (
              <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2">
                <AlertTriangle size={14} className="mt-0.5 shrink-0 text-yellow-400" />
                <p className="text-xs text-yellow-300">
                  OPA is not installed on the server.{' '}
                  Install it with <code className="rounded bg-[#2e2b3a] px-1 py-0.5 text-yellow-200">brew install opa</code> to enable local rule testing.
                </p>
              </div>
            )}

            {/* Evaluation result */}
            {evalResult && evalResult.opa_available && (
              <div
                className={`rounded-lg border px-3 py-2.5 ${
                  evalResult.decision === 'ALLOW'
                    ? 'border-green-500/30 bg-green-500/10'
                    : evalResult.decision === 'DENY'
                    ? 'border-red-500/30 bg-red-500/10'
                    : 'border-yellow-500/30 bg-yellow-500/10'
                }`}
              >
                <div className="flex items-center gap-2">
                  {evalResult.decision === 'ALLOW' && (
                    <CheckCircle2 size={16} className="text-green-400" />
                  )}
                  {evalResult.decision === 'DENY' && (
                    <XCircle size={16} className="text-red-400" />
                  )}
                  {evalResult.decision === 'ERROR' && (
                    <AlertTriangle size={16} className="text-yellow-400" />
                  )}
                  <span
                    className={`text-sm font-semibold ${
                      evalResult.decision === 'ALLOW'
                        ? 'text-green-400'
                        : evalResult.decision === 'DENY'
                        ? 'text-red-400'
                        : 'text-yellow-400'
                    }`}
                  >
                    {evalResult.decision}
                  </span>
                  {evalResult.manifest_kind && (
                    <span className="text-xs text-gray-400">
                      — {evalResult.manifest_kind}/{evalResult.manifest_name}
                    </span>
                  )}
                </div>
                {evalResult.message && (
                  <p className="mt-1 text-xs text-gray-300">{evalResult.message}</p>
                )}
                {evalResult.error && (
                  <p className="mt-1 text-xs text-yellow-300">{evalResult.error}</p>
                )}
              </div>
            )}

            {/* Network/request error */}
            {evalError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                {evalError}
              </div>
            )}
          </div>
        )}
      </div>
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          {error}
        </div>
      )}

      {/* Buttons */}
      <div className="flex items-center gap-3 border-t border-[#2e2b3a] pt-3">
        <button
          onClick={handleCreate}
          disabled={!ruleName.trim() || !regoLogic.trim() || isCreating}
          className="inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-5 py-2 text-xs font-semibold text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
        >
          {isCreating && <Loader2 size={14} className="animate-spin" />}
          Create & Attach Rule
        </button>
        <button
          onClick={onClose}
          className="rounded-lg border border-[#3a3650] px-5 py-2 text-xs font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] hover:text-white"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/* ─── Custom Rule Row (with view/edit/delete) ─────────────── */

function CustomRuleRow({
  rule,
  policyId,
  onDeleted,
}: {
  rule: KacCustomRule;
  policyId: string;
  onDeleted: () => void;
}) {
  const [showConfirm, setShowConfirm] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // View / Edit state
  const [expanded, setExpanded] = useState(false);
  const [ruleDetail, setRuleDetail] = useState<Record<string, unknown> | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [isEditing, setIsEditing] = useState(false);
  const [editLogic, setEditLogic] = useState('');
  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editSeverity, setEditSeverity] = useState(3);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Test panel state
  const [showTestPanel, setShowTestPanel] = useState(false);
  const [manifestYaml, setManifestYaml] = useState('');
  const [evalResult, setEvalResult] = useState<KacEvaluateResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);

  const handleToggleExpand = async () => {
    if (expanded) {
      setExpanded(false);
      setIsEditing(false);
      return;
    }
    setExpanded(true);
    if (!ruleDetail) {
      setIsFetching(true);
      setFetchError(null);
      try {
        const res = await kacApi.getCustomRegoRule(rule.id);
        setRuleDetail(res.data);
      } catch (err: unknown) {
        if (err && typeof err === 'object' && 'response' in err) {
          const axiosErr = err as { response?: { data?: { detail?: string } } };
          setFetchError(axiosErr.response?.data?.detail ?? 'Failed to load rule details.');
        } else {
          setFetchError('Failed to load rule details.');
        }
      } finally {
        setIsFetching(false);
      }
    }
  };

  const startEditing = () => {
    if (!ruleDetail) return;
    const logicList = ruleDetail.rule_logic_list as Array<{ logic?: string }> | undefined;
    setEditLogic(logicList?.[0]?.logic ?? '');
    setEditName((ruleDetail.name as string) ?? '');
    setEditDescription((ruleDetail.description as string) ?? '');
    setEditSeverity((ruleDetail.severity as number) ?? 3);
    setSaveError(null);
    setIsEditing(true);
  };

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError(null);
    try {
      const payload: Record<string, unknown> = {};
      const currentLogic = (ruleDetail?.rule_logic_list as Array<{ logic?: string }> | undefined)?.[0]?.logic ?? '';
      if (editLogic !== currentLogic) payload.logic = editLogic;
      if (editName !== (ruleDetail?.name ?? '')) payload.name = editName;
      if (editDescription !== (ruleDetail?.description ?? '')) payload.description = editDescription;
      if (editSeverity !== (ruleDetail?.severity ?? 3)) payload.severity = editSeverity;

      if (Object.keys(payload).length === 0) {
        setIsEditing(false);
        return;
      }

      await kacApi.updateCustomRegoRule(rule.id, payload as { name?: string; description?: string; severity?: number; logic?: string });

      // Refetch the rule to get updated data
      const res = await kacApi.getCustomRegoRule(rule.id);
      setRuleDetail(res.data);
      setIsEditing(false);
      onDeleted(); // triggers query invalidation to refresh the policy view
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: unknown } } };
        const detail = axiosErr.response?.data?.detail;
        if (typeof detail === 'string') {
          setSaveError(detail);
        } else if (detail && typeof detail === 'object') {
          const csErrors = (detail as Record<string, unknown>).errors;
          if (Array.isArray(csErrors) && csErrors.length > 0) {
            setSaveError(csErrors.map((e: Record<string, unknown>) => e.message ?? e.code ?? 'Unknown error').join('; '));
          } else {
            setSaveError(JSON.stringify(detail).slice(0, 300));
          }
        } else {
          setSaveError('Failed to update rule.');
        }
      } else if (err instanceof Error) {
        setSaveError(err.message);
      } else {
        setSaveError('Failed to update rule.');
      }
    } finally {
      setIsSaving(false);
    }
  };

  const handleEvaluate = async () => {
    const logic = isEditing ? editLogic : ((ruleDetail?.rule_logic_list as Array<{ logic?: string }> | undefined)?.[0]?.logic ?? '');
    if (!logic.trim() || !manifestYaml.trim()) return;
    setEvalResult(null);
    setEvalError(null);
    setIsEvaluating(true);
    try {
      const res = await kacApi.evaluateRule({ logic, manifest_yaml: manifestYaml });
      setEvalResult(res.data);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { detail?: string } } };
        setEvalError(axiosErr.response?.data?.detail ?? 'Evaluation request failed.');
      } else if (err instanceof Error) {
        setEvalError(err.message);
      } else {
        setEvalError('Evaluation request failed.');
      }
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleDelete = async () => {
    setIsDeleting(true);
    try {
      await kacApi.deleteCustomRules(policyId, [rule.id]);
      try {
        await kacApi.deleteCustomRegoRule(rule.id);
      } catch {
        // If deleting the underlying rule fails (e.g. it's shared), that's OK
      }
      onDeleted();
    } catch {
      // Detach failed
    } finally {
      setIsDeleting(false);
      setShowConfirm(false);
    }
  };

  const displayName = rule.name || `Rule ${rule.id.slice(0, 8)}...`;
  const logic = (ruleDetail?.rule_logic_list as Array<{ logic?: string }> | undefined)?.[0]?.logic;

  return (
    <>
      <div className="rounded-lg border border-[#2e2b3a] bg-[#171520] overflow-hidden">
        {/* Row header */}
        <div className="flex items-center justify-between px-3 py-2">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-gray-200">{displayName}</p>
            {rule.description && (
              <p className="text-[11px] text-gray-500">{rule.description}</p>
            )}
            {!rule.name && (
              <p className="text-[10px] font-mono text-gray-600">{rule.id}</p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <ActionBadge action={rule.action} />
            <button
              onClick={handleToggleExpand}
              title={expanded ? 'Collapse' : 'View Rego'}
              className="rounded-md p-1 text-gray-500 transition-colors hover:bg-[#2e2b3a] hover:text-gray-200"
            >
              {isFetching ? (
                <Loader2 size={12} className="animate-spin" />
              ) : expanded ? (
                <ChevronDown size={12} />
              ) : (
                <Eye size={12} />
              )}
            </button>
            <button
              onClick={() => setShowConfirm(true)}
              disabled={isDeleting}
              title="Remove custom rule"
              className="rounded-md p-1 text-gray-500 transition-colors hover:bg-[#2e2b3a] hover:text-red-400 disabled:opacity-50"
            >
              {isDeleting ? (
                <Loader2 size={12} className="animate-spin" />
              ) : (
                <Trash2 size={12} />
              )}
            </button>
          </div>
        </div>

        {/* Expanded detail panel */}
        {expanded && (
          <div className="border-t border-[#2e2b3a] px-3 py-3 space-y-3">
            {fetchError && (
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                {fetchError}
              </div>
            )}

            {ruleDetail && !isEditing && (
              <>
                {/* Read-only Rego view */}
                <div>
                  <div className="mb-1.5 flex items-center justify-between">
                    <label className="text-xs font-semibold text-gray-300">Rego Policy</label>
                    <button
                      onClick={startEditing}
                      className="inline-flex items-center gap-1 rounded-md border border-[#2e2b3a] px-2 py-1 text-[11px] font-medium text-gray-400 transition-colors hover:bg-[#2e2b3a] hover:text-white"
                    >
                      <Pencil size={11} />
                      Edit
                    </button>
                  </div>
                  <div className="overflow-hidden rounded-lg border border-[#3a3650]">
                    <RegoEditor
                      value={logic ?? '(No logic found)'}
                      onChange={() => {}}
                      height="200px"
                      readOnly
                    />
                  </div>
                </div>

                {/* Metadata */}
                <div className="flex flex-wrap gap-3 text-[11px] text-gray-400">
                  <span>Severity: <span className="text-gray-200">{SEVERITY_OPTIONS.find(s => s.value === ruleDetail.severity)?.label ?? String(ruleDetail.severity)}</span></span>
                  {typeof ruleDetail.created_on === 'string' && <span>Created: <span className="text-gray-200">{new Date(ruleDetail.created_on).toLocaleDateString()}</span></span>}
                  {typeof ruleDetail.modified_on === 'string' && <span>Modified: <span className="text-gray-200">{new Date(ruleDetail.modified_on).toLocaleDateString()}</span></span>}
                </div>
              </>
            )}

            {ruleDetail && isEditing && (
              <>
                {/* Editable fields */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1 block text-xs font-semibold text-gray-200">Name</label>
                    <input
                      type="text"
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs font-semibold text-gray-200">Severity</label>
                    <select
                      value={editSeverity}
                      onChange={(e) => setEditSeverity(Number(e.target.value))}
                      className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
                    >
                      {SEVERITY_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-semibold text-gray-200">Description</label>
                  <input
                    type="text"
                    value={editDescription}
                    onChange={(e) => setEditDescription(e.target.value)}
                    className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 text-sm text-gray-100 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
                  />
                </div>

                {/* Editable Rego editor */}
                <div>
                  <label className="mb-1.5 block text-xs font-semibold text-gray-200">
                    Rego Policy <span className="text-[#ED1C24]">*</span>
                  </label>
                  <div className="overflow-hidden rounded-lg border border-[#3a3650]">
                    <RegoEditor
                      value={editLogic}
                      onChange={setEditLogic}
                      height="280px"
                    />
                  </div>
                </div>

                {saveError && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                    {saveError}
                  </div>
                )}

                {/* Save/Cancel buttons */}
                <div className="flex items-center gap-3">
                  <button
                    onClick={handleSave}
                    disabled={isSaving || !editLogic.trim()}
                    className="inline-flex items-center gap-2 rounded-lg bg-[#ED1C24] px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
                  >
                    {isSaving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                    Save Changes
                  </button>
                  <button
                    onClick={() => { setIsEditing(false); setSaveError(null); }}
                    className="inline-flex items-center gap-2 rounded-lg border border-[#3a3650] px-4 py-2 text-xs font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] hover:text-white"
                  >
                    <X size={14} />
                    Cancel
                  </button>
                </div>
              </>
            )}

            {/* Test Panel (available in both view and edit modes) */}
            {ruleDetail && (
              <div>
                <button
                  type="button"
                  onClick={() => setShowTestPanel((v) => !v)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-400 transition-colors hover:text-gray-200"
                >
                  <FlaskConical size={13} />
                  {showTestPanel ? 'Hide Test Panel' : 'Test Rule Locally'}
                </button>

                {showTestPanel && (
                  <div className="mt-2 space-y-3 rounded-lg border border-[#3a3650] bg-[#1c1928] p-4">
                    <div>
                      <label className="mb-1.5 block text-xs font-semibold text-gray-200">
                        Kubernetes Manifest (YAML)
                      </label>
                      <textarea
                        value={manifestYaml}
                        onChange={(e) => setManifestYaml(e.target.value)}
                        rows={8}
                        placeholder={`apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\nspec:\n  containers:\n  - name: nginx\n    image: nginx:latest`}
                        className="w-full rounded-lg border border-[#3a3650] bg-[#23202e] px-3 py-2 font-mono text-xs text-gray-100 placeholder-gray-600 outline-none focus:border-[#ED1C24]/60 focus:ring-1 focus:ring-[#ED1C24]/30"
                      />
                    </div>

                    <button
                      type="button"
                      onClick={handleEvaluate}
                      disabled={!manifestYaml.trim() || isEvaluating}
                      className="inline-flex items-center gap-2 rounded-lg border border-[#3a3650] bg-[#23202e] px-4 py-2 text-xs font-semibold text-gray-200 transition-colors hover:bg-[#2e2b3a] hover:text-white disabled:opacity-50"
                    >
                      {isEvaluating ? (
                        <Loader2 size={14} className="animate-spin" />
                      ) : (
                        <FlaskConical size={14} />
                      )}
                      Evaluate
                    </button>

                    {evalResult && !evalResult.opa_available && (
                      <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2">
                        <AlertTriangle size={14} className="mt-0.5 shrink-0 text-yellow-400" />
                        <p className="text-xs text-yellow-300">
                          OPA is not installed on the server.{' '}
                          Install it with <code className="rounded bg-[#2e2b3a] px-1 py-0.5 text-yellow-200">brew install opa</code> to enable local rule testing.
                        </p>
                      </div>
                    )}

                    {evalResult && evalResult.opa_available && (
                      <div
                        className={`rounded-lg border px-3 py-2.5 ${
                          evalResult.decision === 'ALLOW'
                            ? 'border-green-500/30 bg-green-500/10'
                            : evalResult.decision === 'DENY'
                            ? 'border-red-500/30 bg-red-500/10'
                            : 'border-yellow-500/30 bg-yellow-500/10'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {evalResult.decision === 'ALLOW' && <CheckCircle2 size={16} className="text-green-400" />}
                          {evalResult.decision === 'DENY' && <XCircle size={16} className="text-red-400" />}
                          {evalResult.decision === 'ERROR' && <AlertTriangle size={16} className="text-yellow-400" />}
                          <span className={`text-sm font-semibold ${
                            evalResult.decision === 'ALLOW' ? 'text-green-400' : evalResult.decision === 'DENY' ? 'text-red-400' : 'text-yellow-400'
                          }`}>
                            {evalResult.decision}
                          </span>
                          {evalResult.manifest_kind && (
                            <span className="text-xs text-gray-400">
                              — {evalResult.manifest_kind}/{evalResult.manifest_name}
                            </span>
                          )}
                        </div>
                        {evalResult.message && <p className="mt-1 text-xs text-gray-300">{evalResult.message}</p>}
                        {evalResult.error && <p className="mt-1 text-xs text-yellow-300">{evalResult.error}</p>}
                      </div>
                    )}

                    {evalError && (
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                        {evalError}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        isOpen={showConfirm}
        title="Remove Custom Rule"
        message={`Remove "${displayName}" from this policy and delete it? This cannot be undone.`}
        confirmLabel="Remove & Delete"
        onConfirm={handleDelete}
        onCancel={() => setShowConfirm(false)}
      />
    </>
  );
}

/* ─── Helper Components ─────────────────────────────────────── */

function RuleList<T>({
  title,
  rules,
  emptyText,
  renderRule,
}: {
  title: string;
  rules: T[];
  emptyText: string;
  renderRule: (rule: T) => React.ReactNode;
}) {
  return (
    <div>
      <h4 className="mb-1.5 text-xs font-semibold text-gray-300">{title}</h4>
      {rules.length === 0 ? (
        <p className="text-[11px] text-gray-500">{emptyText}</p>
      ) : (
        <div className="space-y-1.5">{rules.map(renderRule)}</div>
      )}
    </div>
  );
}

function ActionBadge({ action }: { action: string }) {
  const colors: Record<string, string> = {
    ALLOW: 'bg-green-500/15 text-green-400 border-green-500/30',
    DENY: 'bg-red-500/15 text-red-400 border-red-500/30',
    PREVENT: 'bg-red-500/15 text-red-400 border-red-500/30',
    LOG: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    ALERT: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    DISABLED: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  };
  const cls =
    colors[action.toUpperCase()] ??
    'bg-gray-500/15 text-gray-400 border-gray-500/30';

  return (
    <span
      className={`inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${cls}`}
    >
      {action}
    </span>
  );
}
