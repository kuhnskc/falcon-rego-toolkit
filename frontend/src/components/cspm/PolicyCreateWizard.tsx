import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  ChevronLeft,
  ChevronRight,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FlaskConical,
  Rocket,
  Search,
} from 'lucide-react';
import { createPolicy, getResourceTypes, getSampleAsset, testPolicy } from '../../api/cspm';
import type { CspmPolicyCreate, TestResult } from '../../api/types';
import { SEVERITY_MAP } from '../../api/types';
import RegoEditor from '../common/RegoEditor';
import RegoHelpPanel from '../common/RegoHelpPanel';
import TemplatePicker from '../common/TemplatePicker';
import JsonViewer from '../common/JsonViewer';

const TOTAL_STEPS = 8;

const STEP_LABELS = [
  'Name & Description',
  'Resource Type',
  'Sample Asset',
  'Severity',
  'Alert Info',
  'Remediation',
  'Rego Logic',
  'Review & Create',
];

interface WizardData {
  name: string;
  description: string;
  resource_type: string;
  severity: number;
  alert_info: string;
  remediation_info: string;
  logic: string;
}

export default function PolicyCreateWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [data, setData] = useState<WizardData>({
    name: '',
    description: '',
    resource_type: '',
    severity: 2,
    alert_info: '',
    remediation_info: '',
    logic: '',
  });

  // Resource types for step 2
  const resourceTypesQuery = useQuery<string[]>({
    queryKey: ['cspm', 'resource-types'],
    queryFn: () => getResourceTypes().then((res) => res.data),
  });

  // Sample asset for step 3
  const [sampleAsset, setSampleAsset] = useState<unknown>(null);
  const [fetchingSample, setFetchingSample] = useState(false);
  const [sampleError, setSampleError] = useState('');

  // Test for step 8
  const [testResult, setTestResult] = useState<TestResult | null>(null);

  const testMutation = useMutation({
    mutationFn: () =>
      testPolicy({
        logic: data.logic,
        resource_type: data.resource_type,
        num_assets: 5,
      }).then((res) => res.data),
    onSuccess: (result) => setTestResult(result),
  });

  const createMutation = useMutation({
    mutationFn: (payload: CspmPolicyCreate) => createPolicy(payload),
    onSuccess: () => navigate('/cspm'),
  });

  // Resource type search filter
  const [rtSearch, setRtSearch] = useState('');

  const filteredResourceTypes = (resourceTypesQuery.data ?? []).filter((rt) =>
    rt.toLowerCase().includes(rtSearch.toLowerCase()),
  );

  const handleFetchSample = useCallback(async () => {
    if (!data.resource_type) return;
    setFetchingSample(true);
    setSampleError('');
    try {
      const res = await getSampleAsset(data.resource_type);
      setSampleAsset(res.data);
    } catch {
      setSampleError('Failed to fetch sample asset data.');
    } finally {
      setFetchingSample(false);
    }
  }, [data.resource_type]);

  const updateField = useCallback(
    <K extends keyof WizardData>(field: K, value: WizardData[K]) => {
      setData((prev) => ({ ...prev, [field]: value }));
    },
    [],
  );

  // Validation per step
  const isStepValid = useCallback((): boolean => {
    switch (step) {
      case 0:
        return data.name.trim().length > 0;
      case 1:
        return data.resource_type.trim().length > 0;
      case 2:
        return true; // sample asset is optional
      case 3:
        return data.severity >= 0 && data.severity <= 3;
      case 4:
        return data.alert_info.trim().length > 0;
      case 5:
        return data.remediation_info.trim().length > 0;
      case 6:
        return data.logic.trim().length > 0;
      case 7:
        return true;
      default:
        return false;
    }
  }, [step, data]);

  const handleNext = useCallback(() => {
    if (isStepValid() && step < TOTAL_STEPS - 1) {
      setStep((s) => s + 1);
    }
  }, [isStepValid, step]);

  const handlePrev = useCallback(() => {
    if (step > 0) setStep((s) => s - 1);
  }, [step]);

  const handleCreate = useCallback(() => {
    createMutation.mutate({
      name: data.name,
      description: data.description,
      logic: data.logic,
      resource_type: data.resource_type,
      severity: data.severity,
      alert_info: data.alert_info,
      remediation_info: data.remediation_info,
    });
  }, [createMutation, data]);

  const handleTest = useCallback(() => {
    setTestResult(null);
    testMutation.mutate();
  }, [testMutation]);

  return (
    <div className="space-y-6">
      {/* Step Indicator */}
      <div className="flex items-center gap-1">
        {STEP_LABELS.map((label, idx) => (
          <div key={label} className="flex flex-1 flex-col items-center gap-1">
            <div
              className={`h-1.5 w-full rounded-full transition-colors ${
                idx < step
                  ? 'bg-[#ED1C24]'
                  : idx === step
                    ? 'bg-[#ED1C24]/60'
                    : 'bg-[#2e2b3a]'
              }`}
            />
            <span
              className={`text-[10px] ${
                idx === step ? 'font-semibold text-gray-200' : 'text-gray-500'
              }`}
            >
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* Step Content */}
      <div className="rounded-xl border border-[#2e2b3a] bg-[#23202e] p-6">
        {/* Step 1: Name & Description */}
        {step === 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Name & Description</h3>
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
                Policy Name <span className="text-[#ED1C24]">*</span>
              </label>
              <input
                type="text"
                value={data.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="e.g., Ensure S3 bucket logging is enabled"
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium uppercase tracking-wider text-gray-500">
                Description
              </label>
              <textarea
                value={data.description}
                onChange={(e) => updateField('description', e.target.value)}
                rows={4}
                placeholder="Describe what this policy checks..."
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            </div>
          </div>
        )}

        {/* Step 2: Resource Type */}
        {step === 1 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Resource Type</h3>
            <p className="text-sm text-gray-400">
              Select the cloud resource type this policy applies to.
            </p>

            {/* Search */}
            <div className="relative">
              <Search
                size={16}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
              />
              <input
                type="text"
                value={rtSearch}
                onChange={(e) => setRtSearch(e.target.value)}
                placeholder="Search resource types..."
                className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] py-2 pl-9 pr-4 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
              />
            </div>

            {resourceTypesQuery.isLoading && (
              <div className="flex items-center gap-2 py-4 text-gray-400">
                <Loader2 size={16} className="animate-spin" />
                <span className="text-sm">Loading resource types...</span>
              </div>
            )}

            {resourceTypesQuery.isError && (
              <div className="text-sm text-red-400">
                Failed to load resource types. Please try again.
              </div>
            )}

            {resourceTypesQuery.data && (
              <div className="max-h-64 overflow-y-auto rounded-lg border border-[#2e2b3a]">
                {filteredResourceTypes.length === 0 ? (
                  <div className="px-4 py-3 text-sm text-gray-500">No matching resource types.</div>
                ) : (
                  filteredResourceTypes.map((rt) => (
                    <button
                      key={rt}
                      onClick={() => updateField('resource_type', rt)}
                      className={`block w-full px-4 py-2 text-left text-sm transition-colors ${
                        data.resource_type === rt
                          ? 'bg-[#ED1C24]/20 text-white'
                          : 'text-gray-300 hover:bg-[#2e2b3a]'
                      }`}
                    >
                      {rt}
                    </button>
                  ))
                )}
              </div>
            )}

            {data.resource_type && (
              <p className="text-sm text-gray-400">
                Selected: <span className="font-medium text-gray-200">{data.resource_type}</span>
              </p>
            )}
          </div>
        )}

        {/* Step 3: Sample Asset */}
        {step === 2 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Sample Asset Data</h3>
            <p className="text-sm text-gray-400">
              Fetch a sample asset to understand the data structure for writing your Rego logic.
            </p>
            <button
              onClick={handleFetchSample}
              disabled={fetchingSample || !data.resource_type}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
            >
              {fetchingSample ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Search size={14} />
              )}
              Fetch Sample Asset
            </button>
            {sampleError && (
              <div className="text-sm text-red-400">{sampleError}</div>
            )}
            {sampleAsset != null && <JsonViewer data={sampleAsset} title="Sample Asset" />}
          </div>
        )}

        {/* Step 4: Severity */}
        {step === 3 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Severity</h3>
            <p className="text-sm text-gray-400">
              Select the severity level for policy violations.
            </p>
            <div className="space-y-2">
              {Object.entries(SEVERITY_MAP).map(([val, info]) => {
                const numVal = Number(val);
                return (
                  <label
                    key={val}
                    className={`flex cursor-pointer items-center gap-3 rounded-lg border px-4 py-3 transition-colors ${
                      data.severity === numVal
                        ? 'border-[#ED1C24] bg-[#ED1C24]/10'
                        : 'border-[#2e2b3a] hover:border-gray-500'
                    }`}
                  >
                    <input
                      type="radio"
                      name="severity"
                      value={val}
                      checked={data.severity === numVal}
                      onChange={() => updateField('severity', numVal)}
                      className="accent-[#ED1C24]"
                    />
                    <span
                      className={`text-sm font-medium ${
                        data.severity === numVal ? 'text-gray-100' : 'text-gray-300'
                      }`}
                    >
                      {info.label}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 5: Alert Info */}
        {step === 4 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Alert Info</h3>
            <p className="text-sm text-gray-400">
              Provide alert information using pipe-separated values. Each segment separated by{' '}
              <code className="rounded bg-[#2e2b3a] px-1.5 py-0.5 text-xs text-gray-300">|</code>{' '}
              will be rendered as a separate line in the alert details.
            </p>
            <textarea
              value={data.alert_info}
              onChange={(e) => updateField('alert_info', e.target.value)}
              rows={6}
              placeholder="Alert title|Alert description|Recommended action|Additional context"
              className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
            />
          </div>
        )}

        {/* Step 6: Remediation */}
        {step === 5 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Remediation</h3>
            <p className="text-sm text-gray-400">
              Provide remediation steps using pipe-separated values. Each segment separated by{' '}
              <code className="rounded bg-[#2e2b3a] px-1.5 py-0.5 text-xs text-gray-300">|</code>{' '}
              will be rendered as a separate step.
            </p>
            <textarea
              value={data.remediation_info}
              onChange={(e) => updateField('remediation_info', e.target.value)}
              rows={6}
              placeholder="Step 1: Navigate to the resource|Step 2: Enable logging|Step 3: Verify configuration"
              className="w-full rounded-lg border border-[#2e2b3a] bg-[#171520] px-3 py-2 text-sm text-gray-200 placeholder-gray-500 outline-none focus:border-[#ED1C24]/60"
            />
          </div>
        )}

        {/* Step 7: Rego Logic */}
        {step === 6 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold text-gray-100">Rego Logic</h3>
            <p className="text-sm text-gray-400">
              Write the OPA Rego logic that evaluates the cloud resource configuration.
            </p>
            <RegoHelpPanel variant="cspm" />
            <TemplatePicker variant="cspm" onSelect={(code) => updateField('logic', code)} currentCode={data.logic} />
            <RegoEditor
              value={data.logic}
              onChange={(val) => updateField('logic', val)}
              height="500px"
            />
          </div>
        )}

        {/* Step 8: Review & Create */}
        {step === 7 && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-gray-100">Review & Create</h3>

            {/* Summary */}
            <div className="space-y-3 rounded-lg border border-[#2e2b3a] bg-[#171520] p-4">
              <SummaryRow label="Name" value={data.name} />
              <SummaryRow label="Description" value={data.description || '--'} />
              <SummaryRow label="Resource Type" value={data.resource_type} />
              <SummaryRow
                label="Severity"
                value={SEVERITY_MAP[data.severity]?.label ?? 'Unknown'}
              />
              <SummaryRow label="Alert Info" value={data.alert_info || '--'} />
              <SummaryRow label="Remediation" value={data.remediation_info || '--'} />
              <div>
                <span className="text-xs font-medium uppercase tracking-wider text-gray-500">
                  Rego Logic
                </span>
                <div className="mt-1">
                  <RegoEditor value={data.logic} onChange={() => {}} readOnly height="200px" />
                </div>
              </div>
            </div>

            {/* Test */}
            <div className="space-y-3">
              <button
                onClick={handleTest}
                disabled={testMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] disabled:opacity-50"
              >
                {testMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <FlaskConical size={14} />
                )}
                Test Policy
              </button>

              {testMutation.isError && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  Test execution failed.
                </div>
              )}

              {testResult && (
                <div className="space-y-3 rounded-lg border border-[#2e2b3a] p-4">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-2 text-center">
                      <CheckCircle2 size={16} className="mx-auto mb-1 text-green-400" />
                      <p className="text-sm font-bold text-green-400">{testResult.pass_count}</p>
                      <p className="text-[10px] text-green-400/70">Passed</p>
                    </div>
                    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-center">
                      <XCircle size={16} className="mx-auto mb-1 text-red-400" />
                      <p className="text-sm font-bold text-red-400">{testResult.fail_count}</p>
                      <p className="text-[10px] text-red-400/70">Failed</p>
                    </div>
                    <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-2 text-center">
                      <AlertTriangle size={16} className="mx-auto mb-1 text-yellow-400" />
                      <p className="text-sm font-bold text-yellow-400">{testResult.error_count}</p>
                      <p className="text-[10px] text-yellow-400/70">Errors</p>
                    </div>
                  </div>
                  <p className="text-sm text-gray-400">{testResult.summary}</p>
                </div>
              )}
            </div>

            {/* Create */}
            <button
              onClick={handleCreate}
              disabled={createMutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-[#ED1C24] px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#c4161d] disabled:opacity-50"
            >
              {createMutation.isPending ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Rocket size={14} />
              )}
              Create Policy
            </button>

            {createMutation.isError && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                Failed to create policy. Please try again.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Navigation Buttons */}
      <div className="flex items-center justify-between">
        <button
          onClick={handlePrev}
          disabled={step === 0}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[#2e2b3a] px-4 py-2 text-sm font-medium text-gray-300 transition-colors hover:bg-[#2e2b3a] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          <ChevronLeft size={16} />
          Previous
        </button>

        <span className="text-sm text-gray-500">
          Step {step + 1} of {TOTAL_STEPS}
        </span>

        {step < TOTAL_STEPS - 1 && (
          <button
            onClick={handleNext}
            disabled={!isStepValid()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[#ED1C24] px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-[#c4161d] disabled:opacity-30 disabled:cursor-not-allowed"
          >
            Next
            <ChevronRight size={16} />
          </button>
        )}

        {step === TOTAL_STEPS - 1 && <div />}
      </div>
    </div>
  );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wider text-gray-500">{label}</span>
      <p className="mt-0.5 text-sm text-gray-200">{value}</p>
    </div>
  );
}
