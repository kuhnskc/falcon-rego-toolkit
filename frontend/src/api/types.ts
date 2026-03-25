// ── Auth ────────────────────────────────────────────────────
export interface LoginRequest {
  client_id: string;
  client_secret: string;
  base_url: string;
}

export interface LoginResponse {
  authenticated: boolean;
  cloud_environment: string | null;
  base_url: string;
}

export interface AuthStatus {
  authenticated: boolean;
  cloud_environment: string | null;
  base_url: string;
}

// ── CSPM ────────────────────────────────────────────────────
export interface CspmPolicy {
  uuid: string;
  name: string;
  description: string;
  severity: number;
  origin: string;
  created_at: string;
  updated_at: string;
  resource_types: { resource_type: string; service: string }[];
  rule_logic_list: {
    logic: string;
    platform: string;
    remediation_info: string;
  }[];
  alert_info?: string;
}

export interface CspmPolicyCreate {
  name: string;
  description: string;
  logic: string;
  resource_type: string;
  severity: number;
  alert_info: string;
  remediation_info: string;
}

export interface CspmPolicyUpdate {
  description?: string;
  severity?: number;
  logic?: string;
  platform?: string;
  alert_info?: string;
  remediation_info?: string;
}

export interface PolicyTestRequest {
  logic: string;
  resource_type: string;
  num_assets: number;
}

export interface TestResult {
  total_assets: number;
  resource_type: string;
  test_results: { asset_id: string; result: string; error?: string; details?: object }[];
  pass_count: number;
  fail_count: number;
  error_count: number;
  summary: string;
}

// ── KAC ─────────────────────────────────────────────────────
export interface KacPolicy {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  is_enabled: boolean;
  policy_type: string;
  precedence: number;
  host_groups: string[];
  rule_groups: KacRuleGroup[];
}

export interface KacRuleGroup {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  custom_rules: KacCustomRule[];
  default_rules: KacDefaultRule[];
  labels: LabelSelector[];
  namespaces: NamespaceSelector[];
  deny_on_error?: { deny: boolean };
  image_assessment?: { enabled: boolean; unassessed_handling: string };
}

export interface KacCustomRule {
  id: string;
  name: string;
  description: string;
  action: string;
}

export interface KacDefaultRule {
  name: string;
  code: string;
  description: string;
  action: string;
}

export interface LabelSelector {
  key: string;
  operator: string;
  value: string;
}

export interface NamespaceSelector {
  value: string;
}

export interface KacEvaluateResult {
  decision: 'ALLOW' | 'DENY' | 'ERROR';
  message: string;
  opa_available: boolean;
  manifest_kind: string;
  manifest_name: string;
  raw_output: Record<string, unknown> | null;
  error: string | null;
}

// ── Severity ────────────────────────────────────────────────
export const SEVERITY_MAP: Record<number, { label: string; color: string }> = {
  0: { label: 'Critical', color: '#ED1C24' },
  1: { label: 'High', color: '#FD7E14' },
  2: { label: 'Medium', color: '#FFC107' },
  3: { label: 'Informational', color: '#17A2B8' },
};

export const CLOUD_ENVIRONMENTS: Record<string, string> = {
  'US-1': 'https://api.crowdstrike.com',
  'US-2': 'https://api.us-2.crowdstrike.com',
  'EU-1': 'https://api.eu-1.crowdstrike.com',
  'US-GOV-1': 'https://api.laggar.gcw.crowdstrike.com',
  'US-GOV-2': 'https://api.govcloud-us-east-1.crowdstrike.com',
};
