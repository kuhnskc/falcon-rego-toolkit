import client from './client';

export const listPolicies = (filter?: string) =>
  client.get('/kac/policies', { params: filter ? { filter } : {} });

export const getPolicy = (id: string) =>
  client.get(`/kac/policies/${id}`);

export const createPolicy = (name: string, description = '') =>
  client.post('/kac/policies', { name, description });

export const updatePolicy = (id: string, data: { name?: string; description?: string; is_enabled?: boolean }) =>
  client.patch(`/kac/policies/${id}`, data);

export const deletePolicy = (id: string) =>
  client.delete(`/kac/policies/${id}`);

export const updatePrecedence = (id: string, precedence: number) =>
  client.patch(`/kac/policies/${id}/precedence`, { precedence });

export const addHostGroups = (id: string, hostGroupIds: string[]) =>
  client.post(`/kac/policies/${id}/host-groups`, { host_group_ids: hostGroupIds });

export const removeHostGroups = (id: string, hostGroupIds: string[]) =>
  client.delete(`/kac/policies/${id}/host-groups`, { params: { host_group_ids: hostGroupIds } });

export const createRuleGroups = (id: string, groups: { name: string; description?: string }[]) =>
  client.post(`/kac/policies/${id}/rule-groups`, groups);

export const updateRuleGroup = (id: string, groupId: string, data: object) =>
  client.patch(`/kac/policies/${id}/rule-groups/${groupId}`, data);

export const deleteRuleGroups = (id: string, groupIds: string[]) =>
  client.delete(`/kac/policies/${id}/rule-groups`, { params: { rule_group_ids: groupIds } });

export const addCustomRules = (id: string, groupId: string, rules: { rule_id: string; action?: string }[]) =>
  client.post(`/kac/policies/${id}/rule-groups/${groupId}/custom-rules`, rules);

export const deleteCustomRules = (id: string, ruleIds: string[]) =>
  client.delete(`/kac/policies/${id}/custom-rules`, { data: { rule_ids: ruleIds } });

export const updateSelectors = (id: string, groupId: string, data: { labels?: object[]; namespaces?: object[] }) =>
  client.put(`/kac/policies/${id}/rule-groups/${groupId}/selectors`, data);

export const setRuleGroupPrecedence = (id: string, groupIds: string[]) =>
  client.put(`/kac/policies/${id}/rule-groups/precedence`, { rule_group_ids: groupIds });

// ── Custom Rego rule lifecycle (create logic + delete) ──────

export const createCustomRegoRule = (data: {
  name: string;
  description?: string;
  logic: string;
  severity?: number;
  alert_info?: string;
  remediation_info?: string;
}) => client.post('/kac/custom-rego-rules', data);

export const deleteCustomRegoRule = (uuid: string) =>
  client.delete(`/kac/custom-rego-rules/${uuid}`);

export const getCustomRegoRule = (uuid: string) =>
  client.get(`/kac/custom-rego-rules/${uuid}`);

export const updateCustomRegoRule = (uuid: string, data: {
  name?: string;
  description?: string;
  severity?: number;
  logic?: string;
}) => client.patch(`/kac/custom-rego-rules/${uuid}`, data);

// ── Local OPA evaluation (no CrowdStrike auth required) ──────

export const evaluateRule = (data: { logic: string; manifest_yaml: string }) =>
  client.post('/kac/evaluate-rule', data);
