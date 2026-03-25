import client from './client';
import type { CspmPolicyCreate, CspmPolicyUpdate, PolicyTestRequest, TestResult } from './types';

export const listPolicies = () =>
  client.get('/cspm/policies');

export const createPolicy = (data: CspmPolicyCreate) =>
  client.post('/cspm/policies', data);

export const updatePolicy = (uuid: string, data: CspmPolicyUpdate) =>
  client.patch(`/cspm/policies/${uuid}`, data);

export const deletePolicy = (uuid: string) =>
  client.delete(`/cspm/policies/${uuid}`);

export const testPolicy = (data: PolicyTestRequest) =>
  client.post<TestResult>('/cspm/policies/test', data);

export const getSampleAsset = (resourceType: string) =>
  client.get(`/cspm/assets/sample`, { params: { resource_type: resourceType } });

export const getResourceTypes = () =>
  client.get<string[]>('/cspm/resource-types');

export const getInputSchema = (resourceType: string) =>
  client.get('/cspm/input-schema', { params: { resource_type: resourceType } });
