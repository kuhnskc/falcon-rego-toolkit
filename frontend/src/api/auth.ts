import client from './client';
import type { LoginRequest, LoginResponse, AuthStatus } from './types';

export const login = (data: LoginRequest) =>
  client.post<LoginResponse>('/auth/login', data);

export const logout = () =>
  client.post('/auth/logout');

export const getAuthStatus = () =>
  client.get<AuthStatus>('/auth/status');
