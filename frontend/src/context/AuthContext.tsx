import { createContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { login as apiLogin, logout as apiLogout, getAuthStatus } from '../api/auth';
import type { LoginRequest } from '../api/types';

export interface AuthState {
  authenticated: boolean;
  cloud_environment: string | null;
  base_url: string;
  loading: boolean;
}

export interface AuthContextValue extends AuthState {
  login: (data: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
}

const initialState: AuthState = {
  authenticated: false,
  cloud_environment: null,
  base_url: '',
  loading: true,
};

export const AuthContext = createContext<AuthContextValue>({
  ...initialState,
  login: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(initialState);

  useEffect(() => {
    getAuthStatus()
      .then((res) => {
        setState({
          authenticated: res.data.authenticated,
          cloud_environment: res.data.cloud_environment,
          base_url: res.data.base_url,
          loading: false,
        });
      })
      .catch(() => {
        setState((prev) => ({ ...prev, loading: false }));
      });
  }, []);

  const login = useCallback(async (data: LoginRequest) => {
    const res = await apiLogin(data);
    setState({
      authenticated: res.data.authenticated,
      cloud_environment: res.data.cloud_environment,
      base_url: res.data.base_url,
      loading: false,
    });
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setState({
      authenticated: false,
      cloud_environment: null,
      base_url: '',
      loading: false,
    });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
