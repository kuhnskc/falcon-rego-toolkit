import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';
import AuthGuard from './components/auth/AuthGuard';
import MainLayout from './components/layout/MainLayout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './components/dashboard/DashboardPage';
import CspmPoliciesPage from './pages/CspmPoliciesPage';
import CspmPolicyDetailPage from './pages/CspmPolicyDetailPage';
import CspmCreatePolicyPage from './pages/CspmCreatePolicyPage';
import KacPoliciesPage from './pages/KacPoliciesPage';
import KacPolicyDetailPage from './pages/KacPolicyDetailPage';
import KacCreatePolicyPage from './pages/KacCreatePolicyPage';
import NotFoundPage from './pages/NotFoundPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />

            <Route element={<AuthGuard />}>
              <Route element={<MainLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="cspm" element={<CspmPoliciesPage />} />
                <Route path="cspm/create" element={<CspmCreatePolicyPage />} />
                <Route path="cspm/:uuid" element={<CspmPolicyDetailPage />} />
                <Route path="kac" element={<KacPoliciesPage />} />
                <Route path="kac/create" element={<KacCreatePolicyPage />} />
                <Route path="kac/:id" element={<KacPolicyDetailPage />} />
              </Route>
            </Route>

            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}
