'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { 
  Home, 
  Shield, 
  FileText, 
  FolderOpen,
  Network,
  Settings,
  LogOut,
  Bell,
  Search,
  User,
  Users
} from 'lucide-react';

const navItems = [
  { href: '/dashboard', label: 'Overview', icon: Home },
  { href: '/dashboard/files', label: 'Files', icon: FolderOpen },
  { href: '/dashboard/collaboration', label: 'Collaboration', icon: Users },
  { href: '/dashboard/security', label: 'Security', icon: Shield },
  { href: '/dashboard/compliance', label: 'Compliance', icon: FileText },
  { href: '/dashboard/network', label: 'Network', icon: Network },
];

function AuthGuard({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const auth = localStorage.getItem('datavault-auth');
    if (auth) {
      setIsAuthenticated(true);
    } else {
      router.push('/');
      return;
    }
    setIsLoading(false);
  }, [router]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated ? <>{children}</> : null;
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5000,
        refetchInterval: 15000,
      },
    },
  }));

  const pathname = usePathname();
  const router = useRouter();

  const handleLogout = () => {
    localStorage.removeItem('datavault-auth');
    router.push('/');
  };

  return (
    <AuthGuard>
      <QueryClientProvider client={queryClient}>
        <div className="min-h-screen bg-white">
          <nav className="apple-nav">
            <div className="apple-container">
              <div className="flex items-center justify-between h-16">
                <div className="flex items-center space-x-8">
                  <Link href="/dashboard" className="flex items-center space-x-2">
                    <Shield className="w-6 h-6 text-blue-600" />
                    <span className="text-xl font-semibold">DataVault</span>
                  </Link>
                  
                  <div className="hidden md:flex items-center space-x-1">
                    {navItems.map((item) => {
                      const isActive = pathname === item.href;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                            isActive
                              ? 'bg-blue-100 text-blue-700'
                              : 'text-gray-700 hover:text-blue-600 hover:bg-gray-100'
                          }`}
                        >
                          <item.icon className="w-4 h-4" />
                          <span>{item.label}</span>
                        </Link>
                      );
                    })}
                  </div>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search..."
                      className="w-64 h-9 pl-10 pr-4 text-sm bg-gray-100 rounded-lg border-0 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white"
                    />
                  </div>
                  
                  <button className="relative p-2 text-gray-600 hover:text-gray-900 rounded-lg hover:bg-gray-100">
                    <Bell className="w-5 h-5" />
                    <span className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full"></span>
                  </button>

                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                      <User className="w-4 h-4 text-white" />
                    </div>
                    <button
                      onClick={handleLogout}
                      className="text-sm text-gray-600 hover:text-red-600 transition-colors"
                    >
                      <LogOut className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </nav>

          <main>
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              {children}
            </motion.div>
          </main>
        </div>
      </QueryClientProvider>
    </AuthGuard>
  );
}
