'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import { 
  Home, 
  Shield, 
  FileCheck, 
  Network,
  FolderOpen,
  Settings,
  LogOut,
  Activity
} from 'lucide-react';

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

  const navItems = [
    { href: '/dashboard', label: 'Dashboard', icon: <Home className="w-5 h-5" />, active: pathname === '/dashboard' },
    { href: '/dashboard/files', label: 'File Vault', icon: <FolderOpen className="w-5 h-5" />, active: pathname === '/dashboard/files' },
    { href: '/dashboard/security', label: 'Security', icon: <Shield className="w-5 h-5" />, active: pathname === '/dashboard/security' },
    { href: '/dashboard/compliance', label: 'Compliance', icon: <FileCheck className="w-5 h-5" />, active: pathname === '/dashboard/compliance' },
    { href: '/dashboard/network', label: 'Network', icon: <Network className="w-5 h-5" />, active: pathname === '/dashboard/network' },
  ];

  return (
    <QueryClientProvider client={queryClient}>
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex">
        {/* Sidebar */}
        <motion.div 
          className="w-64 bg-white/10 backdrop-blur-md border-r border-white/20 shadow-2xl"
          initial={{ x: -100 }}
          animate={{ x: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Logo */}
          <div className="p-6 border-b border-white/20">
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                DataVault Enterprise
              </h1>
              <p className="text-xs text-gray-400 mt-1">
                Quantum-Proof Security Platform
              </p>
              <div className="mt-3 flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-400">All Systems Operational</span>
              </div>
            </motion.div>
          </div>

          {/* Navigation */}
          <nav className="p-4 space-y-2">
            {navItems.map((item, index) => (
              <motion.div
                key={item.href}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + index * 0.1 }}
              >
                <Link 
                  href={item.href}
                  className={`flex items-center space-x-3 p-3 rounded-lg transition-all duration-300 ${
                    item.active 
                      ? 'bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/50 text-white shadow-lg' 
                      : 'text-gray-300 hover:bg-white/10 hover:text-white'
                  }`}
                >
                  <span className={item.active ? 'text-blue-400' : ''}>{item.icon}</span>
                  <span className="font-medium">{item.label}</span>
                  {item.active && (
                    <motion.div
                      className="w-2 h-2 bg-blue-400 rounded-full ml-auto"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ duration: 0.3 }}
                    />
                  )}
                </Link>
              </motion.div>
            ))}
          </nav>

          {/* System Status */}
          <div className="p-4 mt-8 border-t border-white/20">
            <h3 className="text-sm font-semibold text-gray-400 mb-4">SYSTEM STATUS</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400">Security Level</span>
                <span className="text-xs text-green-400 font-bold">MAXIMUM</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400">Compliance</span>
                <span className="text-xs text-green-400 font-bold">100%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400">Network</span>
                <div className="flex items-center space-x-1">
                  <Activity className="w-3 h-3 text-green-400 animate-pulse" />
                  <span className="text-xs text-green-400 font-bold">ONLINE</span>
                </div>
              </div>
            </div>
          </div>

          {/* User Actions */}
          <div className="absolute bottom-4 left-4 right-4 space-y-2">
            <motion.button
              className="w-full flex items-center space-x-3 p-3 text-gray-300 hover:bg-white/10 hover:text-white rounded-lg transition-all"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <Settings className="w-5 h-5" />
              <span>Settings</span>
            </motion.button>
            <motion.button
              className="w-full flex items-center space-x-3 p-3 text-red-400 hover:bg-red-500/20 hover:text-red-300 rounded-lg transition-all"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => window.location.href = '/auth/login'}
            >
              <LogOut className="w-5 h-5" />
              <span>Logout</span>
            </motion.button>
          </div>
        </motion.div>

        {/* Main Content */}
        <motion.div 
          className="flex-1 overflow-auto"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          {children}
        </motion.div>
      </div>
    </QueryClientProvider>
  );
}
