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
  Settings,
  Power,
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
    { href: '/dashboard', label: 'Command Center', icon: <Home className="w-5 h-5" />, active: pathname === '/dashboard' },
    { href: '/dashboard/security', label: 'Security Matrix', icon: <Shield className="w-5 h-5" />, active: pathname === '/dashboard/security' },
    { href: '/dashboard/compliance', label: 'Compliance Hub', icon: <FileCheck className="w-5 h-5" />, active: pathname === '/dashboard/compliance' },
    { href: '/dashboard/network', label: 'Network Ops', icon: <Network className="w-5 h-5" />, active: pathname === '/dashboard/network' },
  ];

  return (
    <QueryClientProvider client={queryClient}>
      <div className="min-h-screen cyber flex">
        {/* Sidebar */}
        <motion.div 
          className="w-64 cyber-card border-r border-cyan-500/30"
          initial={{ x: -100 }}
          animate={{ x: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Logo Section */}
          <div className="p-6 border-b border-cyan-500/30">
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <h1 className="text-xl font-bold neon-text mb-1">
                DATAVAULT
              </h1>
              <p className="text-xs text-gray-400 font-mono">
                ENTERPRISE.v1.3.0
              </p>
              <div className="mt-3 flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-400">QUANTUM SECURE</span>
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
                      ? 'bg-cyan-500/20 border border-cyan-500/50 neon-text' 
                      : 'text-gray-300 hover:bg-cyan-500/10 hover:text-cyan-400'
                  }`}
                >
                  <span className={item.active ? 'text-cyan-400' : ''}>{item.icon}</span>
                  <span className="font-medium">{item.label}</span>
                  {item.active && (
                    <motion.div
                      className="w-2 h-2 bg-cyan-400 rounded-full ml-auto"
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
          <motion.div 
            className="p-4 mt-8 border-t border-cyan-500/30"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
          >
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
              <div className="cyber-progress mt-4">
                <motion.div
                  className="cyber-progress-fill"
                  initial={{ width: 0 }}
                  animate={{ width: "99%" }}
                  transition={{ duration: 2, delay: 1 }}
                />
              </div>
              <p className="text-xs text-center text-gray-500 mt-2">System Health: 99%</p>
            </div>
          </motion.div>

          {/* Quick Actions */}
          <motion.div 
            className="p-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1 }}
          >
            <div className="space-y-2">
              <button className="cyber-button w-full text-sm">
                <Settings className="w-4 h-4 mr-2" />
                SYSTEM CONFIG
              </button>
              <button className="cyber-button w-full text-sm bg-red-500/20 border-red-500/50 hover:bg-red-500/30">
                <Power className="w-4 h-4 mr-2" />
                EMERGENCY LOCK
              </button>
            </div>
          </motion.div>
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
