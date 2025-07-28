'use client';

import { motion } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import { DataVaultAPI } from './utils/api';
import { useSystemStore } from './hooks/useSystemStore';
import { useEffect } from 'react';
import CyberDashboard from './components/CyberDashboard';

export default function DashboardPage() {
  const { 
    setHealth, setBFT, setQuantum, setSharding, setZeroTrust, 
    setLoading, setError, updateLastUpdated, error, loading 
  } = useSystemStore();

  const { data, isLoading, error: queryError } = useQuery({
    queryKey: ['systemStatus'],
    queryFn: DataVaultAPI.getAllSystemStatus,
    refetchInterval: 15000,
    retry: 2,
  });

  useEffect(() => {
    setLoading(isLoading);
    if (queryError) {
      setError(queryError.message);
    } else {
      setError(null);
    }

    if (data) {
      setHealth(data.health);
      setBFT(data.bft);
      setQuantum(data.quantum);
      setSharding(data.sharding);
      setZeroTrust(data.zeroTrust);
      updateLastUpdated();
    }
  }, [data, isLoading, queryError, setHealth, setBFT, setQuantum, setSharding, setZeroTrust, setLoading, setError, updateLastUpdated]);

  if (loading) {
    return (
      <div className="min-h-screen cyber-grid flex items-center justify-center">
        <motion.div 
          className="text-center"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
        >
          <div className="relative mb-8">
            <div className="w-24 h-24 border-4 border-cyan-500/30 rounded-full animate-spin border-t-cyan-500"></div>
            <div className="absolute inset-0 w-24 h-24 border-4 border-purple-500/20 rounded-full animate-ping"></div>
          </div>
          <h2 className="text-3xl font-bold neon-text mb-4">INITIALIZING DATAVAULT</h2>
          <p className="text-gray-400 mb-4">Loading quantum-proof security systems...</p>
          <div className="flex justify-center space-x-2">
            {[...Array(5)].map((_, i) => (
              <motion.div
                key={i}
                className="w-2 h-8 bg-cyan-500 rounded-full"
                animate={{ scaleY: [1, 2, 1] }}
                transition={{ duration: 1, repeat: Infinity, delay: i * 0.1 }}
              />
            ))}
          </div>
          <div className="mt-6 text-sm text-gray-500 font-mono">
            Quantum encryption... ACTIVE<br/>
            BFT consensus... ONLINE<br/>
            Zero-trust gateway... SECURED
          </div>
        </motion.div>
      </div>
    );
  }

  return <CyberDashboard />;
}
