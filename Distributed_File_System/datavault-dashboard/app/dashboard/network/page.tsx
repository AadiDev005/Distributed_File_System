'use client';

import { motion } from 'framer-motion';
import NetworkTopology3D from '../../components/network/NetworkTopology3D';

export default function NetworkPage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="apple-headline mb-4">Global Network Operations</h1>
          <p className="apple-subheadline">
            3D visualization of worldwide DataVault infrastructure with real-time monitoring
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <NetworkTopology3D />
        </motion.div>
      </div>
    </div>
  );
}
