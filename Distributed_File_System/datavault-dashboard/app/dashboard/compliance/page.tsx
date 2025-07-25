'use client';

import { motion } from 'framer-motion';
import ComplianceDashboard from '../../components/compliance/ComplianceDashboard';

export default function CompliancePage() {
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <ComplianceDashboard />
        </motion.div>
      </div>
    </div>
  );
}
