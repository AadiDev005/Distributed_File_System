'use client';

import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Users, 
  Database,
  TrendingUp,
  Lock,
  Globe,
  CheckCircle,
  AlertCircle
} from 'lucide-react';

const metrics = [
  {
    title: 'Security Score',
    value: '99.9%',
    change: '+0.1%',
    trend: 'up',
    icon: Shield,
    color: 'text-green-600'
  },
  {
    title: 'Active Users',
    value: '2,847',
    change: '+12%',
    trend: 'up',
    icon: Users,
    color: 'text-blue-600'
  },
  {
    title: 'Data Processed',
    value: '847TB',
    change: '+23%',
    trend: 'up',
    icon: Database,
    color: 'text-purple-600'
  },
  {
    title: 'Compliance Rate',
    value: '100%',
    change: 'Perfect',
    trend: 'stable',
    icon: CheckCircle,
    color: 'text-green-600'
  }
];

const securityModules = [
  { name: 'Quantum Encryption', status: 'Active', level: 100, color: 'green' },
  { name: 'Zero-Trust Gateway', status: 'Online', level: 98, color: 'blue' },
  { name: 'AI Compliance Engine', status: 'Learning', level: 91, color: 'purple' },
  { name: 'Threat Detection', status: 'Monitoring', level: 97, color: 'orange' },
  { name: 'Data Loss Prevention', status: 'Active', level: 99, color: 'green' }
];

export default function DashboardPage() {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="apple-section py-12">
        <motion.div
          className="flex items-center justify-between mb-12"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div>
            <h1 className="apple-headline mb-2">DataVault Dashboard</h1>
            <p className="apple-subheadline">
              Enterprise data security and compliance overview
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-semibold text-gray-900">
              {currentTime.toLocaleTimeString()}
            </div>
            <div className="text-sm text-gray-500">
              {currentTime.toLocaleDateString()}
            </div>
          </div>
        </motion.div>

        {/* Key Metrics */}
        <div className="apple-grid mb-16">
          {metrics.map((metric, index) => (
            <motion.div
              key={metric.title}
              className="metric-card apple-hover"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <div className="flex items-center justify-center mb-4">
                <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center">
                  <metric.icon className={`w-6 h-6 ${metric.color}`} />
                </div>
              </div>
              <div className="metric-value">{metric.value}</div>
              <div className="metric-label mb-2">{metric.title}</div>
              <div className="flex items-center justify-center text-sm text-green-600">
                <TrendingUp className="w-4 h-4 mr-1" />
                {metric.change}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Security Status */}
        <motion.div
          className="apple-card p-8 mb-16"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="flex items-center mb-8">
            <Shield className="w-8 h-8 text-blue-600 mr-3" />
            <div>
              <h2 className="text-2xl font-semibold">Security Systems</h2>
              <p className="text-gray-600">All security modules operating at optimal levels</p>
            </div>
          </div>
          
          <div className="space-y-6">
            {securityModules.map((module, index) => (
              <motion.div
                key={module.name}
                className="flex items-center justify-between"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium">{module.name}</span>
                    <div className="flex items-center">
                      <div className={`status-indicator status-${module.color === 'green' ? 'online' : 'warning'} mr-3`}>
                        {module.status}
                      </div>
                      <span className="text-sm font-semibold">{module.level}%</span>
                    </div>
                  </div>
                  <div className="apple-progress">
                    <motion.div
                      className="apple-progress-fill"
                      initial={{ width: 0 }}
                      animate={{ width: `${module.level}%` }}
                      transition={{ duration: 1, delay: 0.2 * index }}
                      style={{ 
                        backgroundColor: module.color === 'green' ? '#30D158' : 
                                       module.color === 'blue' ? '#007AFF' :
                                       module.color === 'purple' ? '#AF52DE' : '#FF9F0A'
                      }}
                    />
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Business Impact */}
        <motion.div
          className="apple-card p-8 mb-16"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
        >
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">Business Impact</h2>
            <p className="text-gray-600">Enterprise ROI and cost savings</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              { value: '$2.5M', label: 'Annual Savings', sublabel: 'Per enterprise client', color: 'text-green-600' },
              { value: '127', label: 'Enterprise Clients', sublabel: '15 new this month', color: 'text-blue-600' },
              { value: '$75M', label: 'Revenue Target', sublabel: 'Year 3 projection', color: 'text-purple-600' }
            ].map((item, index) => (
              <motion.div
                key={item.label}
                className="text-center p-6 bg-gray-50 rounded-2xl"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.8 + index * 0.1 }}
              >
                <div className={`text-4xl font-semibold mb-2 ${item.color}`}>{item.value}</div>
                <div className="font-medium text-gray-900 mb-1">{item.label}</div>
                <div className="text-sm text-gray-600">{item.sublabel}</div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Global Network Status */}
        <motion.div
          className="apple-card p-8"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9 }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <div className="flex items-center">
                <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse mr-3"></div>
                <div>
                  <div className="font-medium">Global Network</div>
                  <div className="text-sm text-gray-600">All systems operational</div>
                </div>
              </div>
              <div className="flex items-center">
                <Globe className="w-5 h-5 text-blue-600 mr-2" />
                <div>
                  <div className="font-medium">25 Regions</div>
                  <div className="text-sm text-gray-600">Worldwide coverage</div>
                </div>
              </div>
              <div className="flex items-center">
                <Activity className="w-5 h-5 text-green-600 mr-2" />
                <div>
                  <div className="font-medium">99.99% Uptime</div>
                  <div className="text-sm text-gray-600">Enterprise SLA</div>
                </div>
              </div>
            </div>
            <div className="text-sm text-gray-500">
              Last updated: {currentTime.toLocaleTimeString()}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
