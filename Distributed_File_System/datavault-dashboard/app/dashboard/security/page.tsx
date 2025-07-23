'use client';

import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Activity, 
  AlertTriangle, 
  CheckCircle,
  Eye,
  Key,
  Globe,
  Database,
  Users
} from 'lucide-react';

const securityMetrics = [
  {
    title: 'Overall Security Score',
    value: '99.9%',
    status: 'excellent',
    icon: Shield,
    color: 'text-green-600'
  },
  {
    title: 'Threat Detection',
    value: '24/7',
    status: 'active',
    icon: Eye,
    color: 'text-blue-600'
  },
  {
    title: 'Quantum Encryption',
    value: 'ACTIVE',
    status: 'secured',
    icon: Key,
    color: 'text-purple-600'
  },
  {
    title: 'Zero Trust Status',
    value: 'ENABLED',
    status: 'protected',
    icon: Lock,
    color: 'text-green-600'
  }
];

const securityModules = [
  { 
    name: 'Quantum-Resistant Encryption', 
    status: 'Active', 
    level: 100, 
    description: 'CRYSTALS-Dilithium post-quantum cryptography',
    lastUpdated: '2 minutes ago'
  },
  { 
    name: 'Byzantine Fault Tolerance', 
    status: 'Online', 
    level: 98, 
    description: 'Distributed consensus mechanism',
    lastUpdated: '5 minutes ago'
  },
  { 
    name: 'Zero-Trust Gateway', 
    status: 'Protected', 
    level: 99, 
    description: 'Microsegmentation and continuous auth',
    lastUpdated: '1 minute ago'
  },
  { 
    name: 'AI Threat Detection', 
    status: 'Learning', 
    level: 91, 
    description: 'Machine learning anomaly detection',
    lastUpdated: '30 seconds ago'
  },
  { 
    name: 'Compliance Engine', 
    status: 'Monitoring', 
    level: 97, 
    description: 'GDPR, HIPAA, SOX automation',
    lastUpdated: '1 minute ago'
  }
];

const recentActivity = [
  {
    type: 'security',
    message: 'Quantum encryption keys rotated successfully',
    time: '2 minutes ago',
    severity: 'info'
  },
  {
    type: 'access',
    message: 'Failed login attempt blocked from IP 192.168.1.100',
    time: '5 minutes ago',
    severity: 'warning'
  },
  {
    type: 'compliance',
    message: 'GDPR compliance scan completed - 100% compliant',
    time: '10 minutes ago',
    severity: 'success'
  },
  {
    type: 'system',
    message: 'Security patch applied to quantum engine',
    time: '15 minutes ago',
    severity: 'info'
  }
];

export default function SecurityPage() {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'success': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-orange-600 bg-orange-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        {/* Header */}
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="apple-headline mb-4">Security Command Center</h1>
          <p className="apple-subheadline">
            Real-time monitoring of quantum-proof security systems
          </p>
        </motion.div>

        {/* Security Metrics */}
        <div className="apple-grid mb-12">
          {securityMetrics.map((metric, index) => (
            <motion.div
              key={metric.title}
              className="apple-card p-6 text-center apple-hover"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <metric.icon className={`w-6 h-6 ${metric.color}`} />
              </div>
              <div className="text-2xl font-semibold text-gray-900 mb-2">{metric.value}</div>
              <div className="text-sm text-gray-600 mb-2">{metric.title}</div>
              <div className="status-indicator status-online">
                {metric.status.toUpperCase()}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Security Modules */}
        <motion.div
          className="apple-card p-8 mb-12"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="flex items-center mb-8">
            <Shield className="w-8 h-8 text-blue-600 mr-3" />
            <div>
              <h2 className="text-2xl font-semibold">Security Module Status</h2>
              <p className="text-gray-600">All security systems operating at optimal levels</p>
            </div>
          </div>
          
          <div className="space-y-6">
            {securityModules.map((module, index) => (
              <motion.div
                key={module.name}
                className="p-6 bg-gray-50 rounded-2xl"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-gray-900">{module.name}</h3>
                      <div className="flex items-center space-x-3">
                        <div className="status-indicator status-online">
                          {module.status}
                        </div>
                        <span className="text-sm font-semibold text-gray-900">{module.level}%</span>
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{module.description}</p>
                    <div className="apple-progress mb-2">
                      <motion.div
                        className="apple-progress-fill"
                        initial={{ width: 0 }}
                        animate={{ width: `${module.level}%` }}
                        transition={{ duration: 1, delay: 0.2 * index }}
                      />
                    </div>
                    <p className="text-xs text-gray-500">Last updated: {module.lastUpdated}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Recent Security Activity */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <motion.div
            className="apple-card p-8"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 }}
          >
            <div className="flex items-center mb-6">
              <Activity className="w-6 h-6 text-green-600 mr-3" />
              <h3 className="text-xl font-semibold">Recent Activity</h3>
            </div>
            
            <div className="space-y-4">
              {recentActivity.map((activity, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                  <div className={`w-2 h-2 rounded-full mt-2 ${getSeverityColor(activity.severity).split(' ')[1]}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900">{activity.message}</p>
                    <p className="text-xs text-gray-500">{activity.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Network Security Status */}
          <motion.div
            className="apple-card p-8"
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.9 }}
          >
            <div className="flex items-center mb-6">
              <Globe className="w-6 h-6 text-blue-600 mr-3" />
              <h3 className="text-xl font-semibold">Global Security Status</h3>
            </div>
            
            <div className="space-y-4">
              {[
                { region: 'North America', status: 'Secure', threats: 0, color: 'text-green-600' },
                { region: 'Europe', status: 'Secure', threats: 2, color: 'text-green-600' },
                { region: 'Asia Pacific', status: 'Monitoring', threats: 1, color: 'text-orange-600' },
                { region: 'Global Network', status: 'Protected', threats: 0, color: 'text-green-600' }
              ].map((region, index) => (
                <div key={region.region} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div>
                    <div className="font-medium text-gray-900">{region.region}</div>
                    <div className={`text-sm ${region.color}`}>{region.status}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">{region.threats}</div>
                    <div className="text-xs text-gray-500">Active Threats</div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* System Status Footer */}
        <motion.div
          className="apple-card p-6 mt-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1.1 }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <div className="flex items-center">
                <CheckCircle className="w-5 h-5 text-green-500 mr-2" />
                <span className="font-medium text-gray-900">All Systems Operational</span>
              </div>
              <div className="flex items-center">
                <Database className="w-5 h-5 text-blue-600 mr-2" />
                <span className="text-gray-600">Data Integrity: 100%</span>
              </div>
              <div className="flex items-center">
                <Users className="w-5 h-5 text-purple-600 mr-2" />
                <span className="text-gray-600">2,847 Protected Users</span>
              </div>
            </div>
            <div className="text-sm text-gray-500">
              Last security scan: {currentTime.toLocaleTimeString()}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
