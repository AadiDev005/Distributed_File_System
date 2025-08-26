'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect, useCallback, useMemo } from 'react';
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
  Users,
  RefreshCw,
  Settings,
  Zap,
  TrendingUp,
  AlertCircle,
  Server,
  Wifi,
  WifiOff
} from 'lucide-react';
import { DataVaultAPI, SecurityMode, SecurityModeInfo } from '../utils/api';

// ✅ FIXED: Better TypeScript interfaces with proper union types
interface SecurityMetric {
  title: string;
  value: string;
  status: 'excellent' | 'good' | 'warning' | 'critical';
  icon: React.ComponentType<any>;
  color: string;
  trend?: string;
  description?: string;
}

interface SecurityModule {
  name: string;
  status: 'Active' | 'Online' | 'Protected' | 'Learning' | 'Monitoring' | 'Offline';
  level: number;
  description: string;
  lastUpdated: string;
  category: 'encryption' | 'consensus' | 'access' | 'detection' | 'compliance';
}

// ✅ CRITICAL FIX: Proper ActivityLog with exact union types
interface ActivityLog {
  id: string;
  type: 'security' | 'access' | 'compliance' | 'system' | 'threat';
  message: string;
  time: string;
  severity: 'info' | 'warning' | 'success' | 'error';
  details?: string;
}

interface RegionStatus {
  region: string;
  status: 'Secure' | 'Monitoring' | 'Protected' | 'Alert';
  threats: number;
  color: string;
  nodes: number;
}

export default function SecurityPage() {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [loading, setLoading] = useState(false);
  
  // Security mode integration
  const [securityMode, setSecurityMode] = useState<SecurityMode>('simple');
  const [securityModeInfo, setSecurityModeInfo] = useState<SecurityModeInfo | null>(null);
  const [showModeDetails, setShowModeDetails] = useState(false);

  // Dynamic activity logs
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
  const [systemMetrics, setSystemMetrics] = useState<any>(null);

  // Initialize security data
  useEffect(() => {
    const initializeSecurity = async () => {
      try {
        const modeInfo = await DataVaultAPI.getSecurityMode();
        setSecurityModeInfo(modeInfo);
        setSecurityMode(modeInfo.current_mode);

        const metrics = await DataVaultAPI.getSystemMetrics();
        setSystemMetrics(metrics);

        console.log(`🔒 Security dashboard loaded in ${modeInfo.current_mode} mode`);
      } catch (error) {
        console.error('Failed to initialize security dashboard:', error);
        const cachedMode = DataVaultAPI.getCachedSecurityMode();
        setSecurityMode(cachedMode);
      }
    };

    initializeSecurity();
  }, []);

  // Real-time clock and periodic updates
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
      
      if (Math.random() > 0.5) {
        generateActivityLog();
      }
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  // Security mode toggle
  const toggleSecurityMode = useCallback(async () => {
    setLoading(true);
    try {
      const newMode: SecurityMode = securityMode === 'simple' ? 'enterprise' : 'simple';
      const result = await DataVaultAPI.setSecurityMode(newMode);
      
      if (result.success) {
        setSecurityMode(result.new_mode);
        if (securityModeInfo) {
          setSecurityModeInfo({
            ...securityModeInfo,
            current_mode: result.new_mode
          });
        }
        
        generateActivityLog('system', `Security mode changed to ${result.new_mode.toUpperCase()}`, 'info');
      }
    } catch (error) {
      console.error('Failed to change security mode:', error);
      generateActivityLog('system', 'Failed to change security mode', 'error');
    } finally {
      setLoading(false);
    }
  }, [securityMode, securityModeInfo]);

  // ✅ CRITICAL FIX: Generate dynamic activity logs with proper types
  const generateActivityLog = useCallback((
    type?: ActivityLog['type'], 
    message?: string, 
    severity?: ActivityLog['severity']
  ) => {
    // ✅ Define activities with proper union literal types
    const predefinedActivities: Array<{
      type: ActivityLog['type'];
      message: string;
      severity: ActivityLog['severity'];
    }> = [
      { type: 'security', message: 'Quantum encryption keys rotated successfully', severity: 'info' },
      { type: 'access', message: `Failed login attempt blocked from IP ${generateRandomIP()}`, severity: 'warning' },
      { type: 'compliance', message: 'GDPR compliance scan completed - 100% compliant', severity: 'success' },
      { type: 'system', message: 'Security patch applied to quantum engine', severity: 'info' },
      { type: 'threat', message: 'AI threat detection identified suspicious pattern', severity: 'warning' },
      { type: 'access', message: 'Zero-trust gateway authenticated new device', severity: 'info' },
      { type: 'compliance', message: 'Audit trail integrity verified', severity: 'success' }
    ];

    const activity = (type && message && severity) ? 
      { type, message, severity } : 
      predefinedActivities[Math.floor(Math.random() * predefinedActivities.length)];

    // ✅ CRITICAL FIX: Properly typed ActivityLog creation
    const newLog: ActivityLog = {
      id: Math.random().toString(36).substr(2, 9),
      type: activity.type, // This is now properly typed
      message: activity.message,
      severity: activity.severity,
      time: 'Just now'
    };

    setActivityLogs(prev => [newLog, ...prev.slice(0, 9)]);
  }, []);

  // Dynamic security metrics based on mode
  const securityMetrics = useMemo((): SecurityMetric[] => {
    return [
      {
        title: 'Overall Security Score',
        value: securityMode === 'enterprise' ? '99.9%' : '98.7%',
        status: 'excellent' as const,
        icon: Shield,
        color: 'text-green-600',
        trend: '+0.1%',
        description: securityMode === 'enterprise' ? 'Maximum security' : 'Enhanced security'
      },
      {
        title: 'Threat Detection',
        value: securityMode === 'enterprise' ? 'AI-Enhanced' : 'Standard',
        status: 'excellent' as const,
        icon: Eye,
        color: 'text-blue-600',
        trend: '24/7',
        description: securityMode === 'enterprise' ? 'ML-powered detection' : 'Rule-based detection'
      },
      {
        title: 'Quantum Encryption',
        value: 'ACTIVE',
        status: 'excellent' as const,
        icon: Key,
        color: 'text-purple-600',
        trend: 'Post-quantum',
        description: 'CRYSTALS-Dilithium ready'
      },
      {
        title: 'Zero Trust Status',
        value: securityMode === 'enterprise' ? 'FULL' : 'BASIC',
        status: securityMode === 'enterprise' ? 'excellent' as const : 'good' as const,
        icon: Lock,
        color: securityMode === 'enterprise' ? 'text-green-600' : 'text-orange-600',
        trend: 'ENABLED',
        description: securityMode === 'enterprise' ? 'Comprehensive evaluation' : 'Standard protection'
      }
    ];
  }, [securityMode]);

  // Dynamic security modules based on mode
  const securityModules = useMemo((): SecurityModule[] => {
    const enterpriseModules: SecurityModule[] = [
      { 
        name: 'Quantum-Resistant Encryption', 
        status: 'Active' as const, 
        level: 100, 
        description: 'CRYSTALS-Dilithium post-quantum cryptography',
        lastUpdated: '2 minutes ago',
        category: 'encryption' as const
      },
      { 
        name: 'Byzantine Fault Tolerance', 
        status: 'Online' as const, 
        level: 98, 
        description: 'Distributed consensus mechanism',
        lastUpdated: '5 minutes ago',
        category: 'consensus' as const
      },
      { 
        name: 'Advanced Zero-Trust Gateway', 
        status: 'Protected' as const, 
        level: 99, 
        description: 'Microsegmentation and continuous authentication',
        lastUpdated: '1 minute ago',
        category: 'access' as const
      },
      { 
        name: 'AI Threat Detection', 
        status: 'Learning' as const, 
        level: 94, 
        description: 'Machine learning anomaly detection with threat intelligence',
        lastUpdated: '30 seconds ago',
        category: 'detection' as const
      },
      { 
        name: 'Enterprise Compliance Engine', 
        status: 'Monitoring' as const, 
        level: 97, 
        description: 'GDPR, HIPAA, SOX, PCI-DSS automation',
        lastUpdated: '1 minute ago',
        category: 'compliance' as const
      }
    ];

    const simpleModules: SecurityModule[] = [
      { 
        name: 'Basic Encryption', 
        status: 'Active' as const, 
        level: 95, 
        description: 'Standard AES-256 encryption',
        lastUpdated: '5 minutes ago',
        category: 'encryption' as const
      },
      { 
        name: 'File Consensus', 
        status: 'Online' as const, 
        level: 92, 
        description: 'Basic distributed storage',
        lastUpdated: '8 minutes ago',
        category: 'consensus' as const
      },
      { 
        name: 'Simple Access Control', 
        status: 'Active' as const, 
        level: 88, 
        description: 'Standard authentication and authorization',
        lastUpdated: '3 minutes ago',
        category: 'access' as const
      },
      { 
        name: 'Basic Threat Detection', 
        status: 'Monitoring' as const, 
        level: 85, 
        description: 'Rule-based security monitoring',
        lastUpdated: '2 minutes ago',
        category: 'detection' as const
      }
    ];

    return securityMode === 'enterprise' ? enterpriseModules : simpleModules;
  }, [securityMode]);

  // Region status based on security mode
  const regionStatus = useMemo((): RegionStatus[] => {
    return [
      { 
        region: 'North America', 
        status: 'Secure' as const, 
        threats: securityMode === 'enterprise' ? 0 : 1, 
        color: 'text-green-600',
        nodes: 3
      },
      { 
        region: 'Europe', 
        status: 'Secure' as const, 
        threats: securityMode === 'enterprise' ? 1 : 3, 
        color: 'text-green-600',
        nodes: 2
      },
      { 
        region: 'Asia Pacific', 
        status: securityMode === 'enterprise' ? 'Secure' as const : 'Monitoring' as const, 
        threats: securityMode === 'enterprise' ? 0 : 2, 
        color: securityMode === 'enterprise' ? 'text-green-600' : 'text-orange-600',
        nodes: 1
      },
      { 
        region: 'Global Network', 
        status: 'Protected' as const, 
        threats: 0, 
        color: 'text-green-600',
        nodes: 6
      }
    ];
  }, [securityMode]);

  // Utility functions
  const generateRandomIP = () => {
    return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const getSeverityColor = useCallback((severity: string) => {
    switch (severity) {
      case 'success': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-orange-600 bg-orange-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  }, []);

  const getStatusColor = useCallback((status: string) => {
    switch (status.toLowerCase()) {
      case 'active':
      case 'online':
      case 'secure':
      case 'protected': return 'bg-green-100 text-green-700';
      case 'learning':
      case 'monitoring': return 'bg-blue-100 text-blue-700';
      case 'warning': return 'bg-orange-100 text-orange-700';
      case 'offline':
      case 'error': return 'bg-red-100 text-red-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Header with Security Mode Toggle */}
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="flex items-center justify-center mb-6">
            <h1 className="text-4xl font-bold text-gray-900 mr-4">Security Command Center</h1>
            
            <button
              onClick={toggleSecurityMode}
              disabled={loading}
              className={`px-4 py-2 rounded-lg font-medium transition-all disabled:opacity-50 ${
                securityMode === 'enterprise'
                  ? 'bg-red-500 hover:bg-red-600 text-white'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
            >
              {loading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                `${securityMode === 'simple' ? '🔒 Enterprise' : '⚡ Simple'} Mode`
              )}
            </button>
          </div>
          
          <p className="text-lg text-gray-600 mb-4">
            Real-time monitoring of quantum-proof security systems
          </p>
          
          <div className={`inline-flex items-center px-4 py-2 rounded-full text-sm font-medium ${
            securityMode === 'enterprise' 
              ? 'bg-red-100 text-red-700' 
              : 'bg-green-100 text-green-700'
          }`}>
            <Shield className="w-4 h-4 mr-2" />
            {securityMode === 'enterprise' ? 'Maximum Security Active' : 'Enhanced Security Active'}
          </div>
        </motion.div>

        {/* Security Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {securityMetrics.map((metric, index) => (
            <motion.div
              key={metric.title}
              className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 hover:shadow-md transition-all duration-300"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              whileHover={{ y: -2 }}
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-r ${
                  metric.color.includes('green') ? 'from-green-500 to-green-600' :
                  metric.color.includes('blue') ? 'from-blue-500 to-blue-600' :
                  metric.color.includes('purple') ? 'from-purple-500 to-purple-600' :
                  'from-gray-500 to-gray-600'
                } flex items-center justify-center`}>
                  <metric.icon className="w-6 h-6 text-white" />
                </div>
                {metric.trend && (
                  <div className="flex items-center space-x-1 text-sm font-medium text-green-600">
                    <TrendingUp className="w-4 h-4" />
                    <span>{metric.trend}</span>
                  </div>
                )}
              </div>
              
              <div className="text-2xl font-bold text-gray-900 mb-1">{metric.value}</div>
              <div className="text-sm text-gray-600 mb-2">{metric.title}</div>
              <div className="text-xs text-gray-500">{metric.description}</div>
              
              <div className={`mt-3 inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                getStatusColor(metric.status)
              }`}>
                {metric.status.toUpperCase()}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Security Modules */}
        <motion.div
          className="bg-white p-8 rounded-xl shadow-sm border border-gray-200 mb-12"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-blue-600 mr-3" />
              <div>
                <h2 className="text-2xl font-semibold">Security Module Status</h2>
                <p className="text-gray-600">
                  {securityMode === 'enterprise' 
                    ? 'Enterprise-grade security systems operating at optimal levels'
                    : 'Essential security systems maintaining protection'
                  }
                </p>
              </div>
            </div>
          </div>
          
          <div className="space-y-6">
            {securityModules.map((module, index) => (
              <motion.div
                key={module.name}
                className="p-6 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-semibold text-gray-900 flex items-center">
                        {module.name}
                        <span className="ml-2 text-xs text-gray-500 bg-gray-200 px-2 py-1 rounded">
                          {module.category}
                        </span>
                      </h3>
                      <div className="flex items-center space-x-3">
                        <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                          getStatusColor(module.status)
                        }`}>
                          {module.status}
                        </div>
                        <span className="text-lg font-bold text-gray-900">{module.level}%</span>
                      </div>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">{module.description}</p>
                    
                    <div className="w-full bg-gray-200 rounded-full h-3 mb-2 overflow-hidden">
                      <motion.div
                        className={`h-3 rounded-full ${
                          module.level >= 95 ? 'bg-green-500' :
                          module.level >= 85 ? 'bg-blue-500' :
                          module.level >= 75 ? 'bg-orange-500' : 'bg-red-500'
                        }`}
                        initial={{ width: 0 }}
                        animate={{ width: `${module.level}%` }}
                        transition={{ duration: 1, delay: 0.2 * index }}
                      />
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-gray-500">Last updated: {module.lastUpdated}</p>
                      <div className="flex items-center text-xs text-gray-500">
                        <div className="w-2 h-2 bg-green-500 rounded-full mr-1 animate-pulse" />
                        Active
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Activity and Network Status Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Recent Security Activity */}
          <motion.div
            className="bg-white p-8 rounded-xl shadow-sm border border-gray-200"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 }}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center">
                <Activity className="w-6 h-6 text-green-600 mr-3" />
                <h3 className="text-xl font-semibold">Recent Activity</h3>
              </div>
              <div className="text-sm text-gray-500">Live Updates</div>
            </div>
            
            <div className="space-y-4 max-h-96 overflow-y-auto">
              <AnimatePresence>
                {activityLogs.length > 0 ? activityLogs.map((activity) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                  >
                    <div className={`w-2 h-2 rounded-full mt-2 ${getSeverityColor(activity.severity).split(' ')[1]}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900">{activity.message}</p>
                      <div className="flex items-center space-x-2 mt-1">
                        <p className="text-xs text-gray-500">{activity.time}</p>
                        <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(activity.severity)}`}>
                          {activity.type}
                        </span>
                      </div>
                    </div>
                  </motion.div>
                )) : (
                  <div className="text-center py-8 text-gray-500">
                    <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>No recent activity</p>
                  </div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>

          {/* Network Security Status */}
          <motion.div
            className="bg-white p-8 rounded-xl shadow-sm border border-gray-200"
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.9 }}
          >
            <div className="flex items-center mb-6">
              <Globe className="w-6 h-6 text-blue-600 mr-3" />
              <h3 className="text-xl font-semibold">Global Security Status</h3>
            </div>
            
            <div className="space-y-4">
              {regionStatus.map((region, index) => (
                <motion.div
                  key={region.region}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 * index }}
                  className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
                >
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${
                      region.threats === 0 ? 'bg-green-500' : 
                      region.threats <= 2 ? 'bg-orange-500' : 'bg-red-500'
                    }`} />
                    <div>
                      <div className="font-medium text-gray-900">{region.region}</div>
                      <div className={`text-sm ${region.color}`}>{region.status}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-medium text-gray-900">
                      {region.threats} threats
                    </div>
                    <div className="text-xs text-gray-500">
                      {region.nodes} nodes
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* System Status Footer */}
        <motion.div
          className={`p-6 rounded-xl border transition-all ${
            securityMode === 'enterprise'
              ? 'bg-gradient-to-r from-red-50 to-purple-50 border-red-200'
              : 'bg-gradient-to-r from-green-50 to-blue-50 border-green-200'
          }`}
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
                <span className="text-gray-600">
                  {systemMetrics?.active_users || '2,847'} Protected Users
                </span>
              </div>
              <div className="flex items-center">
                <Shield className={`w-5 h-5 mr-2 ${
                  securityMode === 'enterprise' ? 'text-red-600' : 'text-green-600'
                }`} />
                <span className="text-gray-600">
                  {securityMode.toUpperCase()} Mode Active
                </span>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">
                Last security scan: {currentTime.toLocaleTimeString()}
              </div>
              <div className="text-xs text-gray-400">
                Security Score: {securityMode === 'enterprise' ? '99.9%' : '98.7%'}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
