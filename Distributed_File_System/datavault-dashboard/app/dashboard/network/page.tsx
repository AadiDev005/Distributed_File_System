'use client';

import { motion } from 'framer-motion';
import { useState, useEffect } from 'react';
import { 
  Globe, 
  Activity, 
  Wifi, 
  Server, 
  Users,
  Shield,
  Zap,
  AlertCircle,
  CheckCircle,
  Clock
} from 'lucide-react';

const networkNodes = [
  { 
    id: 'us-east', 
    name: 'US East', 
    region: 'North America',
    x: '25%', 
    y: '35%', 
    status: 'active', 
    users: 1247,
    latency: '12ms',
    uptime: '99.99%'
  },
  { 
    id: 'eu-central', 
    name: 'EU Central', 
    region: 'Europe',
    x: '55%', 
    y: '25%', 
    status: 'active', 
    users: 843,
    latency: '8ms',
    uptime: '99.98%'
  },
  { 
    id: 'apac', 
    name: 'APAC', 
    region: 'Asia Pacific',
    x: '75%', 
    y: '60%', 
    status: 'active', 
    users: 567,
    latency: '15ms',
    uptime: '99.97%'
  },
  { 
    id: 'us-west', 
    name: 'US West', 
    region: 'North America',
    x: '15%', 
    y: '45%', 
    status: 'active', 
    users: 934,
    latency: '10ms',
    uptime: '99.99%'
  },
  { 
    id: 'brasil', 
    name: 'Brasil', 
    region: 'South America',
    x: '30%', 
    y: '70%', 
    status: 'active', 
    users: 234,
    latency: '18ms',
    uptime: '99.95%'
  }
];

const networkMetrics = [
  {
    title: 'Global Uptime',
    value: '99.98%',
    icon: Activity,
    color: 'text-green-600'
  },
  {
    title: 'Active Nodes',
    value: '25',
    icon: Server,
    color: 'text-blue-600'
  },
  {
    title: 'Connected Users',
    value: '3,825',
    icon: Users,
    color: 'text-purple-600'
  },
  {
    title: 'Avg Latency',
    value: '12ms',
    icon: Zap,
    color: 'text-orange-600'
  }
];

const networkActivity = [
  {
    type: 'connection',
    message: 'New enterprise client connected from Tokyo',
    time: '2 minutes ago',
    severity: 'info'
  },
  {
    type: 'performance',
    message: 'EU Central node performance optimized',
    time: '5 minutes ago',
    severity: 'success'
  },
  {
    type: 'security',
    message: 'DDoS attack mitigated on US East node',
    time: '12 minutes ago',
    severity: 'warning'
  },
  {
    type: 'maintenance',
    message: 'Scheduled maintenance completed on APAC node',
    time: '1 hour ago',
    severity: 'info'
  }
];

export default function NetworkPage() {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
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
          <h1 className="apple-headline mb-4">Global Network Operations</h1>
          <p className="apple-subheadline">
            Real-time monitoring of worldwide DataVault infrastructure
          </p>
        </motion.div>

        {/* Network Metrics */}
        <div className="apple-grid mb-12">
          {networkMetrics.map((metric, index) => (
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
              <div className="text-sm text-gray-600">{metric.title}</div>
            </motion.div>
          ))}
        </div>

        {/* Network Topology */}
        <motion.div
          className="apple-card p-8 mb-12"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="flex items-center mb-8">
            <Globe className="w-8 h-8 text-blue-600 mr-3" />
            <div>
              <h2 className="text-2xl font-semibold">Global Network Topology</h2>
              <p className="text-gray-600">Live view of worldwide DataVault nodes</p>
            </div>
          </div>
          
          <div className="relative h-96 bg-gray-50 rounded-2xl overflow-hidden mb-6">
            {/* World Map Background Effect */}
            <div className="absolute inset-0 opacity-10">
              <div className="w-full h-full bg-gradient-to-r from-blue-100 via-purple-100 to-pink-100"></div>
            </div>
            
            {/* Network Connections */}
            <svg className="absolute inset-0 w-full h-full">
              <defs>
                <linearGradient id="connectionGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#007AFF" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#AF52DE" stopOpacity="0.6" />
                </linearGradient>
              </defs>
              {/* Connection lines between nodes */}
              <motion.line
                x1="25%" y1="35%" x2="55%" y2="25%"
                stroke="url(#connectionGradient)"
                strokeWidth="2"
                strokeDasharray="5,5"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, delay: 1 }}
              />
              <motion.line
                x1="55%" y1="25%" x2="75%" y2="60%"
                stroke="url(#connectionGradient)"
                strokeWidth="2"
                strokeDasharray="5,5"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, delay: 1.2 }}
              />
              <motion.line
                x1="25%" y1="35%" x2="15%" y2="45%"
                stroke="url(#connectionGradient)"
                strokeWidth="2"
                strokeDasharray="5,5"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, delay: 1.4 }}
              />
            </svg>

            {/* Network Nodes */}
            {networkNodes.map((node, index) => (
              <motion.div
                key={node.id}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer"
                style={{ left: node.x, top: node.y }}
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2 * index }}
                onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
              >
                <div className="relative">
                  <motion.div
                    className="w-4 h-4 bg-green-500 rounded-full shadow-lg"
                    animate={{ 
                      boxShadow: [
                        "0 0 10px rgba(34, 197, 94, 0.5)",
                        "0 0 20px rgba(34, 197, 94, 0.8)",
                        "0 0 10px rgba(34, 197, 94, 0.5)"
                      ]
                    }}
                    transition={{ duration: 2, repeat: Infinity }}
                    whileHover={{ scale: 1.2 }}
                  />
                  
                  {/* Node Info Popup */}
                  {selectedNode === node.id && (
                    <motion.div
                      className="absolute bottom-6 left-1/2 transform -translate-x-1/2 bg-white rounded-lg shadow-xl p-4 min-w-48 z-10"
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                    >
                      <div className="text-sm font-semibold text-gray-900 mb-2">{node.name}</div>
                      <div className="space-y-1 text-xs text-gray-600">
                        <div className="flex justify-between">
                          <span>Users:</span>
                          <span className="font-medium">{node.users.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Latency:</span>
                          <span className="font-medium">{node.latency}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Uptime:</span>
                          <span className="font-medium text-green-600">{node.uptime}</span>
                        </div>
                      </div>
                    </motion.div>
                  )}
                  
                  {/* Node Label */}
                  <div className="absolute top-6 left-1/2 transform -translate-x-1/2 whitespace-nowrap">
                    <div className="bg-white/90 backdrop-blur-sm px-2 py-1 rounded text-xs font-medium text-gray-700 shadow-sm">
                      {node.name}
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          {/* Node Details */}
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {networkNodes.map((node, index) => (
              <motion.div
                key={node.id}
                className="p-4 bg-gray-50 rounded-xl apple-hover cursor-pointer"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 * index }}
                onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="font-medium text-gray-900">{node.name}</div>
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                </div>
                <div className="text-xs text-gray-600 space-y-1">
                  <div>{node.region}</div>
                  <div>{node.users.toLocaleString()} users</div>
                  <div className="text-green-600 font-medium">{node.uptime}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Network Activity */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <motion.div
            className="apple-card p-8"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.7 }}
          >
            <div className="flex items-center mb-6">
              <Activity className="w-6 h-6 text-green-600 mr-3" />
              <h3 className="text-xl font-semibold">Network Activity</h3>
            </div>
            
            <div className="space-y-4">
              {networkActivity.map((activity, index) => (
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

          {/* Performance Stats */}
          <motion.div
            className="apple-card p-8"
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.9 }}
          >
            <div className="flex items-center mb-6">
              <Zap className="w-6 h-6 text-orange-600 mr-3" />
              <h3 className="text-xl font-semibold">Performance Metrics</h3>
            </div>
            
            <div className="space-y-6">
              {[
                { label: 'Global Throughput', value: '847 GB/s', progress: 85 },
                { label: 'CPU Usage', value: '23%', progress: 23 },
                { label: 'Memory Usage', value: '45%', progress: 45 },
                { label: 'Network Load', value: '67%', progress: 67 }
              ].map((stat, index) => (
                <div key={stat.label}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-900">{stat.label}</span>
                    <span className="text-sm text-gray-600">{stat.value}</span>
                  </div>
                  <div className="apple-progress">
                    <motion.div
                      className="apple-progress-fill"
                      initial={{ width: 0 }}
                      animate={{ width: `${stat.progress}%` }}
                      transition={{ duration: 1, delay: 0.2 * index }}
                      style={{ 
                        backgroundColor: stat.progress < 50 ? '#30D158' : 
                                       stat.progress < 80 ? '#FF9F0A' : '#FF3B30'
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* Network Status Footer */}
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
                <span className="font-medium text-gray-900">All Nodes Operational</span>
              </div>
              <div className="flex items-center">
                <Wifi className="w-5 h-5 text-blue-600 mr-2" />
                <span className="text-gray-600">25 Active Regions</span>
              </div>
              <div className="flex items-center">
                <Shield className="w-5 h-5 text-purple-600 mr-2" />
                <span className="text-gray-600">Quantum Secured</span>
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
