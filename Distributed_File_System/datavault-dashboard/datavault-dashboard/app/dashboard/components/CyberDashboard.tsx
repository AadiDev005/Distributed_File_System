'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  Zap, 
  Database, 
  Lock, 
  Cpu, 
  Network,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Globe
} from 'lucide-react';

interface MetricData {
  id: string;
  title: string;
  value: string;
  unit: string;
  change: number;
  status: 'optimal' | 'warning' | 'critical';
  icon: React.ReactNode;
  color: string;
}

const metrics: MetricData[] = [
  {
    id: 'security',
    title: 'Security Level',
    value: '99.99',
    unit: '%',
    change: 0.01,
    status: 'optimal',
    icon: <Shield className="w-6 h-6" />,
    color: 'cyber-blue'
  },
  {
    id: 'efficiency',
    title: 'System Efficiency',
    value: '94.7',
    unit: '%',
    change: 2.3,
    status: 'optimal',
    icon: <Zap className="w-6 h-6" />,
    color: 'cyber-green'
  },
  {
    id: 'quantum',
    title: 'Quantum Resistance',
    value: 'ACTIVE',
    unit: '',
    change: 0,
    status: 'optimal',
    icon: <Cpu className="w-6 h-6" />,
    color: 'cyber-purple'
  },
  {
    id: 'compliance',
    title: 'Compliance Score',
    value: '100',
    unit: '%',
    change: 0,
    status: 'optimal',
    icon: <CheckCircle2 className="w-6 h-6" />,
    color: 'cyber-pink'
  }
];

function StatusIndicator({ status }: { status: 'optimal' | 'warning' | 'critical' }) {
  const colors = {
    optimal: 'bg-green-500',
    warning: 'bg-yellow-500', 
    critical: 'bg-red-500'
  };

  return (
    <div className={`w-3 h-3 rounded-full ${colors[status]} animate-pulse`} />
  );
}

function MetricCard({ metric }: { metric: MetricData }) {
  return (
    <motion.div
      className="cyber-card rounded-lg p-6 relative group cursor-pointer"
      whileHover={{ scale: 1.02, y: -5 }}
      transition={{ duration: 0.2 }}
    >
      {/* Background Animation */}
      <div className="absolute inset-0 holographic opacity-0 group-hover:opacity-100 transition-opacity duration-500 rounded-lg" />
      
      {/* Content */}
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className={`p-2 rounded-lg bg-${metric.color}/20 text-${metric.color}`}>
            {metric.icon}
          </div>
          <StatusIndicator status={metric.status} />
        </div>
        
        <div className="space-y-2">
          <h3 className="text-gray-300 text-sm font-medium">{metric.title}</h3>
          <div className="flex items-baseline space-x-1">
            <span className={`text-3xl font-bold neon-text`}>
              {metric.value}
            </span>
            {metric.unit && <span className="text-lg text-gray-400">{metric.unit}</span>}
          </div>
          {metric.change > 0 && (
            <div className="flex items-center text-green-400 text-sm">
              <TrendingUp className="w-4 h-4 mr-1" />
              +{metric.change}%
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

function NetworkVisualization() {
  const [nodes] = useState([
    { id: 1, x: 50, y: 30, status: 'active', label: 'Primary Node' },
    { id: 2, x: 20, y: 70, status: 'active', label: 'BFT Node 1' },
    { id: 3, x: 80, y: 70, status: 'active', label: 'BFT Node 2' },
    { id: 4, x: 50, y: 90, status: 'active', label: 'Quantum Engine' },
  ]);

  return (
    <div className="cyber-card rounded-lg p-6 h-80">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-xl font-bold neon-text">Network Topology</h3>
        <div className="flex items-center space-x-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <span className="text-cyan-400 text-sm">Live Network View</span>
        </div>
      </div>
      
      <div className="relative w-full h-48 cyber-grid rounded-lg overflow-hidden">
        {/* Connections */}
        <svg className="absolute inset-0 w-full h-full">
          <defs>
            <linearGradient id="connectionGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#00ffff" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#bf00ff" stopOpacity="0.8" />
            </linearGradient>
          </defs>
          {nodes.map(node => 
            nodes.slice(1).map(targetNode => (
              <motion.line
                key={`${node.id}-${targetNode.id}`}
                x1={`${node.x}%`}
                y1={`${node.y}%`}
                x2={`${targetNode.x}%`}
                y2={`${targetNode.y}%`}
                stroke="url(#connectionGradient)"
                strokeWidth="2"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, delay: node.id * 0.3 }}
              />
            ))
          )}
        </svg>
        
        {/* Nodes */}
        {nodes.map(node => (
          <motion.div
            key={node.id}
            className="absolute transform -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.5, delay: node.id * 0.2 }}
          >
            <div className="relative">
              <div className="w-8 h-8 bg-cyan-500 rounded-full flex items-center justify-center shadow-lg">
                <div className="w-4 h-4 bg-white rounded-full animate-pulse" />
              </div>
              <div className="absolute top-10 left-1/2 transform -translate-x-1/2 whitespace-nowrap">
                <span className="text-xs text-gray-300 bg-black/50 px-2 py-1 rounded">
                  {node.label}
                </span>
              </div>
              {/* Pulse Effect */}
              <div className="absolute inset-0 w-8 h-8 bg-cyan-500 rounded-full animate-ping opacity-20" />
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

function SecurityLayers() {
  const layers = [
    { name: 'Quantum Encryption', status: 'active', progress: 100 },
    { name: 'Zero Trust Gateway', status: 'active', progress: 98 },
    { name: 'BFT Consensus', status: 'active', progress: 95 },
    { name: 'Behavioral Analytics', status: 'active', progress: 92 },
    { name: 'Audit Trail', status: 'active', progress: 100 },
  ];

  return (
    <div className="cyber-card rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-xl font-bold neon-purple">Security Layers</h3>
        <div className="flex items-center space-x-2">
          <Lock className="w-5 h-5 text-purple-400" />
          <span className="text-purple-400 text-sm">11/11 Active</span>
        </div>
      </div>
      
      <div className="space-y-4">
        {layers.map((layer, index) => (
          <motion.div
            key={layer.name}
            className="space-y-2"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <div className="flex items-center justify-between">
              <span className="text-gray-300 text-sm">{layer.name}</span>
              <span className="text-cyan-400 text-sm">{layer.progress}%</span>
            </div>
            <div className="cyber-progress">
              <motion.div
                className="cyber-progress-fill"
                initial={{ width: 0 }}
                animate={{ width: `${layer.progress}%` }}
                transition={{ duration: 1, delay: index * 0.1 }}
              />
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

export default function CyberDashboard() {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-transparent p-6 space-y-6">
      {/* Header */}
      <motion.div
        className="flex items-center justify-between mb-8"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
      >
        <div>
          <h1 className="text-4xl font-bold neon-text mb-2">
            DATAVAULT ENTERPRISE
          </h1>
          <p className="text-gray-400">Quantum-Proof Security • Real-time Monitoring</p>
        </div>
        <div className="text-right">
          <div className="text-cyan-400 font-mono text-lg">
            {currentTime.toLocaleTimeString()}
          </div>
          <div className="text-gray-400 text-sm">
            {currentTime.toLocaleDateString()}
          </div>
        </div>
      </motion.div>

      {/* Metrics Grid */}
      <motion.div
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        variants={{
          hidden: { opacity: 0 },
          show: {
            opacity: 1,
            transition: {
              staggerChildren: 0.1
            }
          }
        }}
        initial="hidden"
        animate="show"
      >
        {metrics.map((metric) => (
          <motion.div
            key={metric.id}
            variants={{
              hidden: { opacity: 0, y: 20 },
              show: { opacity: 1, y: 0 }
            }}
          >
            <MetricCard metric={metric} />
          </motion.div>
        ))}
      </motion.div>

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Visualization */}
        <motion.div
          className="lg:col-span-2"
          initial={{ opacity: 0, x: -50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
        >
          <NetworkVisualization />
        </motion.div>

        {/* Security Layers */}
        <motion.div
          initial={{ opacity: 0, x: 50 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
        >
          <SecurityLayers />
        </motion.div>
      </div>

      {/* Business Impact Section */}
      <motion.div
        className="cyber-card rounded-lg p-8"
        initial={{ opacity: 0, y: 50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8, delay: 0.8 }}
      >
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold neon-pink mb-4">Enterprise Impact Dashboard</h2>
          <p className="text-gray-400">Real-time business metrics and ROI tracking</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="text-center p-6 rounded-lg bg-gradient-to-b from-blue-900/20 to-purple-900/20 border border-cyan-500/30">
            <div className="text-4xl font-bold neon-text mb-2">$2.5M</div>
            <div className="text-gray-300 mb-1">Annual Savings per Client</div>
            <div className="text-green-400 text-sm">↑ 60% compliance cost reduction</div>
          </div>

          <div className="text-center p-6 rounded-lg bg-gradient-to-b from-purple-900/20 to-pink-900/20 border border-purple-500/30">
            <div className="text-4xl font-bold neon-purple mb-2">127</div>
            <div className="text-gray-300 mb-1">Enterprise Clients</div>
            <div className="text-green-400 text-sm">↑ 15 new this month</div>
          </div>

          <div className="text-center p-6 rounded-lg bg-gradient-to-b from-pink-900/20 to-red-900/20 border border-pink-500/30">
            <div className="text-4xl font-bold neon-pink mb-2">$75M</div>
            <div className="text-gray-300 mb-1">Revenue Target (Year 3)</div>
            <div className="text-green-400 text-sm">↑ On track for unicorn status</div>
          </div>
        </div>
      </motion.div>

      {/* System Status Bar */}
      <motion.div
        className="cyber-card rounded-lg p-4 data-stream"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 1 }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Globe className="w-5 h-5 text-green-400" />
              <span className="text-green-400 text-sm">Global Network: ONLINE</span>
            </div>
            <div className="flex items-center space-x-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              <span className="text-cyan-400 text-sm">All Systems: OPERATIONAL</span>
            </div>
            <div className="flex items-center space-x-2">
              <Database className="w-5 h-5 text-purple-400" />
              <span className="text-purple-400 text-sm">Data Integrity: 100%</span>
            </div>
          </div>
          <div className="text-gray-400 text-sm font-mono">
            Uptime: 99.99% | Last Update: {currentTime.toLocaleTimeString()}
          </div>
        </div>
      </motion.div>
    </div>
  );
}
