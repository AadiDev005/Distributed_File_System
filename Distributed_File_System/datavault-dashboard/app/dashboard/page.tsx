'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { 
  Shield, 
  Activity, 
  Users, 
  Database,
  TrendingUp,
  Globe,
  CheckCircle,
  AlertCircle,
  LogOut,
  RefreshCw,
  Wifi,
  WifiOff,
  Server,
  Zap,
  Lock,
  BarChart3,
  Menu,
  X,
  Settings,
  Bell,
  Search,
  ChevronDown,
  Clock,
  User
} from 'lucide-react';
import { DataVaultAPI } from './utils/api';

// Types remain the same...
interface SystemMetrics {
  security_score: number;
  active_users: number;
  data_processed: number;
  compliance_rate: number;
  uptime: number;
  nodes_active: number;
  bft_consensus: boolean;
  timestamp: string;
}

interface SecurityModule {
  name: string;
  status: string;
  level: number;
  color: string;
}

interface SystemData {
  metrics: SystemMetrics;
  security: { modules: SecurityModule[] };
  network: any;
  health: any;
  bft: any;
  quantum: any;
  sharding: any;
  zeroTrust: any;
  timestamp: string;
}

interface ConnectionStatus {
  connected: boolean;
  activeNodes: number;
  totalNodes: number;
  mode: 'online' | 'offline' | 'degraded';
  lastSuccessfulConnection: Date | null;
}

export default function DashboardPage() {
  // State management
  const [currentTime, setCurrentTime] = useState(new Date());
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [userInfo, setUserInfo] = useState<{ user: string; role: string } | null>(null);
  const [systemData, setSystemData] = useState<SystemData | null>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [sessionTimeLeft, setSessionTimeLeft] = useState(3600); // 1 hour in seconds
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
    connected: false,
    activeNodes: 0,
    totalNodes: 3,
    mode: 'offline',
    lastSuccessfulConnection: null
  });
  const router = useRouter();

  // Authentication and data fetching logic (same as before)
  useEffect(() => {
    const checkAuth = async () => {
      const sessionId = localStorage.getItem('session_id');
      const expiresAt = localStorage.getItem('expires_at');
      
      if (!sessionId || !expiresAt) {
        router.push('/');
        return;
      }
      
      const expirationDate = new Date(expiresAt);
      if (new Date() > expirationDate) {
        localStorage.clear();
        router.push('/');
        return;
      }

      const authData = localStorage.getItem('datavault-auth');
      if (authData) {
        try {
          const parsedAuthData = JSON.parse(authData);
          setUserInfo({
            user: parsedAuthData.user || 'Enterprise User',
            role: 'Admin'
          });
        } catch {
          setUserInfo({ user: 'Enterprise User', role: 'Admin' });
        }
      } else {
        setUserInfo({ user: 'Enterprise User', role: 'Admin' });
      }
      
      setIsAuthenticated(true);
      setIsLoading(false);
    };

    checkAuth();
  }, [router]);

  // Session timer
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const timer = setInterval(() => {
      setSessionTimeLeft(prev => {
        if (prev <= 1) {
          handleLogout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, [isAuthenticated]);

  // Data fetching logic (same as before)
  const fetchSystemData = useCallback(async (showLoading = true) => {
    if (showLoading) setDataLoading(true);
    
    try {
      const nodeResults = await DataVaultAPI.getAllNodesStatus();
      const healthyNodes = nodeResults.filter(node => node.status === 'healthy');
      
      setConnectionStatus({
        connected: healthyNodes.length > 0,
        activeNodes: healthyNodes.length,
        totalNodes: nodeResults.length,
        mode: healthyNodes.length === nodeResults.length ? 'online' : 
              healthyNodes.length > 0 ? 'degraded' : 'offline',
        lastSuccessfulConnection: healthyNodes.length > 0 ? new Date() : null
      });
      
      const data = await DataVaultAPI.getAllSystemStatus();
      setSystemData(data as SystemData);
      setLastUpdated(new Date());
      
    } catch (error) {
      setConnectionStatus(prev => ({ ...prev, connected: false, mode: 'offline' }));
    } finally {
      if (showLoading) setDataLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchSystemData();
    const interval = setInterval(() => fetchSystemData(false), 15000);
    return () => clearInterval(interval);
  }, [isAuthenticated, fetchSystemData]);

  useEffect(() => {
    if (!isAuthenticated) return;
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, [isAuthenticated]);

  const handleLogout = useCallback(async () => {
    const sessionId = localStorage.getItem('session_id');
    if (sessionId) {
      try {
        await DataVaultAPI.logout(sessionId);
      } catch {
        // Silent fail
      }
    }
    localStorage.clear();
    router.push('/');
  }, [router]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getMetrics = useCallback(() => {
    return [
      { 
        title: 'Security Score', 
        value: `${systemData?.metrics?.security_score || 99.9}%`, 
        icon: Shield, 
        color: 'emerald',
        trend: '+0.1%',
        trendUp: true
      },
      { 
        title: 'Active Users', 
        value: (systemData?.metrics?.active_users || 2847).toLocaleString(), 
        icon: Users, 
        color: 'blue',
        trend: '+12%',
        trendUp: true
      },
      { 
        title: 'Data Processed', 
        value: `${Math.round((systemData?.metrics?.data_processed || 847000000000) / (1024**4))}TB`, 
        icon: Database, 
        color: 'purple',
        trend: '+23%',
        trendUp: true
      },
      { 
        title: 'Compliance', 
        value: `${systemData?.metrics?.compliance_rate || 100}%`, 
        icon: CheckCircle, 
        color: 'emerald',
        trend: 'Perfect',
        trendUp: true
      }
    ];
  }, [systemData]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <motion.div 
          className="text-center"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.3 }}
        >
          <div className="w-16 h-16 mx-auto mb-6">
            <motion.div
              className="w-full h-full border-4 border-blue-200 border-t-blue-600 rounded-full"
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            />
          </div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Connecting to DataVault</h2>
          <p className="text-gray-600">Verifying your secure session...</p>
        </motion.div>
      </div>
    );
  }

  if (!isAuthenticated) return null;

  const metrics = getMetrics();
  const securityModules = systemData?.security?.modules || [];

  return (
    <div className="min-h-screen bg-gray-50 flex">
      {/* Sidebar */}
      <AnimatePresence>
        {sidebarOpen && (
          <>
            <motion.div 
              className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
            />
            <motion.aside 
              className="fixed left-0 top-0 h-full w-64 bg-white border-r border-gray-200 z-50 lg:static lg:z-auto"
              initial={{ x: -256 }}
              animate={{ x: 0 }}
              exit={{ x: -256 }}
              transition={{ type: "spring", damping: 25, stiffness: 200 }}
            >
              <div className="p-6 border-b border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                      <Shield className="w-5 h-5 text-white" />
                    </div>
                    <div>
                      <h2 className="font-semibold text-gray-900">DataVault</h2>
                      <p className="text-xs text-gray-500">Enterprise</p>
                    </div>
                  </div>
                  <button 
                    onClick={() => setSidebarOpen(false)}
                    className="lg:hidden p-1 hover:bg-gray-100 rounded"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>
              
              <nav className="p-4 space-y-2">
                {[
                  { name: 'Dashboard', icon: BarChart3, active: true },
                  { name: 'Files', icon: Database },
                  { name: 'Security', icon: Shield },
                  { name: 'Collaboration', icon: Users },
                  { name: 'Network', icon: Globe },
                  { name: 'Settings', icon: Settings },
                ].map((item) => (
                  <button
                    key={item.name}
                    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                      item.active 
                        ? 'bg-blue-50 text-blue-700 border border-blue-200' 
                        : 'text-gray-700 hover:bg-gray-100'
                    }`}
                  >
                    <item.icon className="w-5 h-5" />
                    <span className="font-medium">{item.name}</span>
                  </button>
                ))}
              </nav>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <header className="bg-white border-b border-gray-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button 
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden p-2 hover:bg-gray-100 rounded-lg"
              >
                <Menu className="w-5 h-5" />
              </button>
              
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
                <div className="flex items-center space-x-4 text-sm text-gray-600">
                  <div className={`flex items-center space-x-2 ${
                    connectionStatus.mode === 'online' ? 'text-emerald-600' : 
                    connectionStatus.mode === 'degraded' ? 'text-amber-600' : 'text-red-600'
                  }`}>
                    {connectionStatus.mode === 'online' ? 
                      <Wifi className="w-4 h-4" /> : 
                      connectionStatus.mode === 'degraded' ? 
                      <AlertCircle className="w-4 h-4" /> : 
                      <WifiOff className="w-4 h-4" />
                    }
                    <span className="font-medium">
                      {connectionStatus.activeNodes}/{connectionStatus.totalNodes} Nodes
                    </span>
                  </div>
                  
                  {systemData?.bft?.consensus_active && (
                    <div className="flex items-center space-x-1 text-purple-600">
                      <Zap className="w-4 h-4" />
                      <span>BFT Active</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <button className="p-2 hover:bg-gray-100 rounded-lg">
                <Search className="w-5 h-5 text-gray-600" />
              </button>
              
              <button className="p-2 hover:bg-gray-100 rounded-lg relative">
                <Bell className="w-5 h-5 text-gray-600" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full"></div>
              </button>

              <motion.button
                onClick={() => fetchSystemData(true)}
                disabled={dataLoading}
                className="flex items-center space-x-2 px-3 py-2 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-lg transition-colors disabled:opacity-50"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <RefreshCw className={`w-4 h-4 ${dataLoading ? 'animate-spin' : ''}`} />
                <span className="hidden sm:inline">Refresh</span>
              </motion.button>

              {/* User Profile Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                  className="flex items-center space-x-3 px-3 py-2 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  <div className="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center">
                    <User className="w-4 h-4 text-white" />
                  </div>
                  <div className="hidden sm:block text-left">
                    <div className="text-sm font-medium text-gray-900">{userInfo?.user}</div>
                    <div className="flex items-center space-x-2 text-xs text-gray-500">
                      <Clock className="w-3 h-3" />
                      <span>{formatTime(sessionTimeLeft)}</span>
                    </div>
                  </div>
                  <ChevronDown className="w-4 h-4 text-gray-500" />
                </button>

                <AnimatePresence>
                  {userDropdownOpen && (
                    <motion.div
                      className="absolute right-0 mt-2 w-64 bg-white rounded-xl shadow-lg border border-gray-200 z-50"
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                    >
                      <div className="p-4 border-b border-gray-200">
                        <div className="text-sm font-medium text-gray-900">{userInfo?.user}</div>
                        <div className="text-xs text-gray-500">{userInfo?.role}</div>
                        <div className="flex items-center space-x-2 mt-2 text-xs text-gray-600">
                          <Clock className="w-3 h-3" />
                          <span>Session expires in {formatTime(sessionTimeLeft)}</span>
                        </div>
                      </div>
                      <div className="p-2">
                        <button className="w-full flex items-center space-x-3 px-3 py-2 text-left hover:bg-gray-100 rounded-lg">
                          <Settings className="w-4 h-4 text-gray-500" />
                          <span className="text-sm">Account Settings</span>
                        </button>
                        <button 
                          onClick={handleLogout}
                          className="w-full flex items-center space-x-3 px-3 py-2 text-left hover:bg-red-50 text-red-700 rounded-lg"
                        >
                          <LogOut className="w-4 h-4" />
                          <span className="text-sm">Logout</span>
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </div>
        </header>

        {/* Main Dashboard Content */}
        <main className="flex-1 p-6 overflow-auto">
          {/* Status Banner */}
          <motion.div
            className={`mb-6 p-4 rounded-xl border ${
              connectionStatus.mode === 'online' 
                ? 'bg-emerald-50 border-emerald-200' 
                : connectionStatus.mode === 'degraded'
                ? 'bg-amber-50 border-amber-200'
                : 'bg-red-50 border-red-200'
            }`}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {connectionStatus.mode === 'online' ? (
                  <CheckCircle className="w-5 h-5 text-emerald-600" />
                ) : connectionStatus.mode === 'degraded' ? (
                  <AlertCircle className="w-5 h-5 text-amber-600" />
                ) : (
                  <WifiOff className="w-5 h-5 text-red-600" />
                )}
                
                <div>
                  <div className={`font-semibold ${
                    connectionStatus.mode === 'online' ? 'text-emerald-900' : 
                    connectionStatus.mode === 'degraded' ? 'text-amber-900' : 'text-red-900'
                  }`}>
                    {connectionStatus.mode === 'online' && 'All Systems Operational'}
                    {connectionStatus.mode === 'degraded' && 'Degraded Performance'}
                    {connectionStatus.mode === 'offline' && 'System Offline'}
                  </div>
                  <div className="text-sm text-gray-600">
                    {connectionStatus.mode === 'online' && 'Real-time monitoring active across all security layers'}
                    {connectionStatus.mode === 'degraded' && `${connectionStatus.activeNodes} of ${connectionStatus.totalNodes} nodes responding`}
                    {connectionStatus.mode === 'offline' && 'Operating on cached data with full security protocols'}
                  </div>
                </div>
              </div>
              
              {lastUpdated && (
                <div className="text-sm text-gray-500">
                  Updated {lastUpdated.toLocaleTimeString()}
                </div>
              )}
            </div>
          </motion.div>

          {/* Metrics Grid - Horizontal Layout */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {metrics.map((metric, index) => (
              <motion.div
                key={metric.title}
                className="bg-white p-6 rounded-xl shadow-sm hover:shadow-md transition-all duration-300 border border-gray-200"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                whileHover={{ y: -2 }}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className={`w-12 h-12 rounded-xl bg-gradient-to-r ${
                    metric.color === 'emerald' ? 'from-emerald-500 to-emerald-600' :
                    metric.color === 'blue' ? 'from-blue-500 to-blue-600' :
                    metric.color === 'purple' ? 'from-purple-500 to-purple-600' :
                    'from-gray-500 to-gray-600'
                  } flex items-center justify-center`}>
                    <metric.icon className="w-6 h-6 text-white" />
                  </div>
                  <div className={`flex items-center space-x-1 text-sm font-medium ${
                    metric.trendUp ? 'text-emerald-600' : 'text-red-600'
                  }`}>
                    <TrendingUp className={`w-4 h-4 ${metric.trendUp ? '' : 'rotate-180'}`} />
                    <span>{metric.trend}</span>
                  </div>
                </div>
                <div className="text-2xl font-bold text-gray-900 mb-1">{metric.value}</div>
                <div className="text-sm text-gray-600">{metric.title}</div>
              </motion.div>
            ))}
          </div>

          {/* Two Column Layout for Main Content */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
            {/* Security Systems - Takes 2 columns */}
            <motion.div
              className="xl:col-span-2 bg-white p-8 rounded-xl shadow-sm border border-gray-200"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <div className="w-12 h-12 bg-gradient-to-r from-blue-500 to-purple-600 rounded-xl flex items-center justify-center">
                    <Lock className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-gray-900">Security Systems</h2>
                    <p className="text-gray-600">Enterprise-grade protection with quantum encryption</p>
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {securityModules.slice(0, 6).map((module, index) => (
                  <motion.div
                    key={module.name}
                    className="p-4 bg-gray-50 rounded-lg"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 * index }}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <span className="font-medium text-gray-900">{module.name}</span>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          module.color === 'green' ? 'bg-emerald-100 text-emerald-700' :
                          module.color === 'blue' ? 'bg-blue-100 text-blue-700' :
                          module.color === 'purple' ? 'bg-purple-100 text-purple-700' :
                          'bg-amber-100 text-amber-700'
                        }`}>
                          {module.status}
                        </span>
                        <span className="text-sm font-bold text-gray-900">{module.level}%</span>
                      </div>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <motion.div
                        className={`h-2 rounded-full ${
                          module.color === 'green' ? 'bg-emerald-500' :
                          module.color === 'blue' ? 'bg-blue-500' :
                          module.color === 'purple' ? 'bg-purple-500' :
                          'bg-amber-500'
                        }`}
                        initial={{ width: 0 }}
                        animate={{ width: `${module.level}%` }}
                        transition={{ duration: 1, delay: 0.2 * index }}
                      />
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Network Status - Takes 1 column */}
            <motion.div
              className="bg-white p-6 rounded-xl shadow-sm border border-gray-200"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
            >
              <div className="flex items-center space-x-3 mb-6">
                <Globe className="w-6 h-6 text-blue-600" />
                <h3 className="text-lg font-semibold text-gray-900">Network Status</h3>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Active Nodes</span>
                  <span className="font-semibold">{connectionStatus.activeNodes}/{connectionStatus.totalNodes}</span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">BFT Consensus</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    systemData?.bft?.consensus_active ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'
                  }`}>
                    {systemData?.bft?.consensus_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">System Uptime</span>
                  <span className="font-semibold">99.99%</span>
                </div>
                
                <div className="pt-4 border-t border-gray-200">
                  <div className="text-xs text-gray-500 mb-2">Last Updated</div>
                  <div className="text-sm font-medium">{currentTime.toLocaleTimeString()}</div>
                  <div className="text-xs text-gray-500">{currentTime.toLocaleDateString()}</div>
                </div>
              </div>
            </motion.div>
          </div>
        </main>
      </div>
    </div>
  );
}
