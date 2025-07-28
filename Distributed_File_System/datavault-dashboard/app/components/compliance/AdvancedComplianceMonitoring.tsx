'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  TrendingUp,
  TrendingDown,
  Bell,
  Eye,
  Calendar,
  Target,
  Activity,
  BarChart3,
  PieChart,
  AlertCircle,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { 
  ComplianceMonitoringService, 
  ComplianceRegulation, 
  ComplianceAlert, 
  ComplianceMetrics 
} from '../../lib/compliance/monitoring/complianceMonitoringService';

export default function AdvancedComplianceMonitoring() {
  const [monitoringService] = useState(() => ComplianceMonitoringService.getInstance());
  const [regulations, setRegulations] = useState<ComplianceRegulation[]>([]);
  const [alerts, setAlerts] = useState<ComplianceAlert[]>([]);
  const [metrics, setMetrics] = useState<ComplianceMetrics | null>(null);
  const [selectedRegulation, setSelectedRegulation] = useState<ComplianceRegulation | null>(null);
  const [upcomingDeadlines, setUpcomingDeadlines] = useState<any[]>([]);
  const [complianceByRegulation, setComplianceByRegulation] = useState<{ [key: string]: number }>({});

  useEffect(() => {
    const loadData = () => {
      setRegulations(monitoringService.getRegulations());
      setAlerts(monitoringService.getAlerts());
      setMetrics(monitoringService.getMetrics());
      setUpcomingDeadlines(monitoringService.getUpcomingDeadlines());
      setComplianceByRegulation(monitoringService.getComplianceByRegulation());
    };

    loadData();
    const interval = setInterval(loadData, 30000);

    return () => {
      clearInterval(interval);
      monitoringService.stopMonitoring();
    };
  }, [monitoringService]);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-100 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-100 border-blue-200';
      case 'info': return 'text-gray-600 bg-gray-100 border-gray-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return 'text-green-600 bg-green-100';
      case 'partial': return 'text-yellow-600 bg-yellow-100';
      case 'non-compliant': return 'text-red-600 bg-red-100';
      case 'not-applicable': return 'text-gray-600 bg-gray-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatDate = (date: Date) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const acknowledgeAlert = (alertId: string) => {
    monitoringService.acknowledgeAlert(alertId);
    setAlerts(monitoringService.getAlerts());
  };

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading Advanced Compliance Monitoring...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900">Advanced Compliance Monitoring</h2>
          <p className="text-gray-600 mt-1">Real-time regulatory compliance status across all jurisdictions</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-right">
            <div className="text-2xl font-bold text-green-600">{metrics.overallScore}%</div>
            <div className="text-sm text-gray-600">Overall Compliance</div>
          </div>
          <div className="w-16 h-16 relative">
            <svg className="w-16 h-16 transform -rotate-90" viewBox="0 0 36 36">
              <path
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="#e5e7eb"
                strokeWidth="2"
              />
              <path
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="#10b981"
                strokeWidth="2"
                strokeDasharray={`${metrics.overallScore}, 100`}
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <Shield className="w-6 h-6 text-green-600" />
            </div>
          </div>
        </div>
      </div>

      {/* Key Metrics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6">
        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle className="w-6 h-6 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{metrics.compliantRequirements}</div>
          <div className="text-sm text-gray-600">Compliant</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Clock className="w-6 h-6 text-yellow-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{metrics.partialRequirements}</div>
          <div className="text-sm text-gray-600">Partial Compliance</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="w-6 h-6 text-red-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{metrics.criticalViolations}</div>
          <div className="text-sm text-gray-600">Critical Violations</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Activity className="w-6 h-6 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{metrics.automationLevel}%</div>
          <div className="text-sm text-gray-600">Automated</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Calendar className="w-6 h-6 text-orange-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{metrics.upcomingDeadlines}</div>
          <div className="text-sm text-gray-600">Upcoming Deadlines</div>
        </motion.div>
      </div>

      {/* Critical Alerts Banner */}
      {alerts.filter(a => a.severity === 'critical' && !a.acknowledgedAt).length > 0 && (
        <motion.div
          className="apple-card border-l-4 border-red-500 bg-red-50 p-6"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <AlertCircle className="w-6 h-6 text-red-600 mr-3" />
              <div>
                <h3 className="text-lg font-semibold text-red-900">Critical Compliance Issues Detected</h3>
                <p className="text-red-700">
                  {alerts.filter(a => a.severity === 'critical' && !a.acknowledgedAt).length} critical compliance violations require immediate attention
                </p>
              </div>
            </div>
            <motion.button
              className="apple-button bg-red-600 hover:bg-red-700"
              whileHover={{ scale: 1.02 }}
            >
              Review Now
            </motion.button>
          </div>
        </motion.div>
      )}

      {/* Compliance by Regulation */}
      <div className="apple-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold">Compliance Status by Regulation</h3>
          <div className="flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-gray-600" />
            <span className="text-sm text-gray-600">Last updated: {formatDate(new Date())}</span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {regulations.map((regulation, index) => (
            <motion.div
              key={regulation.id}
              className="p-6 border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              onClick={() => setSelectedRegulation(regulation)}
            >
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h4 className="font-semibold text-gray-900">{regulation.name}</h4>
                  <p className="text-xs text-gray-500">{regulation.jurisdiction.join(', ')}</p>
                </div>
                <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                  regulation.criticality === 'critical' 
                    ? 'bg-red-100 text-red-700'
                    : regulation.criticality === 'high'
                    ? 'bg-orange-100 text-orange-700'
                    : 'bg-gray-100 text-gray-700'
                }`}>
                  {regulation.criticality}
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-600">Compliance Score</span>
                  <span className="text-sm font-semibold">{complianceByRegulation[regulation.id]}%</span>
                </div>
                <div className="apple-progress">
                  <motion.div
                    className="apple-progress-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${complianceByRegulation[regulation.id]}%` }}
                    transition={{ duration: 1, delay: index * 0.1 }}
                    style={{ 
                      backgroundColor: complianceByRegulation[regulation.id] >= 95 ? '#10b981' : 
                                     complianceByRegulation[regulation.id] >= 80 ? '#f59e0b' : '#ef4444'
                    }}
                  />
                </div>
              </div>
              
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-600">
                  {regulation.requirements.filter(r => r.status === 'compliant').length}/{regulation.requirements.length} compliant
                </span>
                <ChevronRight className="w-4 h-4 text-gray-400" />
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="apple-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold">Recent Compliance Alerts</h3>
          <div className="flex items-center space-x-2">
            <Bell className="w-5 h-5 text-gray-600" />
            <span className="text-sm text-gray-600">
              {alerts.filter(a => !a.acknowledgedAt).length} unacknowledged
            </span>
          </div>
        </div>
        
        <div className="space-y-4">
          {alerts.slice(0, 5).map((alert, index) => (
            <motion.div
              key={alert.id}
              className={`p-4 border rounded-lg ${getSeverityColor(alert.severity)}`}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-2 mb-2">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                      {alert.severity.toUpperCase()}
                    </span>
                    <span className="text-sm text-gray-600">{alert.regulation}</span>
                    <span className="text-xs text-gray-500">•</span>
                    <span className="text-xs text-gray-500">{formatDate(alert.createdAt)}</span>
                  </div>
                  <h4 className="font-medium text-gray-900 mb-1">{alert.title}</h4>
                  <p className="text-sm text-gray-700 mb-2">{alert.description}</p>
                  <p className="text-xs text-gray-600 mb-2">
                    <strong>Impact:</strong> {alert.impact}
                  </p>
                  <p className="text-xs text-gray-600">
                    <strong>Recommended Action:</strong> {alert.recommendedAction}
                  </p>
                </div>
                <div className="flex space-x-2 ml-4">
                  {!alert.acknowledgedAt && (
                    <motion.button
                      onClick={() => acknowledgeAlert(alert.id)}
                      className="apple-button-secondary text-xs"
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                    >
                      Acknowledge
                    </motion.button>
                  )}
                  <motion.button
                    className="apple-button text-xs"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Eye className="w-3 h-3 mr-1" />
                    View
                  </motion.button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Upcoming Deadlines */}
      <div className="apple-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold">Upcoming Compliance Deadlines</h3>
          <Calendar className="w-5 h-5 text-gray-600" />
        </div>
        
        <div className="space-y-3">
          {upcomingDeadlines.slice(0, 8).map((deadline, index) => (
            <motion.div
              key={`${deadline.regulation}-${deadline.requirement}-${deadline.type}`}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <div className="flex items-center space-x-3">
                <div className={`px-2 py-1 rounded text-xs font-medium ${
                  deadline.priority === 'critical' 
                    ? 'bg-red-100 text-red-700'
                    : deadline.priority === 'high'
                    ? 'bg-orange-100 text-orange-700'
                    : 'bg-yellow-100 text-yellow-700'
                }`}>
                  {deadline.priority}
                </div>
                <div>
                  <div className="font-medium text-gray-900">{deadline.regulation}</div>
                  <div className="text-sm text-gray-600">{deadline.requirement}</div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-sm font-medium text-gray-900">
                  {formatDate(deadline.dueDate)}
                </div>
                <div className="text-xs text-gray-500 capitalize">
                  {deadline.type.replace('-', ' ')}
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* Compliance Trends */}
      <div className="apple-card p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold">Compliance Trends (30 Days)</h3>
          <TrendingUp className="w-5 h-5 text-green-600" />
        </div>
        
        <div className="h-64 flex items-center justify-center bg-gray-50 rounded-lg">
          <div className="text-center">
            <BarChart3 className="w-12 h-12 text-gray-400 mx-auto mb-2" />
            <p className="text-gray-600">Compliance trend visualization</p>
            <p className="text-sm text-gray-500">Interactive charts showing compliance improvements over time</p>
          </div>
        </div>
      </div>

      {/* Selected Regulation Details Modal */}
      {selectedRegulation && (
        <motion.div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <motion.div
            className="apple-card max-w-4xl w-full max-h-[90vh] overflow-y-auto p-6"
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
          >
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-gray-900">{selectedRegulation.fullName}</h2>
                <p className="text-gray-600">{selectedRegulation.jurisdiction.join(', ')} • {selectedRegulation.category}</p>
              </div>
              <button
                onClick={() => setSelectedRegulation(null)}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h3 className="text-lg font-semibold mb-4">Requirements Status</h3>
                <div className="space-y-3">
                  {selectedRegulation.requirements.map((req) => (
                    <div key={req.id} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium text-gray-900">{req.title}</h4>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(req.status)}`}>
                          {req.status}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">{req.description}</p>
                      {req.article && (
                        <p className="text-xs text-gray-500 mb-2">{req.article}</p>
                      )}
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">Score: {req.score}%</span>
                        <span className="text-xs text-gray-500">
                          Next: {formatDate(req.nextAssessment)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-lg font-semibold mb-4">Regulation Details</h3>
                <div className="space-y-4">
                  <div className="p-4 bg-red-50 rounded-lg">
                    <h4 className="font-semibold text-red-900 mb-2">Penalties</h4>
                    <div className="space-y-1 text-sm text-red-800">
                      <div><strong>Financial:</strong> {selectedRegulation.penalties.financial}</div>
                      <div><strong>Operational:</strong> {selectedRegulation.penalties.operational}</div>
                      <div><strong>Reputational:</strong> {selectedRegulation.penalties.reputational}</div>
                    </div>
                  </div>
                  
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <h4 className="font-semibold text-blue-900 mb-2">Review Schedule</h4>
                    <div className="space-y-1 text-sm text-blue-800">
                      <div><strong>Last Updated:</strong> {formatDate(selectedRegulation.lastUpdated)}</div>
                      <div><strong>Next Review:</strong> {formatDate(selectedRegulation.nextReview)}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}
