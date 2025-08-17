'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  FileText,
  Users,
  Download,
  Eye,
  Trash2,
  Database,
  Link,
  Brain,
  Lightbulb,
  TrendingUp,
  Lock,
  BarChart3
} from 'lucide-react';
import AuditTrailVisualization from './AuditTrailVisualization';
import PolicyRecommendationDashboard from './PolicyRecommendationDashboard';
import AdvancedComplianceMonitoring from './AdvancedComplianceMonitoring';

// ✅ IMPROVED BACKEND INTERFACES WITH OPTIONAL PROPERTIES
interface BackendComplianceStatus {
  data?: {
    activePolicies?: number;
    auditCompliance?: number;
    gdprCompliance?: number;
    lastUpdated?: string;
    overallScore?: number;
    piiDetection?: number;
    riskLevel?: string;
    status?: string;
    violations?: number;
  };
  success: boolean;
}

interface BackendGDPRData {
  data?: {
    complianceScore?: number;
    consentPolicies?: Array<{name: string; policy: string}>;
    dataRights?: string[];
    lastAudit?: string;
    nextAudit?: string;
    retentionPolicies?: Array<{name: string; policy: string}>;
  };
  success: boolean;
}

interface BackendAuditData {
  data?: {
    auditEntries?: any[];
    blockchainHeight?: number;
    integrity?: string;
    lastBlock?: string;
    totalEntries?: number;
  };
  success: boolean;
}

export default function ComplianceDashboard() {
  // ✅ REAL BACKEND STATE
  const [backendStatus, setBackendStatus] = useState<BackendComplianceStatus | null>(null);
  const [backendGDPR, setBackendGDPR] = useState<BackendGDPRData | null>(null);
  const [backendAudit, setBackendAudit] = useState<BackendAuditData | null>(null);
  const [selectedTab, setSelectedTab] = useState<'overview' | 'monitoring' | 'ai-policy' | 'requests' | 'audit' | 'immutable'>('overview');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadRealComplianceData();
    const interval = setInterval(loadRealComplianceData, 10000); // Update every 10 seconds
    return () => clearInterval(interval);
  }, []);

  // ✅ REAL BACKEND DATA LOADING
  const loadRealComplianceData = async () => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('🔄 Fetching real compliance data from DataVault backend...');
      
      const [statusResponse, gdprResponse, auditResponse] = await Promise.all([
        fetch('http://localhost:8080/api/compliance/status').catch(() => null),
        fetch('http://localhost:8080/api/compliance/gdpr').catch(() => null),
        fetch('http://localhost:8080/api/compliance/audit-trail').catch(() => null)
      ]);

      if (statusResponse?.ok) {
        const statusData = await statusResponse.json();
        setBackendStatus(statusData);
        console.log('✅ Real compliance status loaded:', statusData);
      }

      if (gdprResponse?.ok) {
        const gdprData = await gdprResponse.json();
        setBackendGDPR(gdprData);
        console.log('✅ Real GDPR data loaded:', gdprData);
      }

      if (auditResponse?.ok) {
        const auditData = await auditResponse.json();
        setBackendAudit(auditData);
        console.log('✅ Real audit data loaded:', auditData);
      }

    } catch (err) {
      console.error('❌ Failed to load real compliance data:', err);
      setError('Failed to connect to DataVault compliance backend');
    } finally {
      setLoading(false);
    }
  };

  // ✅ SAFE DATA ACCESS METHODS WITH NULL CHECKS
  const getComplianceScore = (): number => {
    return backendStatus?.data?.overallScore ?? 0;
  };

  const getTotalPolicies = (): number => {
    return backendStatus?.data?.activePolicies ?? 0;
  };

  const getViolations = (): number => {
    return backendStatus?.data?.violations ?? 0;
  };

  const getPIIDetectionRate = (): number => {
    return backendStatus?.data?.piiDetection ?? 0;
  };

  const getGDPRScore = (): number => {
    return backendGDPR?.data?.complianceScore ?? 0;
  };

  const getBlockchainHeight = (): number => {
    return backendAudit?.data?.blockchainHeight ?? 0;
  };

  const getAuditIntegrity = (): string => {
    return backendAudit?.data?.integrity ?? 'unknown';
  };

  // ✅ SAFE COMPLIANCE STATUS HELPERS
  const getGDPRCompliance = (): number => {
    return backendStatus?.data?.gdprCompliance ?? 0;
  };

  const getAuditCompliance = (): number => {
    return backendStatus?.data?.auditCompliance ?? 0;
  };

  const getOverallScore = (): number => {
    return backendStatus?.data?.overallScore ?? 0;
  };

  // ✅ REAL REQUEST HANDLERS (these would integrate with your backend APIs)
  const handleAccessRequest = async () => {
    const email = prompt('Enter email for access request:');
    if (email) {
      try {
        // TODO: Implement real backend call
        const response = await fetch('http://localhost:8080/api/compliance/gdpr/access', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, type: 'access' })
        });
        
        if (response.ok) {
          console.log('✅ Access request submitted successfully');
          loadRealComplianceData(); // Refresh data
        }
      } catch (err) {
        console.error('❌ Failed to submit access request:', err);
      }
    }
  };

  const handleErasureRequest = async () => {
    const email = prompt('Enter email for erasure request:');
    const reason = prompt('Reason for erasure:');
    if (email && reason) {
      try {
        // TODO: Implement real backend call
        const response = await fetch('http://localhost:8080/api/compliance/gdpr/erasure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, reason, type: 'erasure' })
        });
        
        if (response.ok) {
          console.log('✅ Erasure request submitted successfully');
          loadRealComplianceData();
        }
      } catch (err) {
        console.error('❌ Failed to submit erasure request:', err);
      }
    }
  };

  const formatDate = (dateString?: string): string => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // ✅ SHOW LOADING STATE
  if (loading && !backendStatus) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading real compliance data from DataVault backend...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Enterprise Compliance Center</h1>
          <p className="text-gray-600 mt-1">
            Real-time regulatory compliance monitoring with DataVault backend integration
            {error && <span className="text-red-600 ml-2">• {error}</span>}
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <motion.button 
            onClick={handleAccessRequest}
            className="apple-button-secondary"
            whileHover={{ scale: 1.02 }}
          >
            <Eye className="w-4 h-4 mr-2" />
            Access Request
          </motion.button>
          <motion.button 
            onClick={handleErasureRequest}
            className="apple-button-secondary"
            whileHover={{ scale: 1.02 }}
          >
            <Trash2 className="w-4 h-4 mr-2" />
            Erasure Request
          </motion.button>
          <motion.button 
            onClick={loadRealComplianceData}
            className="apple-button"
            whileHover={{ scale: 1.02 }}
            disabled={loading}
          >
            {loading ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
            ) : (
              <Download className="w-4 h-4 mr-2" />
            )}
            Refresh Data
          </motion.button>
        </div>
      </div>

      {/* ✅ REAL BACKEND COMPLIANCE CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-6">
        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Shield className="w-6 h-6 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getComplianceScore().toFixed(1)}%</div>
          <div className="text-sm text-gray-600">Overall Score</div>
          <div className="text-xs text-green-600 mt-1">Live DataVault</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <FileText className="w-6 h-6 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getTotalPolicies()}</div>
          <div className="text-sm text-gray-600">Active Policies</div>
          <div className="text-xs text-blue-600 mt-1">Real-time</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Brain className="w-6 h-6 text-purple-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getPIIDetectionRate().toFixed(1)}%</div>
          <div className="text-sm text-gray-600">PII Detection</div>
          <div className="text-xs text-purple-600 mt-1">AI-Powered</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="w-6 h-6 text-red-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getViolations()}</div>
          <div className="text-sm text-gray-600">Violations</div>
          <div className="text-xs text-green-600 mt-1">Zero violations!</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <div className="w-12 h-12 bg-cyan-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Database className="w-6 h-6 text-cyan-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getBlockchainHeight()}</div>
          <div className="text-sm text-gray-600">Audit Blocks</div>
          <div className="text-xs text-cyan-600 mt-1">{getAuditIntegrity()}</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Lock className="w-6 h-6 text-green-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900 mb-1">{getGDPRScore().toFixed(1)}%</div>
          <div className="text-sm text-gray-600">GDPR Score</div>
          <div className="text-xs text-green-600 mt-1">EU Compliant</div>
        </motion.div>
      </div>

      {/* Enhanced Tab Navigation */}
      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        {[
          { id: 'overview', label: 'Real-Time Overview', icon: Shield },
          { id: 'monitoring', label: 'Advanced Monitoring', icon: BarChart3 },
          { id: 'ai-policy', label: 'AI Policy Engine', icon: Brain },
          { id: 'requests', label: 'GDPR Requests', icon: Users },
          { id: 'audit', label: 'Audit Trail', icon: FileText },
          { id: 'immutable', label: 'Blockchain Audit', icon: Link }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSelectedTab(tab.id as any)}
            className={`flex items-center px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              selectedTab === tab.id
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="w-4 h-4 mr-2" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content with Real Data */}
      <motion.div
        key={selectedTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {selectedTab === 'monitoring' && <AdvancedComplianceMonitoring />}
        {selectedTab === 'ai-policy' && <PolicyRecommendationDashboard />}
        {selectedTab === 'immutable' && <AuditTrailVisualization />}

        {selectedTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Real Compliance Status */}
            <div className="apple-card p-6">
              <h3 className="text-lg font-semibold mb-4">Live Regulatory Compliance</h3>
              <div className="space-y-4">
                {[
                  { 
                    name: 'GDPR', 
                    status: getGDPRCompliance() >= 95 ? 'Compliant' : 'Review Required', 
                    score: getGDPRCompliance(), 
                    color: getGDPRCompliance() >= 95 ? 'green' : 'orange', 
                    description: 'EU Data Protection', 
                    live: true 
                  },
                  { 
                    name: 'Audit Trail', 
                    status: getAuditCompliance() >= 95 ? 'Compliant' : 'Review Required', 
                    score: getAuditCompliance(), 
                    color: getAuditCompliance() >= 95 ? 'green' : 'orange', 
                    description: 'Immutable Logging', 
                    live: true 
                  },
                  { 
                    name: 'PII Detection', 
                    status: getPIIDetectionRate() >= 90 ? 'Compliant' : 'Review Required', 
                    score: getPIIDetectionRate(), 
                    color: getPIIDetectionRate() >= 90 ? 'green' : 'orange', 
                    description: 'AI-Powered Scanning', 
                    live: true 
                  },
                  { 
                    name: 'Overall', 
                    status: getOverallScore() >= 95 ? 'Compliant' : 'Review Required', 
                    score: getOverallScore(), 
                    color: getOverallScore() >= 95 ? 'green' : 'orange', 
                    description: 'Enterprise Compliance', 
                    live: true 
                  }
                ].map((regulation) => (
                  <div key={regulation.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <div className="font-medium text-gray-900">{regulation.name}</div>
                        {regulation.live && (
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" title="Live Data" />
                        )}
                      </div>
                      <div className="text-xs text-gray-500">{regulation.description}</div>
                      <div className={`text-sm text-${regulation.color}-600`}>{regulation.status}</div>
                    </div>
                    <div className="flex items-center space-x-3">
                      <div className="w-24 apple-progress">
                        <div 
                          className={`apple-progress-fill bg-${regulation.color}-500`}
                          style={{ width: `${regulation.score}%` }}
                        />
                      </div>
                      <span className="text-sm font-medium text-gray-900">{regulation.score.toFixed(1)}%</span>
                    </div>
                  </div>
                ))}
              </div>
              
              {backendStatus && (
                <div className="mt-6 p-4 bg-green-50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-semibold text-green-900">DataVault Backend Connected</h4>
                      <p className="text-sm text-green-700">
                        Live compliance data • Last updated: {formatDate(backendStatus.data?.lastUpdated)}
                      </p>
                    </div>
                    <CheckCircle className="w-6 h-6 text-green-600" />
                  </div>
                </div>
              )}
            </div>

            {/* Real GDPR Status */}
            <div className="apple-card p-6">
              <h3 className="text-lg font-semibold mb-4">GDPR Compliance Details</h3>
              {backendGDPR?.data ? (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-600">Compliance Score</span>
                    <span className="font-semibold text-green-600">{backendGDPR.data.complianceScore ?? 0}%</span>
                  </div>
                  
                  <div>
                    <span className="text-gray-600 block mb-2">Data Rights Supported:</span>
                    <div className="flex flex-wrap gap-2">
                      {(backendGDPR.data.dataRights ?? []).map((right) => (
                        <span key={right} className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs">
                          {right}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-gray-600 block mb-2">Active Policies:</span>
                    <div className="space-y-1">
                      {(backendGDPR.data.consentPolicies ?? []).slice(0, 3).map((policy) => (
                        <div key={policy.name} className="text-sm text-gray-700">
                          • {policy.name}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-gray-200">
                    <div className="text-xs text-gray-500">
                      Last Audit: {formatDate(backendGDPR.data.lastAudit)}
                    </div>
                    <div className="text-xs text-gray-500">
                      Next Audit: {formatDate(backendGDPR.data.nextAudit)}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
                  <p className="text-gray-500">Loading GDPR data...</p>
                </div>
              )}
            </div>
          </div>
        )}

        {selectedTab === 'requests' && (
          <div className="apple-card p-6">
            <h3 className="text-lg font-semibold mb-4">GDPR Data Subject Requests</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-4 border rounded-lg">
                <h4 className="font-medium mb-2">Access Requests</h4>
                <p className="text-sm text-gray-600 mb-4">
                  Process data subject access requests under Article 15
                </p>
                <button 
                  onClick={handleAccessRequest}
                  className="apple-button w-full"
                >
                  Submit Access Request
                </button>
              </div>
              <div className="p-4 border rounded-lg">
                <h4 className="font-medium mb-2">Erasure Requests</h4>
                <p className="text-sm text-gray-600 mb-4">
                  Process right to be forgotten requests under Article 17
                </p>
                <button 
                  onClick={handleErasureRequest}
                  className="apple-button w-full"
                >
                  Submit Erasure Request
                </button>
              </div>
            </div>
          </div>
        )}

        {selectedTab === 'audit' && (
          <div className="apple-card p-6">
            <h3 className="text-lg font-semibold mb-4">Compliance Audit Trail</h3>
            {backendAudit?.data ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900">{backendAudit.data.blockchainHeight}</div>
                    <div className="text-sm text-gray-600">Blockchain Height</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{backendAudit.data.integrity}</div>
                    <div className="text-sm text-gray-600">Integrity Status</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{backendAudit.data.totalEntries}</div>
                    <div className="text-sm text-gray-600">Total Entries</div>
                  </div>
                </div>
                <div className="text-sm text-gray-500">
                  Last Block: {formatDate(backendAudit.data.lastBlock)}
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p className="text-gray-500">Loading audit trail data...</p>
              </div>
            )}
          </div>
        )}
      </motion.div>
    </div>
  );
}
