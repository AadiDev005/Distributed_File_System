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
import { GDPRComplianceService } from '../../lib/compliance/gdprService';
import { ImmutableAuditTrail } from '../../lib/audit/immutableAuditTrail';
import AuditTrailVisualization from './AuditTrailVisualization';
import PolicyRecommendationDashboard from './PolicyRecommendationDashboard';
import AdvancedComplianceMonitoring from './AdvancedComplianceMonitoring';

export default function ComplianceDashboard() {
  const [complianceStatus, setComplianceStatus] = useState<any>(null);
  const [dataSubjectRequests, setDataSubjectRequests] = useState<any[]>([]);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [selectedTab, setSelectedTab] = useState<'overview' | 'monitoring' | 'ai-policy' | 'requests' | 'audit' | 'immutable'>('overview');

  const gdprService = GDPRComplianceService.getInstance();
  const auditTrail = ImmutableAuditTrail.getInstance();

  useEffect(() => {
    loadComplianceData();
    const interval = setInterval(loadComplianceData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadComplianceData = () => {
    setComplianceStatus(gdprService.getComplianceStatus());
    setDataSubjectRequests(gdprService.getAllRequests());
    setAuditEvents(gdprService.getAuditLog().slice(0, 10));
  };

  const handleAccessRequest = async () => {
    const email = prompt('Enter email for access request:');
    if (email) {
      const request = await gdprService.processAccessRequest(email);
      auditTrail.addAuditEvent({
        id: '',
        timestamp: new Date(),
        userId: 'compliance-system',
        action: 'create',
        resourceId: request.id,
        resourceType: 'data-subject-request',
        metadata: { 
          requestType: 'access',
          subjectEmail: email,
          gdprArticle: 'Article 15',
          automatedProcessing: true
        },
        complianceFlags: ['gdpr-access-request', 'data-subject-rights'],
        ipAddress: '127.0.0.1',
        userAgent: 'DataVault-Compliance'
      });
      loadComplianceData();
    }
  };

  const handleErasureRequest = async () => {
    const email = prompt('Enter email for erasure request:');
    const reason = prompt('Reason for erasure:');
    if (email && reason) {
      const request = await gdprService.processErasureRequest(email, reason);
      auditTrail.addAuditEvent({
        id: '',
        timestamp: new Date(),
        userId: 'compliance-system',
        action: 'create',
        resourceId: request.id,
        resourceType: 'data-subject-request',
        metadata: { 
          requestType: 'erasure',
          subjectEmail: email,
          reason,
          gdprArticle: 'Article 17',
          riskLevel: 'high'
        },
        complianceFlags: ['gdpr-erasure-request', 'data-deletion', 'right-to-be-forgotten'],
        ipAddress: '127.0.0.1',
        userAgent: 'DataVault-Compliance'
      });
      loadComplianceData();
    }
  };

  const handlePortabilityRequest = async () => {
    const email = prompt('Enter email for data portability:');
    if (email) {
      const request = await gdprService.processPortabilityRequest(email, 'json');
      auditTrail.addAuditEvent({
        id: '',
        timestamp: new Date(),
        userId: 'compliance-system',
        action: 'create',
        resourceId: request.id,
        resourceType: 'data-subject-request',
        metadata: { 
          requestType: 'portability',
          subjectEmail: email,
          exportFormat: 'json',
          gdprArticle: 'Article 20'
        },
        complianceFlags: ['gdpr-portability-request', 'data-export'],
        ipAddress: '127.0.0.1',
        userAgent: 'DataVault-Compliance'
      });
      loadComplianceData();
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-600 bg-green-100';
      case 'processing': return 'text-blue-600 bg-blue-100';
      case 'pending': return 'text-orange-600 bg-orange-100';
      case 'rejected': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatDate = (date: Date) => {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Enterprise Compliance Center</h1>
          <p className="text-gray-600 mt-1">Advanced regulatory compliance monitoring with AI-powered automation</p>
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
            onClick={handlePortabilityRequest}
            className="apple-button"
            whileHover={{ scale: 1.02 }}
          >
            <Download className="w-4 h-4 mr-2" />
            Data Export
          </motion.button>
        </div>
      </div>

      {/* Enhanced Compliance Overview Cards */}
      {complianceStatus && (
        <div className="grid grid-cols-1 md:grid-cols-6 gap-6">
          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-6 h-6 text-green-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{complianceStatus.complianceScore}%</div>
            <div className="text-sm text-gray-600">Compliance Score</div>
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
            <div className="text-2xl font-bold text-gray-900 mb-1">{complianceStatus.totalRequests}</div>
            <div className="text-sm text-gray-600">Total Requests</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Clock className="w-6 h-6 text-orange-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{complianceStatus.processingTime}d</div>
            <div className="text-sm text-gray-600">Avg Response Time</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-6 h-6 text-purple-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{complianceStatus.pendingRequests}</div>
            <div className="text-sm text-gray-600">Pending Requests</div>
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
            <div className="text-2xl font-bold text-gray-900 mb-1">{auditTrail.getChainStats().totalBlocks}</div>
            <div className="text-sm text-gray-600">Audit Blocks</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
          >
            <div className="w-12 h-12 bg-pink-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Brain className="w-6 h-6 text-pink-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">12</div>
            <div className="text-sm text-gray-600">AI Recommendations</div>
          </motion.div>
        </div>
      )}

      {/* Enhanced Tab Navigation */}
      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        {[
          { id: 'overview', label: 'Overview', icon: Shield },
          { id: 'monitoring', label: 'Advanced Monitoring', icon: BarChart3 },
          { id: 'ai-policy', label: 'AI Policy Engine', icon: Brain },
          { id: 'requests', label: 'Data Subject Requests', icon: Users },
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

      {/* Tab Content */}
      <motion.div
        key={selectedTab}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {selectedTab === 'monitoring' && <AdvancedComplianceMonitoring />}
        {selectedTab === 'ai-policy' && <PolicyRecommendationDashboard />}
        {selectedTab === 'immutable' && <AuditTrailVisualization />}

        {selectedTab === 'requests' && (
          <div className="apple-card overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold">Data Subject Requests</h3>
              <p className="text-gray-600 text-sm">GDPR Article 15, 17, and 20 requests with immutable logging</p>
            </div>
            <div className="divide-y divide-gray-100">
              {dataSubjectRequests.map((request, index) => (
                <div key={request.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-3">
                        <h4 className="font-medium text-gray-900 capitalize">
                          {request.type} Request
                        </h4>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(request.status)}`}>
                          {request.status}
                        </span>
                        <div className="flex items-center text-green-600">
                          <Database className="w-3 h-3 mr-1" />
                          <span className="text-xs">Immutable</span>
                        </div>
                      </div>
                      <p className="text-sm text-gray-600 mt-1">
                        Subject: {request.subjectEmail} • {formatDate(request.requestDate)}
                      </p>
                      <p className="text-xs text-gray-500 mt-1">
                        {request.legalBasis}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-gray-900">{request.affectedFiles.length} files</p>
                      {request.completionDate && (
                        <p className="text-xs text-gray-500">
                          Completed: {formatDate(request.completionDate)}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {selectedTab === 'audit' && (
          <div className="apple-card overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold">Traditional Audit Trail</h3>
              <p className="text-gray-600 text-sm">Standard compliance audit log (also stored in immutable blockchain)</p>
            </div>
            <div className="divide-y divide-gray-100">
              {auditEvents.map((event, index) => (
                <div key={event.id} className="p-4 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-gray-900 capitalize">{event.action}</span>
                        <span className="text-gray-500">•</span>
                        <span className="text-gray-600">{event.resourceType}</span>
                        {event.complianceFlags.length > 0 && (
                          <div className="flex space-x-1">
                            {event.complianceFlags.map((flag: string) => (
                              <span key={flag} className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-xs">
                                {flag}
                              </span>
                            ))}
                          </div>
                        )}
                        <div className="flex items-center text-blue-600">
                          <Link className="w-3 h-3 mr-1" />
                          <span className="text-xs">Blockchain Verified</span>
                        </div>
                      </div>
                      <p className="text-xs text-gray-500 mt-1">
                        {formatDate(event.timestamp)} • User: {event.userId} • IP: {event.ipAddress}
                      </p>
                    </div>
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {selectedTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Enhanced Compliance Status */}
            <div className="apple-card p-6">
              <h3 className="text-lg font-semibold mb-4">Regulatory Compliance Status</h3>
              <div className="space-y-4">
                {[
                  { name: 'GDPR', status: 'Compliant', score: 98, color: 'green', description: 'EU Data Protection', aiOptimized: true },
                  { name: 'HIPAA', status: 'Compliant', score: 95, color: 'green', description: 'Healthcare Privacy', aiOptimized: true },
                  { name: 'SOX', status: 'Compliant', score: 99, color: 'green', description: 'Financial Reporting', aiOptimized: false },
                  { name: 'PCI-DSS', status: 'Review Required', score: 87, color: 'orange', description: 'Payment Security', aiOptimized: true }
                ].map((regulation) => (
                  <div key={regulation.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <div className="font-medium text-gray-900">{regulation.name}</div>
                        {regulation.aiOptimized && (
                          <Brain className="w-3 h-3 text-blue-600" title="AI-Optimized" />
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
                      <span className="text-sm font-medium text-gray-900">{regulation.score}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Advanced Monitoring Preview */}
            <div className="apple-card p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center">
                <BarChart3 className="w-5 h-5 text-blue-600 mr-2" />
                Advanced Monitoring
              </h3>
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <CheckCircle className="w-5 h-5 text-green-600 mt-1" />
                  <div>
                    <h4 className="font-medium text-gray-900">Real-Time Compliance Tracking</h4>
                    <p className="text-sm text-gray-600">Continuous monitoring of all regulatory requirements with automated alerts</p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <AlertTriangle className="w-5 h-5 text-orange-600 mt-1" />
                  <div>
                    <h4 className="font-medium text-gray-900">Risk Assessment</h4>
                    <p className="text-sm text-gray-600">Proactive identification of compliance risks before they become violations</p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <TrendingUp className="w-5 h-5 text-purple-600 mt-1" />
                  <div>
                    <h4 className="font-medium text-gray-900">Compliance Trends</h4>
                    <p className="text-sm text-gray-600">Historical analysis and predictive insights for compliance improvements</p>
                  </div>
                </div>
                
                <div className="flex items-start space-x-3">
                  <Clock className="w-5 h-5 text-cyan-600 mt-1" />
                  <div>
                    <h4 className="font-medium text-gray-900">Deadline Management</h4>
                    <p className="text-sm text-gray-600">Automated tracking of compliance deadlines and renewal schedules</p>
                  </div>
                </div>
              </div>
              
              <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-semibold text-blue-900">Advanced Monitoring Available</h4>
                    <p className="text-sm text-blue-700">Real-time regulatory compliance monitoring with predictive analytics</p>
                  </div>
                  <motion.button
                    onClick={() => setSelectedTab('monitoring')}
                    className="apple-button text-sm"
                    whileHover={{ scale: 1.02 }}
                  >
                    View Dashboard
                  </motion.button>
                </div>
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
}
