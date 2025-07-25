'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Shield, 
  Lock, 
  CheckCircle, 
  AlertTriangle,
  Download,
  RefreshCw,
  Link,
  Database,
  Hash
} from 'lucide-react';
import { ImmutableAuditTrail } from '../../lib/audit/immutableAuditTrail';

export default function AuditTrailVisualization() {
  const [auditTrail] = useState(() => ImmutableAuditTrail.getInstance());
  const [chainStats, setChainStats] = useState<any>(null);
  const [integrity, setIntegrity] = useState<any>(null);
  const [latestBlocks, setLatestBlocks] = useState<any[]>([]);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    loadAuditData();
    
    // Add some demo audit events
    generateDemoEvents();
    
    const interval = setInterval(loadAuditData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadAuditData = () => {
    setChainStats(auditTrail.getChainStats());
    setLatestBlocks(auditTrail.getLatestBlocks(5));
  };

  const generateDemoEvents = () => {
    // Add demo audit events to populate the blockchain
    const demoEvents = [
      { action: 'create', resourceType: 'file', userId: 'john.doe', resourceId: 'file_123' },
      { action: 'read', resourceType: 'file', userId: 'jane.smith', resourceId: 'file_123' },
      { action: 'update', resourceType: 'file', userId: 'john.doe', resourceId: 'file_123' },
      { action: 'share', resourceType: 'file', userId: 'john.doe', resourceId: 'file_123' },
      { action: 'delete', resourceType: 'file', userId: 'admin', resourceId: 'file_456' },
      { action: 'create', resourceType: 'user', userId: 'admin', resourceId: 'user_789' },
      { action: 'read', resourceType: 'folder', userId: 'jane.smith', resourceId: 'folder_001' },
      { action: 'update', resourceType: 'permission', userId: 'admin', resourceId: 'perm_002' },
      { action: 'create', resourceType: 'file', userId: 'bob.wilson', resourceId: 'file_333' },
      { action: 'download', resourceType: 'file', userId: 'alice.brown', resourceId: 'file_444' },
      { action: 'share', resourceType: 'folder', userId: 'charlie.davis', resourceId: 'folder_555' },
    ];

    demoEvents.forEach((event, index) => {
      setTimeout(() => {
        auditTrail.addAuditEvent({
          id: '',
          timestamp: new Date(),
          userId: event.userId,
          action: event.action as any,
          resourceId: event.resourceId,
          resourceType: event.resourceType as any,
          metadata: { demo: true, sequence: index },
          complianceFlags: [],
          ipAddress: `192.168.1.${100 + index}`,
          userAgent: 'DataVault-Demo'
        });
      }, index * 500);
    });
  };

  const verifyIntegrity = async () => {
    setIsVerifying(true);
    
    // Simulate verification process
    setTimeout(() => {
      setIntegrity(auditTrail.verifyChainIntegrity());
      setIsVerifying(false);
    }, 2000);
  };

  const exportAuditTrail = () => {
    const exportData = auditTrail.exportAuditTrail('json');
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-trail-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatHash = (hash: string) => {
    return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`;
  };

  const formatDate = (date: Date) => {
    return new Date(date).toLocaleString();
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Immutable Audit Trail</h2>
          <p className="text-gray-600">Blockchain-inspired tamper-proof audit logging</p>
        </div>
        <div className="flex space-x-3">
          <motion.button
            onClick={verifyIntegrity}
            disabled={isVerifying}
            className="apple-button-secondary"
            whileHover={{ scale: 1.02 }}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isVerifying ? 'animate-spin' : ''}`} />
            Verify Integrity
          </motion.button>
          <motion.button
            onClick={exportAuditTrail}
            className="apple-button"
            whileHover={{ scale: 1.02 }}
          >
            <Download className="w-4 h-4 mr-2" />
            Export Trail
          </motion.button>
        </div>
      </div>

      {/* Chain Statistics */}
      {chainStats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Database className="w-6 h-6 text-blue-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{chainStats.totalBlocks}</div>
            <div className="text-sm text-gray-600">Total Blocks</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Shield className="w-6 h-6 text-green-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{chainStats.totalEvents}</div>
            <div className="text-sm text-gray-600">Audit Events</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Hash className="w-6 h-6 text-purple-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{chainStats.difficulty}</div>
            <div className="text-sm text-gray-600">PoW Difficulty</div>
          </motion.div>

          <motion.div 
            className="apple-card p-6 text-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Lock className="w-6 h-6 text-orange-600" />
            </div>
            <div className="text-2xl font-bold text-gray-900 mb-1">{chainStats.pendingEvents}</div>
            <div className="text-sm text-gray-600">Pending Events</div>
          </motion.div>
        </div>
      )}

      {/* Integrity Status */}
      {integrity && (
        <motion.div
          className={`apple-card p-6 ${
            integrity.isValid 
              ? 'border-green-200 bg-green-50' 
              : 'border-red-200 bg-red-50'
          }`}
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {integrity.isValid ? (
                <CheckCircle className="w-8 h-8 text-green-600" />
              ) : (
                <AlertTriangle className="w-8 h-8 text-red-600" />
              )}
              <div>
                <h3 className={`text-lg font-semibold ${
                  integrity.isValid ? 'text-green-900' : 'text-red-900'
                }`}>
                  Chain Integrity: {integrity.isValid ? 'VERIFIED' : 'COMPROMISED'}
                </h3>
                <p className={`text-sm ${
                  integrity.isValid ? 'text-green-700' : 'text-red-700'
                }`}>
                  {integrity.isValid 
                    ? 'All blocks verified with cryptographic proof'
                    : `${integrity.errors.length} integrity violations detected`
                  }
                </p>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-2xl font-bold ${
                integrity.isValid ? 'text-green-600' : 'text-red-600'
              }`}>
                {integrity.blockCount}
              </div>
              <div className="text-sm text-gray-600">Blocks Verified</div>
            </div>
          </div>
          
          {!integrity.isValid && integrity.errors.length > 0 && (
            <div className="mt-4 p-4 bg-red-100 rounded-lg">
              <h4 className="font-semibold text-red-900 mb-2">Integrity Violations:</h4>
              <ul className="text-sm text-red-800 space-y-1">
                {integrity.errors.map((error: string, index: number) => (
                  <li key={index}>• {error}</li>
                ))}
              </ul>
            </div>
          )}
        </motion.div>
      )}

      {/* Blockchain Visualization */}
      <div className="apple-card overflow-hidden">
        <div className="p-6 border-b border-gray-200">
          <h3 className="text-lg font-semibold">Blockchain Structure</h3>
          <p className="text-gray-600 text-sm">Latest blocks in the immutable audit chain</p>
        </div>
        
        <div className="p-6">
          <div className="flex space-x-4 overflow-x-auto pb-4">
            {latestBlocks.map((block, index) => (
              <motion.div
                key={block.id}
                className="flex-shrink-0 w-64 bg-gray-50 rounded-lg p-4 border-2 border-gray-200"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-gray-900">Block #{block.id.split('_')[1]}</h4>
                  <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                </div>
                
                <div className="space-y-2 text-sm">
                  <div>
                    <span className="text-gray-600">Hash:</span>
                    <div className="font-mono text-xs text-blue-600 break-all">
                      {formatHash(block.hash)}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-gray-600">Previous:</span>
                    <div className="font-mono text-xs text-purple-600 break-all">
                      {formatHash(block.previousHash)}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-gray-600">Events:</span>
                    <span className="font-semibold text-gray-900 ml-2">{block.events.length}</span>
                  </div>
                  
                  <div>
                    <span className="text-gray-600">Nonce:</span>
                    <span className="font-mono text-xs text-orange-600 ml-2">{block.nonce}</span>
                  </div>
                  
                  <div className="text-xs text-gray-500">
                    {formatDate(block.timestamp)}
                  </div>
                </div>
                
                {/* Chain Link */}
                {index < latestBlocks.length - 1 && (
                  <div className="absolute right-0 top-1/2 transform translate-x-2 -translate-y-1/2">
                    <Link className="w-6 h-6 text-gray-400" />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </div>

      {/* Compliance Benefits */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="apple-card p-6">
          <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
            <Shield className="w-6 h-6 text-blue-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Tamper-Proof</h3>
          <p className="text-gray-600 text-sm">
            Cryptographic hashing and proof-of-work ensure audit logs cannot be modified retroactively.
          </p>
        </div>

        <div className="apple-card p-6">
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-4">
            <CheckCircle className="w-6 h-6 text-green-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Regulatory Ready</h3>
          <p className="text-gray-600 text-sm">
            Meets GDPR Article 30, SOX Section 404, and HIPAA audit requirements with cryptographic proof.
          </p>
        </div>

        <div className="apple-card p-6">
          <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mb-4">
            <Database className="w-6 h-6 text-purple-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 mb-2">Enterprise Scale</h3>
          <p className="text-gray-600 text-sm">
            Handles millions of events with automatic block creation and integrity verification.
          </p>
        </div>
      </div>
    </div>
  );
}
