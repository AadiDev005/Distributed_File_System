'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';
import { 
  FileCheck, 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  Download,
  Eye,
  Filter,
  Search,
  Shield,
  Globe,
  Users,
  Database
} from 'lucide-react';

const complianceStandards = [
  {
    name: 'GDPR',
    description: 'General Data Protection Regulation',
    status: 'Compliant',
    score: 100,
    lastAudit: '15/01/2025',
    nextAudit: '15/04/2025',
    color: 'text-green-600',
    bgColor: 'bg-green-100'
  },
  {
    name: 'HIPAA',
    description: 'Health Insurance Portability and Accountability Act',
    status: 'Compliant',
    score: 98,
    lastAudit: '10/01/2025',
    nextAudit: '10/04/2025',
    color: 'text-green-600',
    bgColor: 'bg-green-100'
  },
  {
    name: 'SOX',
    description: 'Sarbanes-Oxley Act',
    status: 'Compliant',
    score: 99,
    lastAudit: '12/01/2025',
    nextAudit: '12/04/2025',
    color: 'text-green-600',
    bgColor: 'bg-green-100'
  },
  {
    name: 'PCI-DSS',
    description: 'Payment Card Industry Data Security Standard',
    status: 'Review Required',
    score: 87,
    lastAudit: '08/01/2025',
    nextAudit: '08/02/2025',
    color: 'text-orange-600',
    bgColor: 'bg-orange-100'
  }
];

const recentReports = [
  {
    title: 'GDPR Compliance Report Q1 2025',
    type: 'GDPR',
    date: '15/01/2025',
    status: 'Complete',
    size: '2.4 MB'
  },
  {
    title: 'HIPAA Security Assessment',
    type: 'HIPAA',
    date: '10/01/2025',
    status: 'Complete',
    size: '1.8 MB'
  },
  {
    title: 'SOX Financial Controls Audit',
    type: 'SOX',
    date: '12/01/2025',
    status: 'Complete',
    size: '3.2 MB'
  },
  {
    title: 'PCI-DSS Quarterly Scan',
    type: 'PCI-DSS',
    date: '08/01/2025',
    status: 'Action Required',
    size: '1.5 MB'
  }
];

const complianceMetrics = [
  {
    title: 'Overall Compliance Score',
    value: '96%',
    icon: FileCheck,
    color: 'text-green-600'
  },
  {
    title: 'Active Regulations',
    value: '12',
    icon: Shield,
    color: 'text-blue-600'
  },
  {
    title: 'Automated Checks',
    value: '847',
    icon: CheckCircle,
    color: 'text-purple-600'
  },
  {
    title: 'Risk Level',
    value: 'Low',
    icon: AlertTriangle,
    color: 'text-green-600'
  }
];

export default function CompliancePage() {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredReports = recentReports.filter(report =>
    report.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    report.type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        {/* Header */}
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="apple-headline mb-4">Compliance Dashboard</h1>
          <p className="apple-subheadline">
            Automated compliance monitoring and reporting for enterprise standards
          </p>
        </motion.div>

        {/* Compliance Metrics */}
        <div className="apple-grid mb-12">
          {complianceMetrics.map((metric, index) => (
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

        {/* Compliance Standards */}
        <motion.div
          className="apple-card p-8 mb-12"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <div className="flex items-center justify-between mb-8">
            <div>
              <h2 className="text-2xl font-semibold mb-2">Compliance Standards</h2>
              <p className="text-gray-600">Current status of regulatory compliance</p>
            </div>
            <button className="apple-button">
              <Download className="w-4 h-4 mr-2" />
              Export Report
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {complianceStandards.map((standard, index) => (
              <motion.div
                key={standard.name}
                className="p-6 bg-gray-50 rounded-2xl apple-hover"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center">
                    <div className={`w-4 h-4 rounded-full ${standard.bgColor} mr-3`}>
                      <div className={`w-full h-full rounded-full ${standard.status === 'Compliant' ? 'bg-green-500' : 'bg-orange-500'}`} />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900">{standard.name}</h3>
                      <p className="text-sm text-gray-600">{standard.description}</p>
                    </div>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-xs font-medium ${standard.bgColor} ${standard.color}`}>
                    {standard.status}
                  </div>
                </div>
                
                <div className="mb-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-gray-600">Compliance Score</span>
                    <span className="text-sm font-semibold text-gray-900">{standard.score}%</span>
                  </div>
                  <div className="apple-progress">
                    <motion.div
                      className="apple-progress-fill"
                      initial={{ width: 0 }}
                      animate={{ width: `${standard.score}%` }}
                      transition={{ duration: 1, delay: 0.2 * index }}
                      style={{ 
                        backgroundColor: standard.score >= 95 ? '#30D158' : 
                                       standard.score >= 85 ? '#FF9F0A' : '#FF3B30'
                      }}
                    />
                  </div>
                </div>
                
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Last Audit: {standard.lastAudit}</span>
                  <span>Next: {standard.nextAudit}</span>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Recent Reports */}
        <motion.div
          className="apple-card overflow-hidden"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
        >
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold">Compliance Reports</h2>
                <p className="text-gray-600">Recent audits and assessments</p>
              </div>
              <div className="flex items-center space-x-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="apple-input pl-10 w-64"
                    placeholder="Search reports..."
                  />
                </div>
                <button className="apple-button-secondary">
                  <Filter className="w-4 h-4 mr-2" />
                  Filter
                </button>
              </div>
            </div>
          </div>
          
          <div className="divide-y divide-gray-100">
            {filteredReports.map((report, index) => (
              <motion.div
                key={report.title}
                className="p-6 hover:bg-gray-50 transition-colors"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                      <FileCheck className="w-5 h-5 text-blue-600" />
                    </div>
                    
                    <div>
                      <h3 className="font-medium text-gray-900">{report.title}</h3>
                      <div className="flex items-center space-x-4 text-sm text-gray-500 mt-1">
                        <span>{report.type}</span>
                        <span>•</span>
                        <span>{report.date}</span>
                        <span>•</span>
                        <span>{report.size}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className={`px-3 py-1 rounded-full text-xs font-medium ${
                      report.status === 'Complete' 
                        ? 'bg-green-100 text-green-700' 
                        : 'bg-orange-100 text-orange-700'
                    }`}>
                      {report.status}
                    </div>

                    <div className="flex items-center space-x-2">
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <Eye className="w-4 h-4" />
                      </motion.button>
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <Download className="w-4 h-4" />
                      </motion.button>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Compliance Summary */}
        <motion.div
          className="apple-card p-6 mt-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9 }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <div className="flex items-center">
                <CheckCircle className="w-5 h-5 text-green-500 mr-2" />
                <span className="font-medium text-gray-900">96% Overall Compliance</span>
              </div>
              <div className="flex items-center">
                <Globe className="w-5 h-5 text-blue-600 mr-2" />
                <span className="text-gray-600">12 Active Regulations</span>
              </div>
              <div className="flex items-center">
                <Database className="w-5 h-5 text-purple-600 mr-2" />
                <span className="text-gray-600">847 Automated Checks</span>
              </div>
            </div>
            <div className="text-sm text-gray-500">
              Next compliance review: 8 February 2025
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
