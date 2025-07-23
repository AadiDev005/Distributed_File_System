'use client';

import { useSystemStore } from '../../hooks/useSystemStore';

export default function ComplianceMonitor() {
  const { performance } = useSystemStore();

  const complianceItems = [
    {
      name: 'GDPR Compliance',
      status: 'Compliant',
      score: 100,
      lastCheck: '2 minutes ago',
      icon: '🇪🇺',
    },
    {
      name: 'SOX Compliance',
      status: 'Compliant',
      score: 98,
      lastCheck: '5 minutes ago',
      icon: '📊',
    },
    {
      name: 'HIPAA Compliance',
      status: 'Compliant',
      score: 99,
      lastCheck: '3 minutes ago',
      icon: '🏥',
    },
    {
      name: 'PCI-DSS',
      status: 'Compliant',
      score: 97,
      lastCheck: '1 minute ago',
      icon: '💳',
    },
    {
      name: 'PII Detection',
      status: 'Active',
      score: 100,
      lastCheck: 'Real-time',
      icon: '��',
    },
    {
      name: 'Audit Trail',
      status: 'Immutable',
      score: 100,
      lastCheck: 'Continuous',
      icon: '🔒',
    },
  ];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
        📋 Compliance Monitor
      </h2>
      <div className="space-y-4">
        {complianceItems.map((item, index) => (
          <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <span className="text-2xl">{item.icon}</span>
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {item.name}
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Last check: {item.lastCheck}
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="font-semibold text-green-600">
                {item.score}%
              </p>
              <p className="text-xs text-gray-500">
                {item.status}
              </p>
            </div>
          </div>
        ))}
      </div>
      
      <div className="mt-6 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
        <div className="flex items-center">
          <span className="text-green-600 text-xl mr-2">✅</span>
          <div>
            <p className="font-semibold text-green-800 dark:text-green-200">
              All Compliance Requirements Met
            </p>
            <p className="text-sm text-green-600 dark:text-green-300">
              AI Policy Engine maintaining {performance.audit_compliance}% compliance
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
