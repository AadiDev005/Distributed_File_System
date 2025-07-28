'use client';

import { useSystemStore } from '../../hooks/useSystemStore';

export default function MetricsOverview() {
  const { performance, health, lastUpdated } = useSystemStore();

  const metrics = [
    {
      title: 'Efficiency Improvement',
      value: `${performance.efficiency_improvement}%`,
      icon: '⚡',
      color: 'text-green-600 bg-green-100',
      change: '+5%',
    },
    {
      title: 'Security Enhancement',
      value: `${performance.security_enhancement}%`,
      icon: '🛡️',
      color: 'text-blue-600 bg-blue-100',
      change: '+10%',
    },
    {
      title: 'Performance Boost',
      value: `${performance.performance_boost}%`,
      icon: '🚀',
      color: 'text-purple-600 bg-purple-100',
      change: '+8%',
    },
    {
      title: 'Audit Compliance',
      value: `${performance.audit_compliance}%`,
      icon: '📋',
      color: 'text-indigo-600 bg-indigo-100',
      change: 'Perfect',
    },
    {
      title: 'System Availability',
      value: `${performance.availability}%`,
      icon: '🔄',
      color: 'text-emerald-600 bg-emerald-100',
      change: '+0.1%',
    },
    {
      title: 'System Status',
      value: health?.status || 'Loading...',
      icon: '��',
      color: 'text-green-600 bg-green-100',
      change: 'Healthy',
    },
  ];

  return (
    <div className="col-span-full">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            🏆 Enterprise Performance Metrics
          </h2>
          {lastUpdated && (
            <p className="text-sm text-gray-500">
              Last updated: {new Date(lastUpdated).toLocaleTimeString()}
            </p>
          )}
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {metrics.map((metric, index) => (
            <div
              key={index}
              className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 border border-gray-200 dark:border-gray-600"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {metric.title}
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">
                    {metric.value}
                  </p>
                  <p className="text-sm text-green-600">
                    {metric.change}
                  </p>
                </div>
                <div className={`p-3 rounded-full ${metric.color}`}>
                  <span className="text-2xl">{metric.icon}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
