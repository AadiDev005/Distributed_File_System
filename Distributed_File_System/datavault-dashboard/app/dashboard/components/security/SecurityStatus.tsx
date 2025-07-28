'use client';

import { useSystemStore } from '../../hooks/useSystemStore';

export default function SecurityStatus() {
  const { bft, quantum, zeroTrust } = useSystemStore();

  const securityLayers = [
    {
      name: 'Byzantine Fault Tolerance',
      status: bft?.consensus_active ? 'Active' : 'Inactive',
      active: bft?.consensus_active || false,
      details: `${bft?.node_count || 0} nodes`,
    },
    {
      name: 'Quantum-Resistant Crypto',
      status: quantum?.quantum_resistant ? 'Active' : 'Inactive',
      active: quantum?.quantum_resistant || false,
      details: quantum?.algorithm || 'CRYSTALS-Dilithium',
    },
    {
      name: 'Zero-Trust Gateway',
      status: zeroTrust?.gateway_active ? 'Active' : 'Inactive',
      active: zeroTrust?.gateway_active || false,
      details: `Trust Score: ${zeroTrust?.trust_score || 0}%`,
    },
    {
      name: 'Dynamic Sharding',
      status: 'Operational',
      active: true,
      details: '16 shards active',
    },
    {
      name: 'Threshold Secret Sharing',
      status: 'Active',
      active: true,
      details: '3-of-5 sharing',
    },
    {
      name: 'Attribute-Based Encryption',
      status: 'Active',
      active: true,
      details: 'Policy-based access',
    },
  ];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">
        🛡️ Security Layer Status
      </h2>
      <div className="space-y-4">
        {securityLayers.map((layer, index) => (
          <div key={index} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <div className="flex items-center space-x-3">
              <div className={`w-3 h-3 rounded-full ${layer.active ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <div>
                <p className="font-medium text-gray-900 dark:text-white">
                  {layer.name}
                </p>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {layer.details}
                </p>
              </div>
            </div>
            <span className={`px-2 py-1 text-xs rounded-full ${
              layer.active 
                ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' 
                : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
            }`}>
              {layer.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
