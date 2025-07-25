'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { FileText, Plus, Users, Lock, Zap } from 'lucide-react';

export default function CollaborationPage() {
  const router = useRouter();
  const [newDocName, setNewDocName] = useState('');

  const createDocument = () => {
    const docId = newDocName.trim() ? 
      newDocName.toLowerCase().replace(/\s+/g, '-') : 
      `doc-${Date.now()}`;
    router.push(`/dashboard/collaboration/editor/${docId}`);
  };

  const enterpriseDocuments = [
    {
      id: 'quarterly-financial-report',
      name: 'Q4 Financial Report',
      description: 'Executive quarterly financial analysis with audit compliance',
      collaborators: 5,
      lastModified: '2 hours ago',
      encrypted: true
    },
    {
      id: 'product-roadmap-2024',
      name: 'Product Roadmap 2024',
      description: 'Strategic product development plan with market analysis',
      collaborators: 8,
      lastModified: '1 day ago',
      encrypted: true
    },
    {
      id: 'security-compliance-audit',
      name: 'Security Compliance Audit',
      description: 'GDPR and SOX compliance documentation',
      collaborators: 3,
      lastModified: '3 days ago',
      encrypted: true
    }
  ];

  return (
    <div className="max-w-7xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          Real-time Collaboration Platform
        </h1>
        <p className="text-gray-600">
          Enterprise-grade document collaboration with quantum encryption and operational transforms
        </p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <div className="flex items-center">
            <FileText className="w-8 h-8 text-blue-600 mr-3" />
            <div>
              <p className="text-2xl font-bold text-gray-900">75%</p>
              <p className="text-sm text-gray-600">Faster Document Creation</p>
            </div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <div className="flex items-center">
            <Users className="w-8 h-8 text-green-600 mr-3" />
            <div>
              <p className="text-2xl font-bold text-gray-900">90%</p>
              <p className="text-sm text-gray-600">Reduction in Email Attachments</p>
            </div>
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-6">
          <div className="flex items-center">
            <Lock className="w-8 h-8 text-purple-600 mr-3" />
            <div>
              <p className="text-2xl font-bold text-gray-900">100%</p>
              <p className="text-sm text-gray-600">Audit Compliance</p>
            </div>
          </div>
        </div>
      </div>

      {/* Create New Document */}
      <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6 mb-8">
        <h2 className="text-xl font-semibold text-gray-800 mb-4 flex items-center">
          <Plus className="w-5 h-5 mr-2" />
          Create New Document
        </h2>
        <div className="flex gap-3">
          <input
            type="text"
            value={newDocName}
            onChange={(e) => setNewDocName(e.target.value)}
            placeholder="Enter document name..."
            className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            onKeyPress={(e) => e.key === 'Enter' && createDocument()}
          />
          <button
            onClick={createDocument}
            className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors flex items-center"
          >
            <Plus className="w-4 h-4 mr-2" />
            Create Document
          </button>
        </div>
      </div>

      {/* Enterprise Documents */}
      <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-6">
          Enterprise Documents
        </h2>
        <div className="space-y-4">
          {enterpriseDocuments.map((doc) => (
            <div
              key={doc.id}
              className="border border-gray-200 rounded-lg p-6 hover:bg-gray-50 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center mb-2">
                    <h3 className="font-semibold text-gray-900 text-lg">{doc.name}</h3>
                    {doc.encrypted && (
                      <Lock className="w-4 h-4 text-green-600 ml-2" title="Quantum Encrypted" />
                    )}
                  </div>
                  <p className="text-gray-600 mb-3">{doc.description}</p>
                  <div className="flex items-center text-sm text-gray-500 space-x-4">
                    <span className="flex items-center">
                      <Users className="w-4 h-4 mr-1" />
                      {doc.collaborators} collaborators
                    </span>
                    <span>Modified {doc.lastModified}</span>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <Link
                    href={`/dashboard/collaboration/editor/${doc.id}`}
                    className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center"
                  >
                    <Zap className="w-4 h-4 mr-2" />
                    Open Editor
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Test Links */}
      <div className="mt-8 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">Quick Test Links</h3>
        <div className="flex flex-wrap gap-3">
          <Link
            href="/dashboard/collaboration/editor/test-doc-123"
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            test-doc-123
          </Link>
          <Link
            href="/dashboard/collaboration/editor/sample-document"
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            sample-document
          </Link>
          <Link
            href="/dashboard/collaboration/editor/enterprise-demo"
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            enterprise-demo
          </Link>
        </div>
      </div>
    </div>
  );
}
