'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useRouter } from 'next/navigation';
import { 
  FileText, 
  Users, 
  MessageSquare, 
  Plus, 
  Search, 
  Filter,
  Clock,
  Shield,
  Eye,
  Share,
  MoreHorizontal,
  Edit3,
  User
} from 'lucide-react';
import { collaborationService, CollaborationDocument } from '../../lib/collaboration/collaborationService';

export default function CollaborationPage() {
  const router = useRouter();
  const [documents, setDocuments] = useState<CollaborationDocument[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<'all' | 'owned' | 'shared' | 'recent'>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');

  // Initialize collaboration data
  useEffect(() => {
    const initializeCollaboration = async () => {
      if (!collaborationService) {
        console.log('⚠️ Collaboration service not available (SSR)');
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      
      try {
        // Set connection status
        setConnectionStatus(collaborationService.isConnected() ? 'connected' : 'disconnected');
        
        // Load sample documents (replace with actual API call)
        const sampleDocs: CollaborationDocument[] = [
          {
            id: 'quarterly-report-2024',
            title: 'Q4 Financial Report 2024',
            content: '{"type":"doc","content":[{"type":"heading","attrs":{"level":1},"content":[{"type":"text","text":"Q4 Financial Report 2024"}]}]}',
            version: 3,
            lastModified: new Date('2024-07-24T10:30:00Z'),
            collaborators: [
              { id: '1', name: 'John Doe', email: 'john@enterprise.com', isOnline: true, lastSeen: new Date() },
              { id: '2', name: 'Jane Smith', email: 'jane@enterprise.com', isOnline: false, lastSeen: new Date('2024-07-24T09:15:00Z') }
            ],
            permissions: {
              owner: '1',
              editors: ['1', '2'],
              commenters: ['3'],
              viewers: ['4', '5']
            },
            encrypted: true
          },
          {
            id: 'product-roadmap-2024',
            title: 'Product Roadmap 2024',
            content: '{"type":"doc","content":[{"type":"heading","attrs":{"level":1},"content":[{"type":"text","text":"Product Roadmap 2024"}]}]}',
            version: 7,
            lastModified: new Date('2024-07-24T08:45:00Z'),
            collaborators: [
              { id: '2', name: 'Jane Smith', email: 'jane@enterprise.com', isOnline: true, lastSeen: new Date() },
              { id: '3', name: 'Mike Johnson', email: 'mike@enterprise.com', isOnline: true, lastSeen: new Date() }
            ],
            permissions: {
              owner: '2',
              editors: ['2', '3'],
              commenters: ['1'],
              viewers: []
            },
            encrypted: true
          },
          {
            id: 'security-compliance-audit',
            title: 'Security Compliance Audit',
            content: '{"type":"doc","content":[{"type":"heading","attrs":{"level":1},"content":[{"type":"text","text":"Security Compliance Audit"}]}]}',
            version: 12,
            lastModified: new Date('2024-07-23T16:20:00Z'),
            collaborators: [
              { id: '1', name: 'John Doe', email: 'john@enterprise.com', isOnline: false, lastSeen: new Date('2024-07-24T07:30:00Z') }
            ],
            permissions: {
              owner: '1',
              editors: ['1'],
              commenters: [],
              viewers: ['2', '3']
            },
            encrypted: true
          }
        ];

        setDocuments(sampleDocs);

        // Calculate stats
        const totalCollaborators = new Set(
          sampleDocs.flatMap(doc => doc.collaborators.map(c => c.id))
        ).size;
        
        const activeCollaborators = new Set(
          sampleDocs.flatMap(doc => doc.collaborators.filter(c => c.isOnline).map(c => c.id))
        ).size;

        setStats({
          totalDocuments: sampleDocs.length,
          totalCollaborators,
          activeCollaborators,
          totalChanges: sampleDocs.reduce((sum, doc) => sum + doc.version, 0),
          encryptedDocuments: sampleDocs.filter(doc => doc.encrypted).length
        });

      } catch (error) {
        console.error('❌ Failed to initialize collaboration:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initializeCollaboration();

    // Monitor connection status
    const connectionInterval = setInterval(() => {
      if (collaborationService) {
        setConnectionStatus(collaborationService.isConnected() ? 'connected' : 'disconnected');
      }
    }, 5000);

    return () => clearInterval(connectionInterval);
  }, []);

  // Filter documents based on search and filter
  const filteredDocuments = documents.filter(doc => {
    const matchesSearch = doc.title.toLowerCase().includes(searchQuery.toLowerCase());
    
    switch (selectedFilter) {
      case 'owned':
        return matchesSearch && doc.permissions.owner === '1'; // Current user ID
      case 'shared':
        return matchesSearch && doc.collaborators.length > 1;
      case 'recent':
        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
        return matchesSearch && doc.lastModified > threeDaysAgo;
      default:
        return matchesSearch;
    }
  });

  const createNewDocument = () => {
    const docId = `doc-${Date.now()}`;
    router.push(`/dashboard/collaboration/editor/${docId}`);
  };

  const openDocument = (docId: string) => {
    router.push(`/dashboard/collaboration/editor/${docId}`);
  };

  const getConnectionStatusColor = () => {
    switch (connectionStatus) {
      case 'connected': return 'bg-green-500';
      case 'disconnected': return 'bg-red-500';
      case 'connecting': return 'bg-yellow-500';
      default: return 'bg-gray-500';
    }
  };

  const getConnectionStatusText = () => {
    switch (connectionStatus) {
      case 'connected': return 'Connected';
      case 'disconnected': return 'Offline';
      case 'connecting': return 'Connecting';
      default: return 'Unknown';
    }
  };

  const formatLastModified = (date: Date) => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading collaboration platform...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Real-time Collaboration
          </h1>
          <p className="text-gray-600">
            Enterprise-grade document collaboration with quantum encryption
          </p>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${getConnectionStatusColor()}`}></div>
            <span className="text-sm text-gray-600">{getConnectionStatusText()}</span>
          </div>
          
          <button
            onClick={createNewDocument}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>New Document</span>
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
          <div className="bg-white border border-gray-200 rounded-lg p-6">
            <div className="flex items-center">
              <FileText className="w-8 h-8 text-blue-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalDocuments}</p>
                <p className="text-sm text-gray-600">Documents</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6">
            <div className="flex items-center">
              <Users className="w-8 h-8 text-green-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.activeCollaborators}</p>
                <p className="text-sm text-gray-600">Active Users</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6">
            <div className="flex items-center">
              <Edit3 className="w-8 h-8 text-purple-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalChanges}</p>
                <p className="text-sm text-gray-600">Total Edits</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-red-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.encryptedDocuments}</p>
                <p className="text-sm text-gray-600">Encrypted</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6">
            <div className="flex items-center">
              <MessageSquare className="w-8 h-8 text-orange-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">24</p>
                <p className="text-sm text-gray-600">Comments</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Search and Filter */}
      <div className="bg-white border border-gray-200 rounded-lg p-6 mb-8">
        <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search documents..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <div className="flex space-x-2">
            {[
              { key: 'all', label: 'All', icon: FileText },
              { key: 'owned', label: 'Owned', icon: User },
              { key: 'shared', label: 'Shared', icon: Users },
              { key: 'recent', label: 'Recent', icon: Clock },
            ].map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setSelectedFilter(key as any)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  selectedFilter === key
                    ? 'bg-blue-100 text-blue-700 border border-blue-300'
                    : 'text-gray-700 hover:bg-gray-100 border border-transparent'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Documents Grid */}
      <div className="space-y-4">
        {filteredDocuments.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No documents found</h3>
            <p className="text-gray-600 mb-4">
              {searchQuery ? 'Try adjusting your search terms' : 'Create your first collaborative document'}
            </p>
            <button
              onClick={createNewDocument}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Create Document
            </button>
          </div>
        ) : (
          filteredDocuments.map((doc) => (
            <motion.div
              key={doc.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white border border-gray-200 rounded-lg p-6 hover:bg-gray-50 transition-colors cursor-pointer"
              onClick={() => openDocument(doc.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900">{doc.title}</h3>
                    {doc.encrypted && (
                      <Shield className="w-4 h-4 text-green-600" title="Quantum Encrypted" />
                    )}
                    <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                      v{doc.version}
                    </span>
                  </div>
                  
                  <div className="flex items-center space-x-6 text-sm text-gray-600">
                    <div className="flex items-center space-x-1">
                      <Users className="w-4 h-4" />
                      <span>{doc.collaborators.length} collaborator{doc.collaborators.length !== 1 ? 's' : ''}</span>
                    </div>
                    
                    <div className="flex items-center space-x-1">
                      <Clock className="w-4 h-4" />
                      <span>Modified {formatLastModified(doc.lastModified)}</span>
                    </div>
                    
                    <div className="flex items-center space-x-1">
                      <Eye className="w-4 h-4" />
                      <span>{doc.permissions.viewers.length + doc.permissions.editors.length + doc.permissions.commenters.length + 1} access</span>
                    </div>
                  </div>
                  
                  {/* Active Collaborators */}
                  <div className="flex items-center space-x-2 mt-3">
                    <div className="flex -space-x-2">
                      {doc.collaborators.slice(0, 3).map((collaborator) => (
                        <div
                          key={collaborator.id}
                          className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium text-white border-2 border-white ${
                            collaborator.isOnline ? 'bg-green-500' : 'bg-gray-400'
                          }`}
                          title={`${collaborator.name} - ${collaborator.isOnline ? 'Online' : 'Offline'}`}
                        >
                          {collaborator.name.charAt(0).toUpperCase()}
                        </div>
                      ))}
                      {doc.collaborators.length > 3 && (
                        <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-medium text-gray-600 border-2 border-white">
                          +{doc.collaborators.length - 3}
                        </div>
                      )}
                    </div>
                    
                    {doc.collaborators.some(c => c.isOnline) && (
                      <div className="flex items-center space-x-1 text-green-600">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        <span className="text-xs">Live</span>
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      openDocument(doc.id);
                    }}
                    className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
                  >
                    <Edit3 className="w-4 h-4" />
                  </button>
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Handle share action
                    }}
                    className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
                  >
                    <Share className="w-4 h-4" />
                  </button>
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      // Handle more options
                    }}
                    className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100"
                  >
                    <MoreHorizontal className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>

      {/* Quick Actions */}
      <div className="mt-8 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">Quick Start</h3>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => openDocument('quarterly-report-2024')}
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            📊 Q4 Financial Report
          </button>
          <button
            onClick={() => openDocument('product-roadmap-2024')}
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            🚀 Product Roadmap
          </button>
          <button
            onClick={() => openDocument('security-compliance-audit')}
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            🔒 Security Audit
          </button>
          <button
            onClick={createNewDocument}
            className="bg-blue-100 text-blue-800 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
          >
            ➕ Create New Document
          </button>
        </div>
      </div>
    </div>
  );
}
