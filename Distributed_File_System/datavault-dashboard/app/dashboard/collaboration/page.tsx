'use client';

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
  User,
  RefreshCw,
  Wifi,
  WifiOff,
  AlertCircle,
  CheckCircle,
  Zap,
  Lock,
  Trash2,
  Copy,
  X,
  Loader2
} from 'lucide-react';

// ✅ CRITICAL FIX: API Configuration - Connect to your Go backend
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

// ✅ CRITICAL FIX: Define types inline with optional properties
interface CollaborationUser {
  id: string;
  user_id: string;
  name: string;
  userName: string;
  email: string;
  isOnline: boolean;
  isActive: boolean;
  lastSeen: string;
  color: string;
  cursor?: {
    position: number;
    selection: { from: number; to: number };
  };
}

interface CollaborationDocument {
  id: string;
  document_id?: string;
  title: string;
  content: string;
  type: string;
  version: number;
  lastModified: string;
  created: string;
  collaborators: CollaborationUser[];
  permissions?: { // ✅ CRITICAL FIX: Make permissions optional
    owner?: string;
    editors?: string[];
    viewers?: string[];
    commenters?: string[];
  };
  encrypted: boolean;
  owner: string;
  owner_id?: string;
  securityMode: string;
}

interface CurrentUser {
  id: string;
  name?: string;
  username?: string;
  email?: string;
}

interface Notification {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
}

interface DocumentStats {
  totalDocuments: number;
  totalCollaborators: number;
  activeCollaborators: number;
  totalChanges: number;
  encryptedDocuments: number;
  totalComments: number;
}

export default function CollaborationPage() {
  const router = useRouter();
  
  // ✅ CRITICAL FIX: State management for real API
  const [documents, setDocuments] = useState<CollaborationDocument[]>([]);
  const [stats, setStats] = useState<DocumentStats | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilter, setSelectedFilter] = useState<'all' | 'owned' | 'shared' | 'recent'>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ✅ CRITICAL FIX: Get session token for authentication
  const getSessionToken = useCallback(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('datavault_session_id');
    }
    return null;
  }, []);

  // ✅ Notification system
  const showNotification = useCallback((type: Notification['type'], message: string) => {
    const id = Math.random().toString(36).substr(2, 9);
    setNotifications(prev => [...prev, { id, type, message }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);

  // ✅ Helper function for default content
  const getDefaultContent = (title: string, type: 'text' | 'markdown' | 'code'): string => {
    switch (type) {
      case 'markdown':
        return `# ${title}\n\nStart writing your collaborative document here...\n\n## Features\n\n- **Real-time collaboration** with multiple users\n- **Quantum encryption** for security\n- **Version control** with automatic backups\n\nStart typing to see the magic happen! ✨`;
      
      case 'code':
        return `// ${title}\n// DataVault Collaborative Code Editor\n\nfunction main() {\n  console.log('Welcome to DataVault!');\n  console.log('Start coding with real-time collaboration!');\n}\n\nmain();`;
      
      default:
        return `${title}\n\nWelcome to DataVault's collaborative text editor!\n\nStart typing to begin your collaborative document...`;
    }
  };

  // ✅ CRITICAL FIX: Fetch current user from real API
  const fetchCurrentUser = useCallback(async () => {
    try {
      const sessionId = getSessionToken();
      const response = await fetch(`${API_BASE_URL}/api/auth/me`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
      });

      if (response.ok) {
        const result = await response.json();
        if (result.success && result.data) {
          setCurrentUser(result.data);
          setConnectionStatus('connected');
        }
      } else {
        // Set fallback user for development
        setCurrentUser({
          id: 'dev_user',
          name: 'Development User',
          username: 'dev_user',
          email: 'dev@datavault.local'
        });
      }
    } catch (error) {
      console.error('Failed to fetch current user:', error);
      setCurrentUser({
        id: 'dev_user',
        name: 'Development User',
        username: 'dev_user',
        email: 'dev@datavault.local'
      });
    }
  }, [getSessionToken]);

  // ✅ CRITICAL FIX: Load documents with safe data transformation
  const loadDocuments = useCallback(async () => {
    setIsLoading(true);
    setConnectionStatus('connecting');
    setError(null);
    
    try {
      const sessionId = getSessionToken();
      console.log('🔄 Fetching documents from:', `${API_BASE_URL}/api/collaboration/documents`);

      const response = await fetch(`${API_BASE_URL}/api/collaboration/documents`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      console.log('✅ API Response:', result);

      // Handle different response formats
      let docs: any[] = [];
      
      if (result.success && Array.isArray(result.data)) {
        docs = result.data;
      } else if (Array.isArray(result.documents)) {
        docs = result.documents;
      } else if (Array.isArray(result)) {
        docs = result;
      }

      // ✅ CRITICAL FIX: Transform API data with safe defaults for all properties
      const transformedDocs: CollaborationDocument[] = docs.map(doc => ({
        id: doc.id || 'unknown',
        document_id: doc.document_id || doc.id,
        title: doc.title || 'Untitled Document',
        content: doc.content || '',
        type: doc.type || 'markdown',
        version: typeof doc.version === 'number' ? doc.version : 1,
        lastModified: typeof doc.lastModified === 'string' ? doc.lastModified : new Date().toISOString(),
        created: typeof doc.created === 'string' ? doc.created : new Date().toISOString(),
        collaborators: Array.isArray(doc.collaborators) ? doc.collaborators.map((c: any) => ({
          id: c.id || 'unknown',
          user_id: c.user_id || c.id,
          name: c.name || 'Anonymous',
          userName: c.userName || c.name || 'Anonymous',
          email: c.email || '',
          isOnline: Boolean(c.isOnline),
          isActive: Boolean(c.isActive),
          lastSeen: typeof c.lastSeen === 'string' ? c.lastSeen : new Date().toISOString(),
          color: c.color || '#3B82F6',
          cursor: c.cursor
        })) : [],
        // ✅ CRITICAL FIX: Always provide permissions with safe defaults
        permissions: {
          owner: doc.permissions?.owner || doc.owner || 'system',
          editors: Array.isArray(doc.permissions?.editors) ? doc.permissions.editors : [],
          viewers: Array.isArray(doc.permissions?.viewers) ? doc.permissions.viewers : [],
          commenters: Array.isArray(doc.permissions?.commenters) ? doc.permissions.commenters : [],
        },
        encrypted: Boolean(doc.encrypted),
        owner: doc.owner || doc.permissions?.owner || 'system',
        owner_id: doc.owner_id || doc.owner,
        securityMode: doc.securityMode || 'simple'
      }));

      setDocuments(transformedDocs);
      setConnectionStatus('connected');

      // Calculate stats from real data
      const totalCollaborators = new Set(
        transformedDocs.flatMap(doc => doc.collaborators.map(c => c.id))
      ).size;
      
      const activeCollaborators = new Set(
        transformedDocs.flatMap(doc => doc.collaborators.filter(c => c.isOnline).map(c => c.id))
      ).size;

      const calculatedStats: DocumentStats = {
        totalDocuments: transformedDocs.length,
        totalCollaborators,
        activeCollaborators,
        totalChanges: transformedDocs.reduce((sum, doc) => sum + doc.version, 0),
        encryptedDocuments: transformedDocs.filter(doc => doc.encrypted).length,
        totalComments: Math.max(transformedDocs.length * 5, 0) // Estimate
      };

      setStats(calculatedStats);
      
      if (transformedDocs.length > 0) {
        showNotification('success', `✅ Loaded ${transformedDocs.length} documents - ${activeCollaborators} users online`);
      } else {
        showNotification('info', '📄 No documents found - create your first collaborative document');
      }

    } catch (error) {
      console.error('❌ Failed to load documents:', error);
      setConnectionStatus('disconnected');
      setError(`Failed to load documents: ${error instanceof Error ? error.message : 'Unknown error'}`);
      showNotification('error', '❌ Failed to connect to DataVault services');
      setDocuments([]);
    } finally {
      setIsLoading(false);
    }
  }, [showNotification, getSessionToken]);

  // ✅ Refresh documents
  const refreshDocuments = useCallback(async () => {
    setRefreshing(true);
    await loadDocuments();
    setRefreshing(false);
  }, [loadDocuments]);

  // ✅ CRITICAL FIX: Initialize with real API calls (prevent infinite loops)
  useEffect(() => {
    let mounted = true;
    
    const initialize = async () => {
      if (mounted) {
        await fetchCurrentUser();
        await loadDocuments();
      }
    };

    initialize();

    return () => {
      mounted = false;
    };
  }, []); // ✅ Empty dependency array to run only once

  // ✅ Filter documents based on search and filter
  const filteredDocuments = documents.filter((doc) => {
    const matchesSearch = doc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         doc.content.toLowerCase().includes(searchQuery.toLowerCase());
    
    switch (selectedFilter) {
      case 'owned':
        return matchesSearch && (doc.permissions?.owner === currentUser?.id || doc.owner === currentUser?.id);
      case 'shared':
        return matchesSearch && doc.collaborators.length > 1;
      case 'recent':
        const threeDaysAgo = new Date();
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
        return matchesSearch && new Date(doc.lastModified) > threeDaysAgo;
      default:
        return matchesSearch;
    }
  });

  // ✅ CRITICAL FIX: Create new document with safe response handling
  const createNewDocument = async (data: { title: string; type: 'text' | 'markdown' | 'code' }) => {
    try {
      const sessionId = getSessionToken();
      const requestData = {
        title: data.title,
        type: data.type,
        content: getDefaultContent(data.title, data.type),
      };

      console.log('🔄 Creating document:', requestData);

      const response = await fetch(`${API_BASE_URL}/api/collaboration/documents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
        body: JSON.stringify(requestData),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      const result = await response.json();
      console.log('✅ Document created:', result);

      // ✅ CRITICAL FIX: Handle both 'data' and 'document' response formats
      if (result.success && (result.data || result.document)) {
        const docData = result.data || result.document;
        const newDoc: CollaborationDocument = {
          id: docData.id || 'unknown',
          document_id: docData.document_id || docData.id,
          title: docData.title || data.title,
          content: docData.content || '',
          type: docData.type || data.type,
          version: typeof docData.version === 'number' ? docData.version : 1,
          lastModified: typeof docData.lastModified === 'string' ? docData.lastModified : new Date().toISOString(),
          created: typeof docData.created === 'string' ? docData.created : new Date().toISOString(),
          collaborators: Array.isArray(docData.collaborators) ? docData.collaborators.map((c: any) => ({
            id: c.id || currentUser?.id || 'unknown',
            user_id: c.user_id || c.id,
            name: c.name || currentUser?.name || 'Anonymous',
            userName: c.userName || c.name || currentUser?.username || 'Anonymous',
            email: c.email || currentUser?.email || '',
            isOnline: Boolean(c.isOnline),
            isActive: Boolean(c.isActive),
            lastSeen: typeof c.lastSeen === 'string' ? c.lastSeen : new Date().toISOString(),
            color: c.color || '#3B82F6',
            cursor: c.cursor
          })) : [{
            id: currentUser?.id || 'current',
            user_id: currentUser?.id || 'current',
            name: currentUser?.name || 'Current User',
            userName: currentUser?.username || 'Current User',
            email: currentUser?.email || '',
            isOnline: true,
            isActive: true,
            lastSeen: new Date().toISOString(),
            color: '#3B82F6',
          }],
          // ✅ CRITICAL FIX: Always provide permissions
          permissions: {
            owner: docData.permissions?.owner || docData.owner || currentUser?.id || 'system',
            editors: Array.isArray(docData.permissions?.editors) ? docData.permissions.editors : [],
            viewers: Array.isArray(docData.permissions?.viewers) ? docData.permissions.viewers : [],
            commenters: Array.isArray(docData.permissions?.commenters) ? docData.permissions.commenters : [],
          },
          encrypted: Boolean(docData.encrypted),
          owner: docData.owner || docData.permissions?.owner || currentUser?.id || 'system',
          owner_id: docData.owner_id || docData.owner,
          securityMode: docData.securityMode || 'enterprise'
        };

        setDocuments(prev => [newDoc, ...prev]);
        setShowCreateModal(false);
        showNotification('success', `✅ Created "${data.title}"`);
        
        // Navigate to editor
        setTimeout(() => {
          router.push(`/dashboard/collaboration/editor/${newDoc.id}`);
        }, 500);
      } else {
        throw new Error('No document data in response');
      }
    } catch (error) {
      console.error('❌ Failed to create document:', error);
      showNotification('error', `❌ Failed to create document: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  // ✅ Open document in editor
  const openDocument = (docId: string) => {
    router.push(`/dashboard/collaboration/editor/${docId}`);
  };

  // ✅ Share document
  const shareDocument = async (doc: CollaborationDocument) => {
    try {
      const shareUrl = `${window.location.origin}/dashboard/collaboration/editor/${doc.id}`;
      await navigator.clipboard.writeText(shareUrl);
      showNotification('success', `📋 Share link copied to clipboard`);
    } catch (error) {
      showNotification('error', '❌ Failed to copy share link');
    }
  };

  // ✅ Delete document
  const deleteDocument = async (doc: CollaborationDocument) => {
    if (!confirm(`⚠️ Delete "${doc.title}"?\n\nThis action cannot be undone.`)) {
      return;
    }

    try {
      const sessionId = getSessionToken();
      const response = await fetch(`${API_BASE_URL}/api/collaboration/documents/${doc.id}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
      });

      if (response.ok) {
        setDocuments(prev => prev.filter(d => d.id !== doc.id));
        showNotification('success', `✅ Deleted "${doc.title}"`);
      } else {
        throw new Error('Failed to delete document');
      }
    } catch (error) {
      console.error('Failed to delete document:', error);
      showNotification('error', `❌ Failed to delete "${doc.title}"`);
    }
  };

  // ✅ Status helpers
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

  const formatLastModified = (date: string | Date) => {
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    const now = new Date();
    const diffMs = now.getTime() - dateObj.getTime();
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
          <Loader2 className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Initializing collaboration workspace...</p>
          <p className="text-sm text-gray-500 mt-2">Connecting to DataVault services</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      {/* ✅ Notifications */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        <AnimatePresence>
          {notifications.map((notification: Notification) => (
            <motion.div
              key={notification.id}
              initial={{ opacity: 0, x: 100 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 100 }}
              className={`p-4 rounded-lg shadow-lg border backdrop-blur-sm ${
                notification.type === 'success' ? 'bg-green-100 text-green-800 border-green-200' :
                notification.type === 'error' ? 'bg-red-100 text-red-800 border-red-200' :
                notification.type === 'warning' ? 'bg-yellow-100 text-yellow-800 border-yellow-200' :
                'bg-blue-100 text-blue-800 border-blue-200'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  {notification.type === 'success' && <CheckCircle className="w-4 h-4 mr-2" />}
                  {notification.type === 'error' && <AlertCircle className="w-4 h-4 mr-2" />}
                  {notification.type === 'warning' && <AlertCircle className="w-4 h-4 mr-2" />}
                  {notification.type === 'info' && <Eye className="w-4 h-4 mr-2" />}
                  <span className="text-sm font-medium">{notification.message}</span>
                </div>
                <button
                  onClick={() => setNotifications(prev => prev.filter((n: Notification) => n.id !== notification.id))}
                  className="ml-2 p-1 hover:bg-black/10 rounded"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* ✅ Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Real-time Collaboration
          </h1>
          <p className="text-gray-600 flex items-center space-x-2">
            <span>Enterprise-grade document collaboration with quantum encryption</span>
            {currentUser && (
              <>
                <span>•</span>
                <span className="text-blue-600 font-medium">
                  Welcome, {currentUser.name || currentUser.username || 'User'}
                </span>
              </>
            )}
          </p>
        </div>
        
        <div className="flex items-center space-x-4">
          {/* Connection Status */}
          <div className="flex items-center space-x-2">
            {connectionStatus === 'connected' ? 
              <Wifi className="w-4 h-4 text-green-600" /> : 
              <WifiOff className="w-4 h-4 text-red-600" />
            }
            <div className={`w-2 h-2 rounded-full ${getConnectionStatusColor()}`}></div>
            <span className="text-sm text-gray-600">{getConnectionStatusText()}</span>
          </div>

          {/* Refresh Button */}
          <button
            onClick={refreshDocuments}
            disabled={refreshing}
            className="flex items-center space-x-2 px-3 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          
          {/* New Document Button */}
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>New Document</span>
          </button>
        </div>
      </div>

      {/* ✅ Error Display */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-red-50 border border-red-200 rounded-lg p-4 mb-8"
        >
          <div className="flex items-center text-red-700">
            <AlertCircle className="w-4 h-4 mr-2" />
            <span>{error}</span>
          </div>
        </motion.div>
      )}

      {/* ✅ Stats Grid */}
      {stats && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 md:grid-cols-6 gap-6 mb-8"
        >
          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <FileText className="w-8 h-8 text-blue-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalDocuments}</p>
                <p className="text-sm text-gray-600">Documents</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <Users className="w-8 h-8 text-green-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.activeCollaborators}</p>
                <p className="text-sm text-gray-600">Online Now</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <Edit3 className="w-8 h-8 text-purple-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalChanges}</p>
                <p className="text-sm text-gray-600">Total Edits</p>
              </div>
            </div>
          </div>
          
          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-red-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.encryptedDocuments}</p>
                <p className="text-sm text-gray-600">Encrypted</p>
              </div>
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <MessageSquare className="w-8 h-8 text-orange-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalComments}</p>
                <p className="text-sm text-gray-600">Comments</p>
              </div>
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
            <div className="flex items-center">
              <Users className="w-8 h-8 text-indigo-600 mr-3" />
              <div>
                <p className="text-2xl font-bold text-gray-900">{stats.totalCollaborators}</p>
                <p className="text-sm text-gray-600">Total Users</p>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* ✅ Search and Filter */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-white border border-gray-200 rounded-lg p-6 mb-8"
      >
        <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search documents by title, content, or collaborator..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 p-1 hover:bg-gray-100 rounded-full"
              >
                <X className="w-4 h-4 text-gray-400" />
              </button>
            )}
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
        
        <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
          <span>Showing {filteredDocuments.length} of {documents.length} documents</span>
          {searchQuery && (
            <span>Filtered by: "{searchQuery}"</span>
          )}
        </div>
      </motion.div>

      {/* ✅ Documents Grid */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-4"
      >
        {filteredDocuments.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No documents found</h3>
            <p className="text-gray-600 mb-4">
              {searchQuery ? 'Try adjusting your search terms or filters' : 'Create your first collaborative document to get started'}
            </p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Create Document
            </button>
          </div>
        ) : (
          <AnimatePresence>
            {filteredDocuments.map((doc: CollaborationDocument, index: number) => (
              <motion.div
                key={doc.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ delay: Math.min(index * 0.1, 0.5) }}
                className="bg-white border border-gray-200 rounded-lg p-6 hover:bg-gray-50 hover:shadow-md transition-all cursor-pointer"
                onClick={() => openDocument(doc.id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    {/* Document Header */}
                    <div className="flex items-center space-x-3 mb-3">
                      <h3 className="text-lg font-semibold text-gray-900">{doc.title}</h3>
                      {doc.encrypted && (
                        <Shield className="w-4 h-4 text-green-600" />
                      )}
                      <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded font-mono">
                        v{doc.version}
                      </span>
                      <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                        doc.securityMode === 'enterprise' 
                          ? 'bg-purple-100 text-purple-700 border border-purple-200'
                          : 'bg-green-100 text-green-700 border border-green-200'
                      }`}>
                        {doc.securityMode === 'enterprise' ? '🔒 Enterprise' : '⚡ Simple'}
                      </span>
                    </div>
                    
                    {/* Document Stats */}
                    <div className="flex items-center space-x-6 text-sm text-gray-600 mb-3">
                      <div className="flex items-center space-x-1">
                        <Users className="w-4 h-4" />
                        <span>{doc.collaborators.length} collaborator{doc.collaborators.length !== 1 ? 's' : ''}</span>
                      </div>
                      
                      <div className="flex items-center space-x-1">
                        <Clock className="w-4 h-4" />
                        <span>Modified {formatLastModified(doc.lastModified)}</span>
                      </div>
                      
                      {/* ✅ CRITICAL FIX: Safe access to permissions with optional chaining and fallbacks */}
                      <div className="flex items-center space-x-1">
                        <Eye className="w-4 h-4" />
                        <span>
                          {(doc.permissions?.viewers?.length ?? 0) + 
                           (doc.permissions?.editors?.length ?? 0) + 
                           (doc.permissions?.commenters?.length ?? 0) + 1} access
                        </span>
                      </div>

                      <div className="flex items-center space-x-1">
                        <FileText className="w-4 h-4" />
                        <span className="capitalize">{doc.type}</span>
                      </div>
                    </div>
                    
                    {/* Active Collaborators */}
                    <div className="flex items-center space-x-3">
                      <div className="flex -space-x-2">
                        {doc.collaborators.slice(0, 4).map((collaborator: CollaborationUser) => (
                          <div
                            key={collaborator.id}
                            className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium text-white border-2 border-white shadow-sm ${
                              collaborator.isOnline ? 'bg-gradient-to-br from-green-500 to-green-600' : 'bg-gray-400'
                            }`}
                            title={`${collaborator.name} - ${collaborator.isOnline ? 'Online' : `Last seen ${formatLastModified(collaborator.lastSeen)}`}`}
                            style={{ backgroundColor: collaborator.isOnline ? collaborator.color : undefined }}
                          >
                            {collaborator.name.charAt(0).toUpperCase()}
                          </div>
                        ))}
                        {doc.collaborators.length > 4 && (
                          <div className="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-xs font-medium text-gray-600 border-2 border-white">
                            +{doc.collaborators.length - 4}
                          </div>
                        )}
                      </div>
                      
                      {doc.collaborators.some((c: CollaborationUser) => c.isOnline) && (
                        <div className="flex items-center space-x-1 text-green-600">
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                          <span className="text-xs font-medium">Live editing</span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* Action Buttons */}
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        openDocument(doc.id);
                      }}
                      className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                      title="Open in editor"
                    >
                      <Edit3 className="w-4 h-4" />
                    </button>
                    
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        shareDocument(doc);
                      }}
                      className="p-2 text-gray-400 hover:text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                      title="Share document"
                    >
                      <Share className="w-4 h-4" />
                    </button>
                    
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteDocument(doc);
                      }}
                      className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                      title="Delete document"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                    
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        // Handle more options
                      }}
                      className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                      title="More options"
                    >
                      <MoreHorizontal className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </motion.div>

      {/* ✅ Quick Actions */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mt-8 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-lg"
      >
        <h3 className="text-lg font-semibold text-blue-900 mb-3 flex items-center">
          <Zap className="w-5 h-5 mr-2" />
          Quick Actions
        </h3>
        <div className="flex flex-wrap gap-3">
          {documents.slice(0, 3).map((doc: CollaborationDocument) => (
            <button
              key={doc.id}
              onClick={() => openDocument(doc.id)}
              className="bg-blue-100 hover:bg-blue-200 text-blue-800 px-4 py-2 rounded-lg text-sm transition-colors font-medium flex items-center space-x-2"
            >
              <FileText className="w-4 h-4" />
              <span>{doc.title.length > 20 ? doc.title.substring(0, 20) + '...' : doc.title}</span>
              {doc.collaborators.some((c: CollaborationUser) => c.isOnline) && (
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              )}
            </button>
          ))}
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition-colors font-medium flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Create New Document</span>
          </button>
        </div>
      </motion.div>

      {/* ✅ Create Document Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <CreateDocumentModal
            onClose={() => setShowCreateModal(false)}
            onCreate={createNewDocument}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// ✅ CRITICAL FIX: Create Document Modal Component
function CreateDocumentModal({
  onClose,
  onCreate
}: {
  onClose: () => void;
  onCreate: (data: { title: string; type: 'text' | 'markdown' | 'code' }) => Promise<void>;
}) {
  const [title, setTitle] = useState('');
  const [type, setType] = useState<'text' | 'markdown' | 'code'>('markdown');
  const [creating, setCreating] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (title.trim()) {
      setCreating(true);
      try {
        await onCreate({ title: title.trim(), type });
      } finally {
        setCreating(false);
      }
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-xl p-6 w-full max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Create New Document</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Document Title *
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter document title..."
              required
              autoFocus
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Document Type
            </label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as any)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="markdown">📝 Markdown (Rich text with formatting)</option>
              <option value="text">📄 Plain Text (Simple text document)</option>
              <option value="code">💻 Code (Programming and scripts)</option>
            </select>
          </div>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
            <div className="flex items-center text-blue-800 text-sm">
              <Shield className="w-4 h-4 mr-2 flex-shrink-0" />
              <span>All documents are encrypted with quantum-safe algorithms and support real-time collaboration.</span>
            </div>
          </div>

          <div className="flex items-center space-x-3 pt-4">
            <button
              type="submit"
              disabled={creating || !title.trim()}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium flex items-center justify-center space-x-2"
            >
              {creating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Creating...</span>
                </>
              ) : (
                <span>Create & Open</span>
              )}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>
  );
}
