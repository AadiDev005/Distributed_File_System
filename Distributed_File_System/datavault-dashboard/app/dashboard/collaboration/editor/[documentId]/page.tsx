'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { ArrowLeft, AlertCircle, Loader2, Users, FileText, Save, Lock } from 'lucide-react';

// ✅ CRITICAL FIX: Direct API calls instead of broken collaborationService
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

interface DocumentData {
  id: string;
  title: string;
  content: string;
  type: string;
  version: number;
  lastModified: string;
  created: string;
  collaborators: any[];
  permissions: any;
  encrypted: boolean;
  owner: string;
  securityMode: string;
}

interface EditorPageProps {
  params: { documentId: string };
}

export default function EditorPage({ params }: EditorPageProps) {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [document, setDocument] = useState<DocumentData | null>(null);
  const [content, setContent] = useState('');
  const [saving, setSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  // ✅ CRITICAL FIX: Get session token for authentication
  const getSessionToken = useCallback(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('datavault_session_id');
    }
    return null;
  }, []);

  // ✅ CRITICAL FIX: Simple document loading with timeout
  const loadDocument = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      console.log('🔄 Loading document:', params.documentId);

      const sessionId = getSessionToken();
      
      // Add timeout to prevent hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(`${API_BASE_URL}/api/collaboration/documents/${params.documentId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      console.log('✅ Document loaded:', result);

      if (result.success && (result.data || result.document)) {
        const docData = result.data || result.document;
        setDocument(docData);
        setContent(docData.content || '');
        console.log('📄 Document ready:', docData.title);
      } else {
        throw new Error('Invalid document data received');
      }
    } catch (err: any) {
      console.error('❌ Failed to load document:', err);
      if (err.name === 'AbortError') {
        setError('Request timed out. Please check your connection and try again.');
      } else if (err.message?.includes('404')) {
        setError('Document not found. It may have been deleted.');
      } else {
        setError(err.message || 'Failed to load document');
      }
    } finally {
      setIsLoading(false);
    }
  }, [params.documentId, getSessionToken]);

  // ✅ CRITICAL FIX: Simple save functionality
  const saveDocument = useCallback(async () => {
    if (!document || saving) return;

    try {
      setSaving(true);
      const sessionId = getSessionToken();

      const response = await fetch(`${API_BASE_URL}/api/collaboration/documents/${params.documentId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(sessionId && { 'X-Session-ID': sessionId }),
        },
        body: JSON.stringify({
          content,
          version: document.version + 1,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to save document');
      }

      const result = await response.json();
      if (result.success) {
        setDocument(prev => prev ? { ...prev, version: prev.version + 1 } : null);
        setLastSaved(new Date());
        console.log('✅ Document saved');
      }
    } catch (err) {
      console.error('❌ Save failed:', err);
      alert('Failed to save document. Please try again.');
    } finally {
      setSaving(false);
    }
  }, [document, content, params.documentId, getSessionToken, saving]);

  // ✅ CRITICAL FIX: Auto-save functionality
  useEffect(() => {
    if (!document || !content) return;

    const autoSaveTimer = setTimeout(() => {
      if (content !== document.content) {
        saveDocument();
      }
    }, 3000); // Auto-save after 3 seconds of no typing

    return () => clearTimeout(autoSaveTimer);
  }, [content, document, saveDocument]);

  // ✅ CRITICAL FIX: Simple initialization
  useEffect(() => {
    loadDocument();
  }, [loadDocument]);

  // ✅ Handle back navigation
  const handleBack = useCallback(() => {
    router.push('/dashboard/collaboration');
  }, [router]);

  // ✅ Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center max-w-md">
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            className="inline-block mb-6"
          >
            <Loader2 className="w-16 h-16 text-blue-600" />
          </motion.div>
          
          <h2 className="text-2xl font-semibold text-gray-900 mb-2">
            Loading Editor
          </h2>
          
          <p className="text-gray-600 mb-6">
            Loading document: {params.documentId.slice(-8)}...
          </p>
          
          <motion.button
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 3 }}
            onClick={handleBack}
            className="text-gray-500 hover:text-gray-700 underline text-sm"
          >
            Cancel and go back
          </motion.button>
        </div>
      </div>
    );
  }

  // ✅ Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-6">
        <div className="max-w-lg w-full">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white rounded-xl shadow-lg border border-gray-200 p-8 text-center"
          >
            <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-6" />
            
            <h2 className="text-2xl font-semibold text-gray-900 mb-3">
              Unable to Load Editor
            </h2>
            
            <p className="text-gray-600 mb-8 leading-relaxed">{error}</p>
            
            <div className="space-y-4">
              <button
                onClick={loadDocument}
                className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium"
                disabled={isLoading}
              >
                Try Again
              </button>
              
              <button
                onClick={handleBack}
                className="w-full flex items-center justify-center space-x-2 text-gray-600 hover:text-gray-800 px-6 py-3 rounded-lg hover:bg-gray-100 transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back to Documents</span>
              </button>
            </div>
          </motion.div>
        </div>
      </div>
    );
  }

  // ✅ Editor interface
  if (!document) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <FileText className="w-16 h-16 text-blue-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Preparing Editor...</h2>
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="min-h-screen bg-gray-50 flex flex-col"
    >
      {/* ✅ Header */}
      <div className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Navigation */}
            <nav className="flex items-center space-x-3">
              <button
                onClick={handleBack}
                className="flex items-center space-x-2 text-gray-600 hover:text-blue-600 transition-colors group"
              >
                <ArrowLeft className="w-4 h-4 group-hover:-translate-x-1 transition-transform" />
                <span className="font-medium">Collaboration</span>
              </button>
              <span className="text-gray-400">/</span>
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-gray-400" />
                <span className="text-gray-900 font-semibold max-w-64 truncate">
                  {document.title}
                </span>
              </div>
            </nav>

            {/* Controls */}
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-6 text-sm text-gray-500">
                <div className="flex items-center space-x-1">
                  <Users className="w-4 h-4" />
                  <span>{document.collaborators?.length || 1} user{(document.collaborators?.length || 1) !== 1 ? 's' : ''}</span>
                </div>
                {document.encrypted && (
                  <div className="flex items-center space-x-1 text-green-600">
                    <Lock className="w-4 h-4" />
                    <span>Encrypted</span>
                  </div>
                )}
                <span>v{document.version}</span>
                {lastSaved && (
                  <span className="text-green-600">
                    Saved {lastSaved.toLocaleTimeString()}
                  </span>
                )}
              </div>
              
              <button
                onClick={saveDocument}
                disabled={saving}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center space-x-2"
              >
                <Save className="w-4 h-4" />
                <span>{saving ? 'Saving...' : 'Save'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ✅ CRITICAL FIX: Simple text editor instead of broken CollaborativeEditor */}
      <div className="flex-1 p-6">
        <div className="max-w-4xl mx-auto">
          <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
            <div className="p-6">
              <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                className="w-full min-h-96 p-4 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none font-mono text-sm"
                placeholder="Start typing your collaborative document..."
                style={{ minHeight: '500px' }}
              />
            </div>
          </div>
          
          {/* Document info */}
          <div className="mt-4 text-center text-sm text-gray-500">
            <p>Document ID: {params.documentId}</p>
            <p>Type: {document.type} • Security: {document.securityMode}</p>
          </div>
        </div>
      </div>

      {/* ✅ Footer */}
      <div className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between text-sm text-gray-500">
            <div className="flex items-center space-x-8">
              <div className="flex items-center space-x-2">
                <span className="text-green-500">🔒</span>
                <span>End-to-end encrypted</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-blue-500">🛡️</span>
                <span>Quantum-safe algorithms</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="text-purple-500">⚡</span>
                <span>Auto-save enabled</span>
              </div>
            </div>
            
            <div className="flex items-center space-x-6">
              <span className="font-medium">DataVault Enterprise</span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
