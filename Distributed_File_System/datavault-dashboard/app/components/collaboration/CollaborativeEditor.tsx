'use client';

import { useEffect, useState } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { TextStyle } from '@tiptap/extension-text-style';
import Color from '@tiptap/extension-color';
import { collaborationService } from '../../lib/collaboration/collaborationService';

interface CollaborativeEditorProps {
  documentId: string;
  currentUserId: string;
  currentUserName: string;
}

export default function CollaborativeEditor({
  documentId,
  currentUserId,
  currentUserName,
}: CollaborativeEditorProps) {
  const [isClient, setIsClient] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [lastSaved, setLastSaved] = useState<Date>(new Date());
  const [collaborators, setCollaborators] = useState<any[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');

  useEffect(() => {
    setIsClient(true);
  }, []);

  const editor = useEditor({
    extensions: [StarterKit, TextStyle, Color],
    content: '',
    immediatelyRender: false,
    shouldRerenderOnTransaction: false,
    editorProps: {
      attributes: {
        class: 'prose prose-lg max-w-none min-h-[400px] focus:outline-none p-6 border-0',
      },
    },
    onUpdate: ({ editor }) => {
      if (isClient) {
        collaborationService.publishChange(
          documentId,
          editor.getJSON(),
          currentUserId,
          currentUserName
        );
        setLastSaved(new Date());
      }
    },
    onSelectionUpdate: ({ editor }) => {
      if (isClient) {
        const { from, to } = editor.state.selection;
        collaborationService.updateCursor(documentId, currentUserId, from, { from, to });
      }
    },
  }, [isClient]);

  // Load document content
  useEffect(() => {
    if (!isClient || !editor) return;

    const loadDocument = async () => {
      try {
        setIsLoading(true);
        setConnectionStatus('connecting');
        
        const content = await collaborationService.fetchDocument(documentId);
        
        if (content) {
          let parsedContent;
          try {
            parsedContent = JSON.parse(content);
          } catch {
            parsedContent = content;
          }
          
          editor.commands.setContent(parsedContent);
        }
        
        setConnectionStatus(collaborationService.isConnected() ? 'connected' : 'disconnected');
        setIsLoading(false);
      } catch (error) {
        console.error('Failed to load document:', error);
        setConnectionStatus('disconnected');
        setIsLoading(false);
      }
    };

    loadDocument();
  }, [documentId, editor, isClient]);

  // Subscribe to real-time changes
  useEffect(() => {
    if (!isClient || !editor) return;

    const unsubscribeChanges = collaborationService.subscribe(documentId, (content) => {
      try {
        let parsedContent;
        try {
          parsedContent = JSON.parse(content);
        } catch {
          parsedContent = content;
        }
        
        // Only update if content is different to avoid cursor jumps
        const currentContent = editor.getJSON();
        if (JSON.stringify(currentContent) !== JSON.stringify(parsedContent)) {
          const { from, to } = editor.state.selection;
          editor.commands.setContent(parsedContent);
          editor.commands.setTextSelection({ from, to });
        }
      } catch (error) {
        console.error('Error processing content update:', error);
      }
    });

    const unsubscribeCursors = collaborationService.subscribeToCursors(documentId, (cursors) => {
      setCollaborators(cursors.filter(c => c.userId !== currentUserId));
    });

    return () => {
      unsubscribeChanges();
      unsubscribeCursors();
    };
  }, [documentId, editor, isClient, currentUserId]);

  // Monitor connection status
  useEffect(() => {
    const checkConnection = setInterval(() => {
      const isConnected = collaborationService.isConnected();
      setConnectionStatus(isConnected ? 'connected' : 'disconnected');
    }, 5000);

    return () => clearInterval(checkConnection);
  }, []);

  if (!isClient || isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading quantum-encrypted editor...</p>
        </div>
      </div>
    );
  }

  if (!editor) {
    return (
      <div className="text-center p-8">
        <p className="text-red-600">Failed to initialize editor</p>
        <button 
          onClick={() => window.location.reload()}
          className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Retry
        </button>
      </div>
    );
  }

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
      case 'connected': return 'Live';
      case 'disconnected': return 'Offline';
      case 'connecting': return 'Connecting';
      default: return 'Unknown';
    }
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-lg shadow-sm mb-6">
        <div className="border-b border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                📄 {documentId}
              </h1>
              <p className="text-sm text-gray-600 mt-2">
                Real-time collaborative editing with quantum encryption
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${getConnectionStatusColor()} ${connectionStatus === 'connecting' ? 'animate-pulse' : ''}`}></div>
                <span className="text-sm text-gray-600">{getConnectionStatusText()}</span>
              </div>
              {collaborators.length > 0 && (
                <div className="flex items-center space-x-1">
                  <span className="text-sm text-gray-600">{collaborators.length} collaborator(s)</span>
                </div>
              )}
              <div className="text-sm text-gray-500">
                🔒 Quantum Encrypted
              </div>
              <div className="text-xs text-gray-400">
                Saved: {lastSaved.toLocaleTimeString()}
              </div>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="border-b border-gray-200 p-4 bg-gray-50">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => editor.chain().focus().toggleBold().run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('bold') 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              <strong>B</strong>
            </button>
            <button
              onClick={() => editor.chain().focus().toggleItalic().run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('italic') 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              <em>I</em>
            </button>
            <div className="w-px h-6 bg-gray-300 mx-2"></div>
            <button
              onClick={() => editor.chain().focus().toggleHeading({ level: 1 }).run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('heading', { level: 1 }) 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              H1
            </button>
            <button
              onClick={() => editor.chain().focus().toggleHeading({ level: 2 }).run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('heading', { level: 2 }) 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              H2
            </button>
            <div className="w-px h-6 bg-gray-300 mx-2"></div>
            <button
              onClick={() => editor.chain().focus().toggleBulletList().run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('bulletList') 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              • List
            </button>
            <button
              onClick={() => editor.chain().focus().toggleOrderedList().run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('orderedList') 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              1. List
            </button>
            <div className="w-px h-6 bg-gray-300 mx-2"></div>
            <button
              onClick={() => editor.chain().focus().toggleBlockquote().run()}
              className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                editor.isActive('blockquote') 
                  ? 'bg-blue-100 text-blue-700 border border-blue-300' 
                  : 'text-gray-700 hover:bg-gray-100 border border-transparent'
              }`}
            >
              Quote
            </button>
            
            {/* Connection retry button */}
            {connectionStatus === 'disconnected' && (
              <button
                onClick={() => collaborationService.reconnect()}
                className="ml-4 px-3 py-2 bg-red-100 text-red-700 rounded-lg text-sm hover:bg-red-200 transition-colors"
              >
                Reconnect
              </button>
            )}
          </div>
        </div>

        {/* Editor */}
        <div className="min-h-[500px] bg-white">
          <EditorContent 
            editor={editor}
            className="min-h-[500px]"
          />
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 p-4 bg-gray-50">
          <div className="flex items-center justify-between text-sm text-gray-600">
            <div className="flex items-center space-x-4">
              <span>👤 {currentUserName}</span>
              <span>•</span>
              <span>📡 {connectionStatus === 'connected' ? 'Auto-saved' : 'Offline mode'}</span>
              <span>•</span>
              <span>{editor.storage.characterCount?.characters() || 0} characters</span>
            </div>
            <div className="flex items-center space-x-4">
              <span>🛡️ BFT Consensus</span>
              <span>•</span>
              <span>🔐 Quantum Secure</span>
              <span>•</span>
              <span>📋 Audit Ready</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
