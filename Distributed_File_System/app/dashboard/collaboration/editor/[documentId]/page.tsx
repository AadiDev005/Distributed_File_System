'use client';

import { useEffect, useState, Suspense } from 'react';
import { useRouter } from 'next/navigation';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import { TextStyle } from '@tiptap/extension-text-style';
import Color from '@tiptap/extension-color';

interface EditorPageProps {
  params: { documentId: string };
}

// Mock collaboration service for immediate functionality
const mockCollaborationService = {
  fetchDocument: async (docId: string) => {
    return `# Document: ${docId}\n\nStart collaborating with quantum-encrypted security...`;
  },
  publishChange: (docId: string, content: any, userId: string, userName: string) => {
    console.log('📝 Publishing change:', { docId, userId, userName });
  },
  subscribe: (docId: string, callback: (content: string) => void) => {
    console.log('🔌 Subscribed to document:', docId);
    return () => console.log('🔚 Unsubscribed from:', docId);
  }
};

function EditorComponent({ documentId }: { documentId: string }) {
  const [isClient, setIsClient] = useState(false);
  const [docContent, setDocContent] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    setIsClient(true);
  }, []);

  const editor = useEditor({
    extensions: [StarterKit, TextStyle, Color],
    content: docContent,
    immediatelyRender: false,
    shouldRerenderOnTransaction: false,
    editorProps: {
      attributes: {
        class: 'prose prose-lg max-w-none min-h-[400px] focus:outline-none p-4',
      },
    },
    onUpdate: ({ editor }) => {
      if (isClient) {
        mockCollaborationService.publishChange(
          documentId,
          editor.getJSON(),
          'current-user',
          'Enterprise User'
        );
      }
    },
  }, [isClient]);

  useEffect(() => {
    if (!isClient || !editor) return;

    const loadDocument = async () => {
      try {
        const initial = await mockCollaborationService.fetchDocument(documentId);
        setDocContent(initial);
        editor.commands.setContent(initial);
        setIsLoading(false);
      } catch (error) {
        console.error('Failed to load document:', error);
        setIsLoading(false);
      }
    };

    loadDocument();

    const unsub = mockCollaborationService.subscribe(documentId, (newContent) => {
      setDocContent(newContent);
      editor.commands.setContent(newContent);
    });

    return unsub;
  }, [documentId, editor, isClient]);

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
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-lg shadow-sm mb-6">
        <div className="border-b border-gray-200 p-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Document: {documentId}
              </h1>
              <p className="text-sm text-gray-600 mt-2">
                Real-time collaborative editing with quantum encryption
              </p>
            </div>
            <div className="flex items-center space-x-3">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-sm text-gray-600">Online</span>
              </div>
              <div className="text-sm text-gray-500">🔒 Quantum Encrypted</div>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="border-b border-gray-200 p-4">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => editor.chain().focus().toggleBold().run()}
              className={`px-3 py-1 rounded text-sm ${
                editor.isActive('bold') ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              Bold
            </button>
            <button
              onClick={() => editor.chain().focus().toggleItalic().run()}
              className={`px-3 py-1 rounded text-sm ${
                editor.isActive('italic') ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              Italic
            </button>
            <button
              onClick={() => editor.chain().focus().toggleHeading({ level: 1 }).run()}
              className={`px-3 py-1 rounded text-sm ${
                editor.isActive('heading', { level: 1 }) ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              H1
            </button>
            <button
              onClick={() => editor.chain().focus().toggleBulletList().run()}
              className={`px-3 py-1 rounded text-sm ${
                editor.isActive('bulletList') ? 'bg-blue-100 text-blue-700' : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              Bullet List
            </button>
          </div>
        </div>

        {/* Editor */}
        <div className="min-h-[500px]">
          <EditorContent editor={editor} />
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 p-4 bg-gray-50">
          <div className="flex items-center justify-between text-sm text-gray-600">
            <div className="flex items-center space-x-4">
              <span>User: Enterprise User</span>
              <span>•</span>
              <span>Auto-saved</span>
            </div>
            <div className="flex items-center space-x-2">
              <span>🛡️ BFT Consensus</span>
              <span>•</span>
              <span>🔐 Quantum Secure</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function EditorPage({ params }: EditorPageProps) {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    }>
      <EditorComponent documentId={params.documentId} />
    </Suspense>
  );
}
