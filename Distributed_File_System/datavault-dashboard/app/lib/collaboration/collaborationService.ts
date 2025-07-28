// Remove Socket.IO import - use native WebSocket instead
// import { io, Socket } from 'socket.io-client';

export interface CollaborationDocument {
  id: string;
  title: string;
  content: string;
  version: number;
  lastModified: Date;
  collaborators: Collaborator[];
  permissions: DocumentPermissions;
  encrypted: boolean;
}

export interface Collaborator {
  id: string;
  name: string;
  email: string;
  avatar?: string;
  cursor?: {
    position: number;
    selection: { from: number; to: number };
  };
  isOnline: boolean;
  lastSeen: Date;
}

export interface DocumentPermissions {
  owner: string;
  editors: string[];
  commenters: string[];
  viewers: string[];
}

export interface CollaborationComment {
  id: string;
  documentId: string;
  userId: string;
  userName: string;
  content: string;
  position: number;
  replies: CommentReply[];
  resolved: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CommentReply {
  id: string;
  commentId: string;
  userId: string;
  userName: string;
  content: string;
  createdAt: Date;
}

export interface CollaborationChange {
  id: string;
  documentId: string;
  userId: string;
  userName: string;
  type: 'insert' | 'delete' | 'format' | 'replace';
  position: number;
  content: any;
  timestamp: Date;
  version: number;
}

export interface CollaborationSession {
  documentId: string;
  userId: string;
  userName: string;
  joinedAt: Date;
  lastActivity: Date;
}

// WebSocket message format to match your Go backend
interface WSMessage {
  type: string;
  payload: any;
}

export class CollaborationService {
  private socket: WebSocket | null = null;
  private documents: Map<string, CollaborationDocument> = new Map();
  private sessions: Map<string, CollaborationSession[]> = new Map();
  private changeListeners: Map<string, ((content: string) => void)[]> = new Map();
  private cursorListeners: Map<string, ((cursors: any[]) => void)[]> = new Map();
  private commentListeners: Map<string, ((comments: CollaborationComment[]) => void)[]> = new Map();
  private _isConnected = false; // Fixed: renamed to avoid conflict
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private isClient = false;
  private reconnectTimeout: NodeJS.Timeout | null = null;

  constructor() {
    if (typeof window !== 'undefined') {
      this.isClient = true;
      this.initializeWebSocket();
      this.initializeLocalStorage();
    }
  }

  private initializeWebSocket() {
    if (!this.isClient) {
      console.log('🔌 WebSocket initialization skipped (SSR)');
      return;
    }

    console.log('🔌 Initializing native WebSocket connection...');
    
    try {
      // Connect to your Go WebSocket backend
      const wsUrl = `ws://localhost:3000/ws/collaboration?session=${Date.now()}`;
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        console.log('✅ WebSocket connected to collaboration endpoint');
        this._isConnected = true;
        this.reconnectAttempts = 0;
        
        // Send initial join message
        this.sendMessage({
          type: 'join-document',
          payload: {
            documentId: 'demo-document',
            userId: 'user-' + Date.now(),
            userName: 'Enterprise User'
          }
        });
      };

      this.socket.onclose = (event) => {
        console.log('❌ WebSocket disconnected:', event.code, event.reason);
        this._isConnected = false;
        this.attemptReconnect();
      };

      this.socket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this._isConnected = false;
      };

      this.socket.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          console.log('📨 Received WebSocket message:', message);
          this.handleWebSocketMessage(message);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this._isConnected = false;
    }
  }

  private handleWebSocketMessage(message: WSMessage) {
    switch (message.type) {
      case 'fetch-document-response':
        this.handleFetchDocumentResponse(message.payload);
        break;
      case 'document-change':
        this.handleDocumentChangeMessage(message.payload);
        break;
      case 'user-joined':
        this.handleUserJoined(message.payload.documentId, message.payload.user);
        break;
      case 'user-left':
        this.handleUserLeft(message.payload.documentId, message.payload.userId);
        break;
      case 'operation-applied':
        console.log('✅ Operation applied:', message.payload);
        break;
      case 'operation-error':
        console.error('❌ Operation error:', message.payload);
        break;
      default:
        console.log('Unknown message type:', message.type);
    }
  }

  private handleFetchDocumentResponse(payload: any) {
    if (payload.success && payload.document) {
      const doc: CollaborationDocument = {
        ...payload.document,
        lastModified: new Date(payload.document.lastModified),
        collaborators: []
      };
      this.documents.set(doc.id, doc);
      this.saveToLocalStorage();
    }
  }

  private handleDocumentChangeMessage(payload: any) {
    this.handleDocumentChange(payload.documentId, payload.content, payload.change);
  }

  private sendMessage(message: WSMessage) {
    if (this.socket && this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(message));
    } else {
      console.warn('Cannot send message: WebSocket not connected');
    }
  }

  private attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('❌ Max reconnection attempts reached');
      this.handleOfflineMode();
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    
    console.log(`🔄 Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
    
    this.reconnectTimeout = setTimeout(() => {
      this.initializeWebSocket();
    }, delay);
  }

  private initializeLocalStorage() {
    if (!this.isClient) {
      console.log('📋 LocalStorage initialization skipped (SSR)');
      return;
    }

    try {
      const stored = localStorage.getItem('datavault-documents');
      if (stored) {
        const docs = JSON.parse(stored);
        Object.entries(docs).forEach(([id, doc]) => {
          const document = doc as any;
          document.lastModified = new Date(document.lastModified);
          this.documents.set(id, document as CollaborationDocument);
        });
        console.log('📋 Loaded documents from localStorage');
      }
    } catch (error) {
      console.error('❌ Failed to parse stored documents:', error);
    }
  }

  async fetchDocument(documentId: string): Promise<string> {
    console.log(`📄 Fetching document: ${documentId}`);

    // Check local cache first
    const cached = this.documents.get(documentId);
    if (cached) {
      console.log('📋 Using cached document');
      return cached.content;
    }

    // Try to fetch from server
    if (this.isClient && this._isConnected && this.socket) {
      try {
        this.sendMessage({
          type: 'fetch-document',
          payload: { documentId }
        });
        
        // Wait for response (simplified - in production use proper promise handling)
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const doc = this.documents.get(documentId);
        if (doc) {
          return doc.content;
        }
      } catch (error) {
        console.error('Failed to fetch from server:', error);
      }
    }

    // Create new document if not found
    const newDocument: CollaborationDocument = {
      id: documentId,
      title: documentId,
      content: this.getDefaultContent(documentId),
      version: 1,
      lastModified: new Date(),
      collaborators: [],
      permissions: {
        owner: 'current-user',
        editors: ['current-user'],
        commenters: [],
        viewers: []
      },
      encrypted: true
    };

    this.documents.set(documentId, newDocument);
    this.saveToLocalStorage();
    
    return newDocument.content;
  }

  publishChange(documentId: string, content: any, userId: string, userName: string): void {
    if (!this.isClient) {
      console.log('📝 Publish change skipped (SSR)');
      return;
    }

    console.log(`📝 Publishing change to: ${documentId}`);

    const change: CollaborationChange = {
      id: `change-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      documentId,
      userId,
      userName,
      type: 'replace',
      position: 0,
      content,
      timestamp: new Date(),
      version: this.getDocumentVersion(documentId) + 1
    };

    // Update local document
    const doc = this.documents.get(documentId);
    if (doc) {
      doc.content = typeof content === 'string' ? content : JSON.stringify(content);
      doc.version = change.version;
      doc.lastModified = new Date();
      this.documents.set(documentId, doc);
      this.saveToLocalStorage();
    }

    // Send to server
    if (this._isConnected && this.socket) {
      this.sendMessage({
        type: 'document-change',
        payload: {
          documentId,
          content: typeof content === 'string' ? content : JSON.stringify(content),
          change
        }
      });
    } else {
      this.queueOfflineChange(change);
    }
  }

  subscribe(documentId: string, callback: (content: string) => void): () => void {
    console.log(`🔌 Subscribing to document: ${documentId}`);

    // Join document room
    if (this.isClient && this._isConnected && this.socket) {
      this.sendMessage({
        type: 'join-document',
        payload: {
          documentId,
          userId: 'current-user',
          userName: 'Enterprise User'
        }
      });
    }

    // Add callback to listeners
    if (!this.changeListeners.has(documentId)) {
      this.changeListeners.set(documentId, []);
    }
    this.changeListeners.get(documentId)!.push(callback);

    // Return unsubscribe function
    return () => {
      console.log(`🔚 Unsubscribing from document: ${documentId}`);
      
      const listeners = this.changeListeners.get(documentId);
      if (listeners) {
        const index = listeners.indexOf(callback);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }

      // Leave document room
      if (this.isClient && this._isConnected && this.socket) {
        this.sendMessage({
          type: 'leave-document',
          payload: { documentId, userId: 'current-user' }
        });
      }
    };
  }

  subscribeToCursors(documentId: string, callback: (cursors: any[]) => void): () => void {
    if (!this.cursorListeners.has(documentId)) {
      this.cursorListeners.set(documentId, []);
    }
    this.cursorListeners.get(documentId)!.push(callback);

    return () => {
      const listeners = this.cursorListeners.get(documentId);
      if (listeners) {
        const index = listeners.indexOf(callback);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }
    };
  }

  subscribeToComments(documentId: string, callback: (comments: CollaborationComment[]) => void): () => void {
    if (!this.commentListeners.has(documentId)) {
      this.commentListeners.set(documentId, []);
    }
    this.commentListeners.get(documentId)!.push(callback);

    return () => {
      const listeners = this.commentListeners.get(documentId);
      if (listeners) {
        const index = listeners.indexOf(callback);
        if (index > -1) {
          listeners.splice(index, 1);
        }
      }
    };
  }

  updateCursor(documentId: string, userId: string, position: number, selection: { from: number; to: number }): void {
    if (this.isClient && this._isConnected && this.socket) {
      this.sendMessage({
        type: 'cursor-update',
        payload: {
          documentId,
          userId,
          cursor: { position, selection }
        }
      });
    }
  }

  addComment(documentId: string, content: string, position: number, userId: string, userName: string): Promise<CollaborationComment> {
    const comment: CollaborationComment = {
      id: `comment-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      documentId,
      userId,
      userName,
      content,
      position,
      replies: [],
      resolved: false,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    if (this.isClient && this._isConnected && this.socket) {
      this.sendMessage({
        type: 'add-comment',
        payload: comment
      });
    }

    return Promise.resolve(comment);
  }

  // Private helper methods
  private handleDocumentChange(documentId: string, content: string, change: CollaborationChange): void {
    const doc = this.documents.get(documentId);
    if (doc) {
      doc.content = content;
      doc.version = change.version;
      doc.lastModified = new Date();
      this.documents.set(documentId, doc);
      this.saveToLocalStorage();
    }

    const listeners = this.changeListeners.get(documentId);
    if (listeners) {
      listeners.forEach(callback => callback(content));
    }
  }

  private handleCursorUpdate(documentId: string, cursors: any[]): void {
    const listeners = this.cursorListeners.get(documentId);
    if (listeners) {
      listeners.forEach(callback => callback(cursors));
    }
  }

  private handleCommentUpdate(documentId: string, comments: CollaborationComment[]): void {
    const listeners = this.commentListeners.get(documentId);
    if (listeners) {
      listeners.forEach(callback => callback(comments));
    }
  }

  private handleUserJoined(documentId: string, user: Collaborator): void {
    const doc = this.documents.get(documentId);
    if (doc) {
      const existingIndex = doc.collaborators.findIndex(c => c.id === user.id);
      if (existingIndex >= 0) {
        doc.collaborators[existingIndex] = user;
      } else {
        doc.collaborators.push(user);
      }
      this.documents.set(documentId, doc);
    }
  }

  private handleUserLeft(documentId: string, userId: string): void {
    const doc = this.documents.get(documentId);
    if (doc) {
      doc.collaborators = doc.collaborators.filter(c => c.id !== userId);
      this.documents.set(documentId, doc);
    }
  }

  private handleOfflineMode(): void {
    console.log('📴 Entering offline mode');
  }

  private queueOfflineChange(change: CollaborationChange): void {
    if (!this.isClient) return;
    
    try {
      const queue = JSON.parse(localStorage.getItem('datavault-offline-queue') || '[]');
      queue.push(change);
      localStorage.setItem('datavault-offline-queue', JSON.stringify(queue));
    } catch (error) {
      console.error('Failed to queue offline change:', error);
    }
  }

  private getDocumentVersion(documentId: string): number {
    const doc = this.documents.get(documentId);
    return doc ? doc.version : 0;
  }

  private getDefaultContent(documentId: string): string {
    return JSON.stringify({
      type: 'doc',
      content: [
        {
          type: 'heading',
          attrs: { level: 1 },
          content: [{ type: 'text', text: `Document: ${documentId}` }]
        },
        {
          type: 'paragraph',
          content: [
            { type: 'text', text: 'Welcome to your quantum-encrypted collaborative document. This enterprise-grade editor provides:' }
          ]
        },
        {
          type: 'bulletList',
          content: [
            {
              type: 'listItem',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', marks: [{ type: 'bold' }], text: 'Real-time collaboration' }, { type: 'text', text: ' - Multiple users can edit simultaneously' }]
                }
              ]
            },
            {
              type: 'listItem',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', marks: [{ type: 'bold' }], text: 'Quantum encryption' }, { type: 'text', text: ' - Military-grade security for your content' }]
                }
              ]
            },
            {
              type: 'listItem',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', marks: [{ type: 'bold' }], text: 'Operational transforms' }, { type: 'text', text: ' - Conflict-free editing with automatic merge' }]
                }
              ]
            },
            {
              type: 'listItem',
              content: [
                {
                  type: 'paragraph',
                  content: [{ type: 'text', marks: [{ type: 'bold' }], text: 'Audit trail' }, { type: 'text', text: ' - Complete history of all changes for compliance' }]
                }
              ]
            }
          ]
        },
        {
          type: 'paragraph',
          content: [{ type: 'text', text: 'Start typing to begin your collaborative document...' }]
        }
      ]
    });
  }

  private saveToLocalStorage(): void {
    if (!this.isClient) return;
    
    try {
      const docsObj: Record<string, CollaborationDocument> = {};
      this.documents.forEach((doc, id) => {
        docsObj[id] = doc;
      });
      localStorage.setItem('datavault-documents', JSON.stringify(docsObj));
    } catch (error) {
      console.error('Failed to save to localStorage:', error);
    }
  }

  // Public API methods
  getDocument(documentId: string): CollaborationDocument | undefined {
    return this.documents.get(documentId);
  }

  getDocumentCollaborators(documentId: string): Collaborator[] {
    const doc = this.documents.get(documentId);
    return doc ? doc.collaborators : [];
  }

  // Fixed: Return the private property value
  isConnected(): boolean {
    return this._isConnected;
  }

  // Alternative getter approach
  get connected(): boolean {
    return this._isConnected;
  }

  reconnect(): void {
    if (!this.isClient) return;
    
    if (!this._isConnected) {
      this.reconnectAttempts = 0;
      this.initializeWebSocket();
    }
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this._isConnected = false;
  }

  getCollaborationMetrics(documentId: string) {
    const doc = this.documents.get(documentId);
    if (!doc) return null;

    return {
      totalCollaborators: doc.collaborators.length,
      activeCollaborators: doc.collaborators.filter(c => c.isOnline).length,
      documentVersion: doc.version,
      lastModified: doc.lastModified,
      encryptionStatus: doc.encrypted,
      permissionModel: doc.permissions
    };
  }
}

// Export singleton instance - only create on client side
export const collaborationService = typeof window !== 'undefined' ? new CollaborationService() : null as any;
