export interface CollaborationDocument {
    id: string;
    title: string;
    content: string;
    type: 'text' | 'markdown' | 'code';
    version: number;
    lastModified: Date;
    created: Date;
    collaborators: Collaborator[];
    permissions: DocumentPermissions;
    encrypted: boolean;
    owner: string;
    securityMode: 'simple' | 'enterprise';
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
    color: string;
  }
  
  export interface DocumentPermissions {
    owner: string;
    editors: string[];
    commenters: string[];
    viewers: string[];
  }
  
  export interface CollaborationChange {
    id: string;
    documentId: string;
    userId: string;
    userName: string;
    type: 'insert' | 'delete' | 'format' | 'replace' | 'cursor';
    position: number;
    content: any;
    length?: number;
    timestamp: Date;
    version: number;
  }
  
  export interface DocumentCreateData {
    title: string;
    type: 'text' | 'markdown' | 'code';
    content?: string;
    permissions?: string;
  }
  
  export interface DocumentUpdateData {
    id: string;
    content: string;
  }
  