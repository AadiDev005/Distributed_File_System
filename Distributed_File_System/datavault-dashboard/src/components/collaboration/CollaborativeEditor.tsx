"use client";

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Users, Wifi, WifiOff, Save, FileText } from 'lucide-react';

interface Operation {
  type: 'insert' | 'delete' | 'retain';
  position: number;
  content?: string;
  length?: number;
  author: string;
  timestamp: string;
  version: number;
  id: string;
}

interface CollaborativeEditorProps {
  documentId: string;
  userId: string;
  userName: string;
}

interface User {
  id: string;
  name: string;
  cursor?: {
    position: number;
    selection: { start: number; end: number };
  };
}

const CollaborativeEditor: React.FC<CollaborativeEditorProps> = ({
  documentId,
  userId,
  userName,
}) => {
  const [content, setContent] = useState('');
  const [version, setVersion] = useState(0);
  const [isConnected, setIsConnected] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [lastSaved, setLastSaved] = useState<Date | null>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const contentRef = useRef(content);
  const versionRef = useRef(version);

  // Update refs when state changes
  useEffect(() => {
    contentRef.current = content;
    versionRef.current = version;
  }, [content, version]);

  const connectWebSocket = useCallback(() => {
    const wsUrl = `ws://localhost:8080/ws/collaboration?session=${userId}`;
    
    try {
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setIsConnected(true);
        console.log('🔌 Connected to collaboration server');
        
        // Join document after connection
        joinDocument();
      };

      wsRef.current.onclose = () => {
        setIsConnected(false);
        console.log('🔌 Disconnected from collaboration server');
        
        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (!isConnected) {
            connectWebSocket();
          }
        }, 3000);
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          handleWebSocketMessage(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      };

    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
      setIsConnected(false);
    }
  }, [userId, isConnected]);

  const joinDocument = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'join-document',
        payload: {
          documentId,
          userId,
          userName,
        },
      };
      
      wsRef.current.send(JSON.stringify(message));
      
      // Fetch document content
      setTimeout(() => {
        fetchDocument();
      }, 100);
    }
  };

  const fetchDocument = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'fetch-document',
        payload: {
          documentId,
        },
      };
      
      wsRef.current.send(JSON.stringify(message));
    }
  };

  const handleWebSocketMessage = (message: any) => {
    switch (message.type) {
      case 'fetch-document-response':
        if (message.payload.success && message.payload.document) {
          const doc = message.payload.document;
          
          // Parse JSON content if it's structured
          let docContent = doc.content;
          try {
            const parsed = JSON.parse(doc.content);
            if (parsed.type === 'doc' && parsed.content) {
              docContent = extractTextFromDoc(parsed);
            }
          } catch {
            // Use content as-is if not JSON
          }
          
          setContent(docContent);
          setVersion(doc.version);
        }
        break;

      case 'operation-broadcast':
        if (message.payload && message.payload.authorId !== userId) {
          applyRemoteOperation(message.payload.operation);
        }
        break;

      case 'cursor-update':
        updateUserCursor(message.payload);
        break;

      default:
        console.log('Unknown message type:', message.type);
    }
  };

  const extractTextFromDoc = (docJson: any): string => {
    let text = '';
    if (docJson.content && Array.isArray(docJson.content)) {
      docJson.content.forEach((block: any) => {
        if (block.content && Array.isArray(block.content)) {
          block.content.forEach((inline: any) => {
            if (inline.text) {
              text += inline.text;
            }
          });
        }
        text += '\n';
      });
    }
    return text.trim();
  };

  const applyRemoteOperation = (operation: Operation) => {
    setContent(prevContent => {
      let newContent = prevContent;
      
      switch (operation.type) {
        case 'insert':
          if (operation.position <= newContent.length) {
            newContent = newContent.slice(0, operation.position) + 
                        (operation.content || '') + 
                        newContent.slice(operation.position);
          }
          break;
          
        case 'delete':
          if (operation.position < newContent.length) {
            const end = Math.min(operation.position + (operation.length || 0), newContent.length);
            newContent = newContent.slice(0, operation.position) + newContent.slice(end);
          }
          break;
      }
      
      return newContent;
    });
    
    setVersion(operation.version);
  };

  const updateUserCursor = (cursorData: any) => {
    setUsers(prevUsers => {
      const updatedUsers = prevUsers.filter(u => u.id !== cursorData.userId);
      updatedUsers.push({
        id: cursorData.userId,
        name: cursorData.userName,
        cursor: {
          position: cursorData.position,
          selection: cursorData.selection,
        },
      });
      return updatedUsers;
    });
  };

  const handleTextChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    const newContent = event.target.value;
    const cursorPosition = event.target.selectionStart;
    
    // Calculate operation
    let operation: Operation | null = null;
    
    if (newContent.length > content.length) {
      // Insert operation
      const insertedText = newContent.slice(content.length);
      operation = {
        type: 'insert',
        position: cursorPosition - insertedText.length,
        content: insertedText,
        author: userId,
        timestamp: new Date().toISOString(),
        version: version,
        id: `op_${Date.now()}_${userId}`,
      };
    } else if (newContent.length < content.length) {
      // Delete operation
      const deletedLength = content.length - newContent.length;
      operation = {
        type: 'delete',
        position: cursorPosition,
        length: deletedLength,
        author: userId,
        timestamp: new Date().toISOString(),
        version: version,
        id: `op_${Date.now()}_${userId}`,
      };
    }

    // Update local content immediately
    setContent(newContent);

    // Send operation to server
    if (operation && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'document-change',
        payload: {
          documentId,
          operation,
          clientId: userId,
        },
      };
      
      wsRef.current.send(JSON.stringify(message));
    }

    // Send cursor position
    sendCursorPosition(cursorPosition);
  };

  const sendCursorPosition = (position: number) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const message = {
        type: 'cursor-position',
        payload: {
          documentId,
          position,
          selection: {
            start: textareaRef.current?.selectionStart || position,
            end: textareaRef.current?.selectionEnd || position,
          },
        },
      };
      
      wsRef.current.send(JSON.stringify(message));
    }
  };

  const handleSave = () => {
    setLastSaved(new Date());
    // Additional save logic if needed
  };

  // Connect on mount
  useEffect(() => {
    connectWebSocket();
    
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connectWebSocket]);

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Document: {documentId}
          </CardTitle>
          
          <div className="flex items-center gap-2">
            {users.length > 0 && (
              <Badge variant="secondary" className="flex items-center gap-1">
                <Users className="h-3 w-3" />
                {users.length + 1} active
              </Badge>
            )}
            
            <Badge variant={isConnected ? "default" : "destructive"} className="flex items-center gap-1">
              {isConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
              {isConnected ? 'Connected' : 'Disconnected'}
            </Badge>
            
            <Button onClick={handleSave} size="sm" variant="outline">
              <Save className="h-4 w-4 mr-1" />
              Save
            </Button>
          </div>
        </div>
        
        {lastSaved && (
          <p className="text-sm text-muted-foreground">
            Last saved: {lastSaved.toLocaleTimeString()}
          </p>
        )}
      </CardHeader>
      
      <CardContent className="p-0">
        <textarea
          ref={textareaRef}
          value={content}
          onChange={handleTextChange}
          onSelect={() => {
            if (textareaRef.current) {
              sendCursorPosition(textareaRef.current.selectionStart);
            }
          }}
          className="w-full h-96 p-4 font-mono text-sm resize-none border-0 focus:outline-none focus:ring-0"
          placeholder="Start typing to collaborate in real-time..."
          disabled={!isConnected}
        />
        
        <div className="px-4 py-2 bg-muted/50 border-t text-xs text-muted-foreground flex justify-between">
          <span>Version: {version} | User: {userName}</span>
          <span>{content.length} characters</span>
        </div>
      </CardContent>
    </Card>
  );
};

export default CollaborativeEditor;
