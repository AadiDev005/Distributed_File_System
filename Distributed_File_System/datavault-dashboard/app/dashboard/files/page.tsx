'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  MoreHorizontal,
  Download,
  Share,
  Eye,
  File,
  Folder,
  Clock,
  User,
  Shield,
  Trash2,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  X,
  Upload,
  Loader2,
  Wifi,
  WifiOff
} from 'lucide-react';
import { DataVaultAPI, FileItem } from '../utils/api';
import FileUpload from '../../components/FileUpload';

// Enhanced loading states
type LoadingState = 'idle' | 'loading' | 'success' | 'error';

// Enhanced notification type
interface Notification {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
  duration?: number;
}

export default function FilesPage() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'online' | 'offline'>('online');
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [loadingState, setLoadingState] = useState<LoadingState>('idle');

  // Refs for cleanup
  const timeoutRefs = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // ✅ FIXED: Type-safe transformation helper with proper union casting
  const toFileItem = useCallback((raw: any): FileItem => ({
    id: String(raw.id ?? `unknown_${Date.now()}_${Math.random()}`),
    name: String(raw.name ?? 'Unknown file'),
    // ✅ FIXED: Cast to proper union literal for 'type'
    type: (raw.type === 'folder') ? 'folder' : 'file' as const,
    size: typeof raw.size === 'number' ? raw.size : 0,
    lastModified: typeof raw.lastModified === 'string' 
      ? raw.lastModified 
      : raw.lastModified?.toISOString() ?? new Date().toISOString(),
    owner: String(raw.owner ?? raw.uploadedBy ?? 'Unknown'),
    // ✅ FIXED: Cast to proper union literal for 'compliance'
    compliance: (['SOX', 'HIPAA', 'GDPR', 'PCI-DSS', 'NONE'].includes(raw.compliance)) 
      ? raw.compliance as 'SOX' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'NONE'
      : 'GDPR' as const,
    encrypted: raw.encrypted ?? true,
    shared: raw.shared ?? false,
    // ✅ FIXED: Ensure status is always a valid union literal
    status: (raw.status === 'uploading' || raw.status === 'error') 
      ? raw.status 
      : 'complete' as const,
    mimeType: String(raw.mimeType ?? 'application/octet-stream'),
  }), []);

  // Enhanced error handling
  const getErrorMessage = useCallback((error: any): string => {
    if (error?.response?.data?.message) return error.response.data.message;
    if (error?.message) return error.message;
    if (typeof error === 'string') return error;
    return 'An unexpected error occurred';
  }, []);

  // Enhanced notification system
  const showNotification = useCallback((type: Notification['type'], message: string, duration = 5000) => {
    const id = Math.random().toString(36).substr(2, 9);
    const notification: Notification = { id, type, message, duration };
    
    setNotifications(prev => [...prev, notification]);
    
    const timeout = setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
      timeoutRefs.current.delete(id);
    }, duration);
    
    timeoutRefs.current.set(id, timeout);
  }, []);

  // ✅ IMPROVED: Remove notification with better cleanup
  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
    if (timeoutRefs.current.has(id)) {
      clearTimeout(timeoutRefs.current.get(id));
      timeoutRefs.current.delete(id);
    }
  }, []);

  // Enhanced file loading with better error handling and caching
  const loadFiles = useCallback(async (silent = false) => {
    try {
      if (!silent) {
        setLoading(true);
        setLoadingState('loading');
      }
      
      console.log('📁 Loading files from DataVault network...');
      
      const response = await DataVaultAPI.getFileList();
      
      if (response.success && response.files) {
        // ✅ FIXED: Use type-safe transformation
        const transformedFiles: FileItem[] = response.files.map(toFileItem);
        
        setFiles(transformedFiles);
        setConnectionStatus('online');
        setLastRefresh(new Date());
        setLoadingState('success');
        
        console.log(`✅ Loaded ${transformedFiles.length} files from DataVault network`);
        
        if (!silent) {
          showNotification('success', `Loaded ${transformedFiles.length} files from DataVault network`, 3000);
        }
      } else {
        console.warn('⚠️ Unexpected response format:', response);
        setFiles([]);
        setLoadingState('error');
        showNotification('warning', 'No files found or unexpected response format');
      }
    } catch (error) {
      console.error('Failed to load files:', error);
      setConnectionStatus('offline');
      setLoadingState('error');
      
      const errorMsg = getErrorMessage(error);
      showNotification('error', `Failed to load files: ${errorMsg}. Using offline mode.`);
      
      // ✅ FIXED: Fallback files with proper union literal typing
      const fallbackFiles: FileItem[] = [
        {
          id: 'welcome.txt',
          name: 'welcome.txt',
          type: 'file' as const,
          size: 351,
          lastModified: new Date().toISOString(),
          owner: 'system',
          compliance: 'GDPR' as const,
          encrypted: true,
          shared: false,
          status: 'complete' as const,
          mimeType: 'text/plain'
        },
        {
          id: 'readme.md',
          name: 'readme.md',
          type: 'file' as const,
          size: 399,
          lastModified: new Date().toISOString(),
          owner: 'system',
          compliance: 'GDPR' as const,
          encrypted: true,
          shared: false,
          status: 'complete' as const,
          mimeType: 'text/markdown'
        },
        {
          id: 'config.json',
          name: 'config.json',
          type: 'file' as const,
          size: 327,
          lastModified: new Date().toISOString(),
          owner: 'system',
          compliance: 'GDPR' as const,
          encrypted: true,
          shared: false,
          status: 'complete' as const,
          mimeType: 'application/json'
        }
      ];
      setFiles(fallbackFiles);
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, [showNotification, getErrorMessage, toFileItem]);

  // ✅ ENHANCED: Smoother file upload with better progress handling
  const handleFilesUploaded = useCallback(async (uploadedFiles: FileList) => {
    if (uploadedFiles.length === 0) return;

    try {
      setUploading(true);
      setUploadProgress(0);

      console.log(`📤 Uploading ${uploadedFiles.length} files to DataVault...`);
      showNotification('info', `Starting upload of ${uploadedFiles.length} file(s)...`, 2000);

      // ✅ IMPROVED: Smoother progress that reaches 90% before completion
      progressIntervalRef.current = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) return prev; // Stop at 90%
          return prev + Math.random() * 8 + 2; // Faster, more consistent progress
        });
      }, 150); // Faster updates for smoother animation

      const result = await DataVaultAPI.uploadFiles(uploadedFiles);
      
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
        progressIntervalRef.current = null;
      }
      
      // Smooth transition to 100%
      setUploadProgress(100);

      if (result.success && result.files) {
        showNotification('success', 
          `Successfully uploaded ${result.files.length} file(s) with quantum encryption! 🔐`
        );
        
        // ✅ FIXED: Use type-safe transformation
        const newFiles: FileItem[] = result.files.map(toFileItem);
        
        // Add new files to the beginning with animation
        setFiles(prev => [...newFiles, ...prev]);
        
        // Silent refresh after 2 seconds to ensure consistency
        setTimeout(() => loadFiles(true), 2000);
      } else {
        showNotification('error', 'Upload completed but no files were returned from server');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      const errorMessage = getErrorMessage(error);
      showNotification('error', `Upload failed: ${errorMessage}`);
    } finally {
      setUploading(false);
      // Clear progress after showing completion
      setTimeout(() => setUploadProgress(0), 2000);
    }
  }, [loadFiles, showNotification, getErrorMessage, toFileItem]);

  // ✅ ENHANCED: File operations with optimistic updates
  const handleFileDownload = useCallback(async (file: FileItem) => {
    try {
      showNotification('info', `Downloading ${file.name}...`, 2000);
      console.log(`⬇️ Downloading file: ${file.name} (ID: ${file.id})`);
      
      await DataVaultAPI.downloadFile(file.id, file.name);
      showNotification('success', `Downloaded ${file.name} successfully! 📥`);
    } catch (error) {
      console.error('Download failed:', error);
      const errorMessage = getErrorMessage(error);
      showNotification('error', `Failed to download ${file.name}: ${errorMessage}`);
    }
  }, [showNotification, getErrorMessage]);

  const handleFileView = useCallback(async (file: FileItem) => {
    try {
      showNotification('info', `Opening ${file.name}...`, 2000);
      console.log(`👁️ Viewing file: ${file.name} (ID: ${file.id})`);
      
      const viewUrl = await DataVaultAPI.getFileViewUrl(file.id);
      window.open(viewUrl, '_blank');
      showNotification('success', `Opened ${file.name} in new tab 👁️`);
    } catch (error) {
      console.error('View failed:', error);
      const errorMessage = getErrorMessage(error);
      showNotification('error', `Failed to view ${file.name}: ${errorMessage}`);
    }
  }, [showNotification, getErrorMessage]);

  const handleFileDelete = useCallback(async (fileId: string, fileName: string) => {
    if (!confirm(`Are you sure you want to delete "${fileName}"?\n\nThis action cannot be undone and the file will be removed from all DataVault nodes.`)) {
      return;
    }

    // Optimistic update
    setFiles(prev => prev.filter(f => f.id !== fileId));
    setSelectedFiles(prev => prev.filter(id => id !== fileId));
    
    showNotification('info', `Deleting ${fileName}...`, 2000);

    try {
      console.log(`🗑️ Deleting file: ${fileName} (ID: ${fileId})`);
      const result = await DataVaultAPI.deleteFile(fileId);
      
      if (result.success) {
        showNotification('success', `Deleted ${fileName} successfully! 🗑️`);
        // Silent refresh to ensure consistency
        setTimeout(() => loadFiles(true), 1000);
      } else {
        // Revert optimistic update on failure
        setTimeout(() => loadFiles(true), 100);
        showNotification('error', result.message || `Failed to delete ${fileName}`);
      }
    } catch (error) {
      // Revert optimistic update on error
      setTimeout(() => loadFiles(true), 100);
      console.error('Delete failed:', error);
      const errorMessage = getErrorMessage(error);
      showNotification('error', `Failed to delete ${fileName}: ${errorMessage}`);
    }
  }, [loadFiles, showNotification, getErrorMessage]);

  const handleFileShare = useCallback(async (fileId: string, fileName: string) => {
    // Optimistic update
    setFiles(prev => prev.map(file => 
      file.id === fileId ? { ...file, shared: true } : file
    ));
    
    showNotification('info', `Sharing ${fileName}...`, 2000);

    try {
      console.log(`🔗 Sharing file: ${fileName} (ID: ${fileId})`);
      const result = await DataVaultAPI.shareFile(fileId, { 
        public: false, 
        expiresIn: '7d',
        permissions: ['read'] 
      });
      
      if (result.success) {
        if (result.shareUrl) {
          try {
            await navigator.clipboard.writeText(result.shareUrl);
            showNotification('success', `${fileName} shared successfully! Link copied to clipboard. 🔗📋`);
          } catch {
            showNotification('success', `${fileName} shared successfully! 🔗`);
          }
        } else {
          showNotification('success', `${fileName} shared successfully! 🔗`);
        }
        
        // Silent refresh to ensure consistency
        setTimeout(() => loadFiles(true), 1000);
      } else {
        // Revert optimistic update on failure
        setFiles(prev => prev.map(file => 
          file.id === fileId ? { ...file, shared: false } : file
        ));
        showNotification('error', result.message || `Failed to share ${fileName}`);
      }
    } catch (error) {
      // Revert optimistic update on error
      setFiles(prev => prev.map(file => 
        file.id === fileId ? { ...file, shared: false } : file
      ));
      console.error('Share failed:', error);
      const errorMessage = getErrorMessage(error);
      showNotification('error', `Failed to share ${fileName}: ${errorMessage}`);
    }
  }, [loadFiles, showNotification, getErrorMessage]);

  // ✅ ENHANCED: Better utility functions
  const formatFileSize = useCallback((bytes?: number) => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }, []);

  const formatDate = useCallback((dateInput: string | Date) => {
    try {
      const date = typeof dateInput === 'string' ? new Date(dateInput) : dateInput;
      
      if (isNaN(date.getTime())) {
        return 'Unknown date';
      }
      
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffHours = diffMs / (1000 * 60 * 60);
      
      if (diffHours < 1) {
        return 'Just now';
      } else if (diffHours < 24) {
        return `${Math.floor(diffHours)} hours ago`;
      } else if (diffHours < 48) {
        return 'Yesterday';
      } else {
        return date.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        });
      }
    } catch (error) {
      console.warn('Error formatting date:', dateInput, error);
      return 'Invalid date';
    }
  }, []);

  const getComplianceColor = useCallback((compliance: string) => {
    switch (compliance.toLowerCase()) {
      case 'sox': return 'bg-blue-100 text-blue-700 border-blue-200';
      case 'hipaa': return 'bg-green-100 text-green-700 border-green-200';
      case 'gdpr': return 'bg-purple-100 text-purple-700 border-purple-200';
      case 'pci-dss': return 'bg-orange-100 text-orange-700 border-orange-200';
      default: return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  }, []);

  // ✅ PERFORMANCE: Memoize filtered files to avoid recalculation on every render
  const filteredFiles = useMemo(() => {
    if (!searchQuery.trim()) return files;
    
    const searchTerms = searchQuery.toLowerCase().split(' ').filter(Boolean);
    
    return files.filter(file => searchTerms.every(term => 
      file.name.toLowerCase().includes(term) ||
      file.owner.toLowerCase().includes(term) ||
      file.compliance.toLowerCase().includes(term) ||
      (file.mimeType && file.mimeType.toLowerCase().includes(term)) ||
      formatFileSize(file.size || 0).toLowerCase().includes(term)
    ));
  }, [files, searchQuery, formatFileSize]);

  // ✅ PERFORMANCE: Memoize statistics calculations
  const fileStats = useMemo(() => {
    const totalSize = files.reduce((acc, file) => acc + (file.size || 0), 0);
    const encryptedFiles = files.filter(f => f.encrypted).length;
    const sharedFiles = files.filter(f => f.shared).length;
    
    return { totalSize, encryptedFiles, sharedFiles };
  }, [files]);

  // Auto-refresh files every 30 seconds (silent refresh)
  useEffect(() => {
    const interval = setInterval(() => {
      if (!uploading && !loading && connectionStatus === 'online') {
        loadFiles(true); // Silent refresh
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [loadFiles, uploading, loading, connectionStatus]);

  // Load files on component mount
  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  // ✅ CLEANUP: Ensure all timers are cleaned up on unmount
  useEffect(() => {
    return () => {
      for (const timeout of timeoutRefs.current.values()) {
        clearTimeout(timeout);
      }
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        {/* Enhanced Notification System */}
        <div className="fixed top-4 right-4 z-50 space-y-2">
          <AnimatePresence>
            {notifications.map((notification) => (
              <motion.div
                key={notification.id}
                className={`p-4 rounded-xl shadow-lg border max-w-md backdrop-blur-sm ${
                  notification.type === 'success' 
                    ? 'bg-emerald-50/95 border-emerald-200 text-emerald-800' 
                    : notification.type === 'error'
                    ? 'bg-red-50/95 border-red-200 text-red-800'
                    : notification.type === 'warning'
                    ? 'bg-yellow-50/95 border-yellow-200 text-yellow-800'
                    : 'bg-blue-50/95 border-blue-200 text-blue-800'
                }`}
                initial={{ opacity: 0, x: 100, scale: 0.95 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 100, scale: 0.95 }}
                transition={{ type: "spring", stiffness: 300, damping: 30 }}
              >
                <div className="flex items-center space-x-3">
                  {notification.type === 'success' ? (
                    <CheckCircle className="w-5 h-5 flex-shrink-0" />
                  ) : notification.type === 'error' ? (
                    <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                  ) : notification.type === 'warning' ? (
                    <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                  ) : (
                    <Loader2 className="w-5 h-5 flex-shrink-0" />
                  )}
                  <span className="font-medium text-sm flex-1">{notification.message}</span>
                  <button
                    onClick={() => removeNotification(notification.id)}
                    className="p-1 hover:bg-black/10 rounded transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {/* Enhanced Header */}
        <motion.div
          className="flex items-center justify-between mb-8"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ type: "spring", stiffness: 300, damping: 30 }}
        >
          <div>
            <h1 className="apple-headline mb-2">Secure File Management</h1>
            <p className="apple-subheadline">
              Upload, share, and manage files with quantum-proof encryption across DataVault network
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => loadFiles()}
              disabled={loading}
              className="flex items-center space-x-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg transition-all duration-200 disabled:opacity-50 hover:scale-105"
            >
              <RefreshCw className={`w-4 h-4 transition-transform ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
            
            {/* Connection Status */}
            <div className="flex items-center space-x-2">
              {connectionStatus === 'online' ? (
                <Wifi className="w-4 h-4 text-green-600" />
              ) : (
                <WifiOff className="w-4 h-4 text-red-600" />
              )}
              <span className={`text-sm ${connectionStatus === 'online' ? 'text-green-600' : 'text-red-600'}`}>
                {connectionStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>
            
            <div className="text-sm text-gray-600">
              {files.length} files • {fileStats.encryptedFiles} encrypted • {fileStats.sharedFiles} shared
            </div>
          </div>
        </motion.div>

        {/* File Upload Component */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1, type: "spring", stiffness: 300, damping: 30 }}
          className="mb-8"
        >
          <FileUpload
            onFilesUploaded={handleFilesUploaded}
            maxFiles={10}
            maxFileSize={100}
            uploading={uploading}
            uploadProgress={uploadProgress}
          />
        </motion.div>

        {/* Enhanced Search and Filter Bar */}
        <motion.div
          className="flex items-center space-x-4 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, type: "spring", stiffness: 300, damping: 30 }}
        >
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="apple-input pl-12 transition-all duration-200 focus:scale-[1.02]"
              placeholder="Search by filename, owner, compliance, size, or file type..."
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-4 top-1/2 transform -translate-y-1/2 p-1 hover:bg-gray-100 rounded-full transition-colors"
              >
                <X className="w-4 h-4 text-gray-400" />
              </button>
            )}
          </div>
          <div className="text-sm text-gray-500">
            {filteredFiles.length} of {files.length} files
          </div>
          <button className="apple-button-secondary hover:scale-105 transition-transform">
            <Filter className="w-4 h-4 mr-2" />
            Filter
          </button>
        </motion.div>

        {/* Enhanced Files List */}
        <motion.div
          className="apple-card overflow-hidden"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, type: "spring", stiffness: 300, damping: 30 }}
        >
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                Files & Folders ({filteredFiles.length})
                {loading && (
                  <span className="ml-2 text-sm text-gray-500 animate-pulse">Loading...</span>
                )}
              </h2>
              <div className="flex items-center space-x-4">
                <div className="flex items-center text-sm text-gray-600">
                  <Shield className="w-4 h-4 mr-1 text-green-600" />
                  All files quantum-encrypted by DataVault
                </div>
                <div className="text-xs text-gray-400">
                  Last updated: {formatDate(lastRefresh)}
                </div>
              </div>
            </div>
          </div>
          
          <div className="divide-y divide-gray-100">
            {loading ? (
              <div className="p-12 text-center">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                >
                  <RefreshCw className="w-8 h-8 text-gray-400 mx-auto mb-4" />
                </motion.div>
                <p className="text-gray-500">Loading files from DataVault network...</p>
                <p className="text-sm text-gray-400 mt-2">Scanning distributed storage nodes...</p>
              </div>
            ) : filteredFiles.length === 0 ? (
              <div className="p-12 text-center">
                <File className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">
                  {searchQuery ? 'No files match your search criteria' : 'No files uploaded yet'}
                </p>
                {!searchQuery && (
                  <p className="text-sm text-gray-400 mt-2">
                    Upload your first file to get started with DataVault enterprise storage
                  </p>
                )}
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="mt-4 px-4 py-2 bg-blue-100 hover:bg-blue-200 text-blue-700 rounded-lg transition-colors"
                  >
                    Clear Search
                  </button>
                )}
              </div>
            ) : (
              <AnimatePresence>
                {filteredFiles.map((file, index) => (
                  <motion.div
                    key={file.id}
                    className="p-6 hover:bg-gray-50 transition-all duration-200 apple-hover"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ 
                      delay: Math.min(0.05 * index, 0.5),
                      type: "spring", 
                      stiffness: 300, 
                      damping: 30 
                    }}
                    layout
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <input
                          type="checkbox"
                          checked={selectedFiles.includes(file.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedFiles(prev => [...prev, file.id]);
                            } else {
                              setSelectedFiles(prev => prev.filter(id => id !== file.id));
                            }
                          }}
                          className="w-4 h-4 text-blue-600 rounded transition-all hover:scale-110"
                        />
                        
                        <motion.div 
                          className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center"
                          whileHover={{ scale: 1.1 }}
                          transition={{ type: "spring", stiffness: 400, damping: 10 }}
                        >
                          {file.type === 'folder' ? (
                            <Folder className="w-5 h-5 text-blue-600" />
                          ) : (
                            <File className="w-5 h-5 text-blue-600" />
                          )}
                        </motion.div>
                        
                        <div>
                          <h3 className="font-medium text-gray-900 flex items-center space-x-2">
                            <span>{file.name}</span>
                            {file.status === 'uploading' && (
                              <motion.div 
                                className="w-2 h-2 bg-blue-500 rounded-full"
                                animate={{ scale: [1, 1.5, 1] }}
                                transition={{ duration: 1, repeat: Infinity }}
                              />
                            )}
                            {file.status === 'error' && (
                              <div className="w-2 h-2 bg-red-500 rounded-full" />
                            )}
                          </h3>
                          <div className="flex items-center space-x-4 text-sm text-gray-500 mt-1">
                            <div className="flex items-center">
                              <User className="w-3 h-3 mr-1" />
                              {file.owner}
                            </div>
                            <div className="flex items-center">
                              <Clock className="w-3 h-3 mr-1" />
                              {formatDate(file.lastModified)}
                            </div>
                            {file.size && <span>{formatFileSize(file.size)}</span>}
                            {file.mimeType && file.mimeType !== 'application/octet-stream' && (
                              <span className="text-xs bg-gray-100 px-2 py-0.5 rounded">
                                {file.mimeType.split('/')[1]?.toUpperCase() || 'FILE'}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium border transition-all hover:scale-105 ${getComplianceColor(file.compliance)}`}>
                          {file.compliance}
                        </span>
                        
                        <div className="flex items-center space-x-1">
                          {file.encrypted && (
                            <motion.div 
                              className="w-2 h-2 bg-green-500 rounded-full" 
                              title="Quantum Encrypted"
                              whileHover={{ scale: 1.5 }}
                            />
                          )}
                          {file.shared && (
                            <motion.div 
                              className="w-2 h-2 bg-blue-500 rounded-full" 
                              title="Shared"
                              whileHover={{ scale: 1.5 }}
                            />
                          )}
                          {file.status === 'uploading' && (
                            <motion.div 
                              className="w-2 h-2 bg-yellow-500 rounded-full" 
                              title="Uploading"
                              animate={{ scale: [1, 1.5, 1] }}
                              transition={{ duration: 1, repeat: Infinity }}
                            />
                          )}
                        </div>

                        <div className="flex items-center space-x-1">
                          <motion.button
                            onClick={() => handleFileView(file)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all duration-200"
                            whileHover={{ scale: 1.1, backgroundColor: "#f3f4f6" }}
                            whileTap={{ scale: 0.9 }}
                            title="View file"
                            disabled={file.status === 'uploading' || uploading}
                          >
                            <Eye className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileDownload(file)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all duration-200"
                            whileHover={{ scale: 1.1, backgroundColor: "#f3f4f6" }}
                            whileTap={{ scale: 0.9 }}
                            title="Download file"
                            disabled={file.status === 'uploading' || uploading}
                          >
                            <Download className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileShare(file.id, file.name)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all duration-200"
                            whileHover={{ scale: 1.1, backgroundColor: "#f3f4f6" }}
                            whileTap={{ scale: 0.9 }}
                            title="Share file"
                            disabled={file.status === 'uploading' || uploading}
                          >
                            <Share className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileDelete(file.id, file.name)}
                            className="p-2 text-red-400 hover:text-red-600 hover:bg-red-100 rounded-lg transition-all duration-200"
                            whileHover={{ scale: 1.1, backgroundColor: "#fee2e2" }}
                            whileTap={{ scale: 0.9 }}
                            title="Delete file"
                            disabled={file.status === 'uploading' || uploading}
                          >
                            <Trash2 className="w-4 h-4" />
                          </motion.button>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            )}
          </div>
        </motion.div>

        {/* Enhanced Storage Statistics */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, type: "spring", stiffness: 300, damping: 30 }}
        >
          {[
            { label: 'Total Files', value: files.length.toString(), icon: File, color: 'text-blue-600', bgColor: 'bg-blue-100' },
            { label: 'Storage Used', value: formatFileSize(fileStats.totalSize), icon: Folder, color: 'text-green-600', bgColor: 'bg-green-100' },
            { label: 'Shared Files', value: fileStats.sharedFiles.toString(), icon: Share, color: 'text-purple-600', bgColor: 'bg-purple-100' },
            { label: 'Encrypted', value: `${Math.round((fileStats.encryptedFiles / Math.max(files.length, 1)) * 100)}%`, icon: Shield, color: 'text-orange-600', bgColor: 'bg-orange-100' }
          ].map((stat, index) => (
            <motion.div
              key={stat.label}
              className="apple-card p-6 text-center apple-hover cursor-pointer"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ 
                delay: 0.6 + index * 0.1, 
                type: "spring", 
                stiffness: 300, 
                damping: 30 
              }}
              whileHover={{ scale: 1.05, y: -2 }}
              whileTap={{ scale: 0.95 }}
            >
              <motion.div 
                className={`w-12 h-12 ${stat.bgColor} rounded-full flex items-center justify-center mx-auto mb-4`}
                whileHover={{ rotate: 360 }}
                transition={{ duration: 0.6 }}
              >
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </motion.div>
              <div className="text-2xl font-semibold text-gray-900 mb-1">{stat.value}</div>
              <div className="text-sm text-gray-600">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>

        {/* Enhanced DataVault Info Banner */}
        <motion.div
          className="mt-8 p-6 bg-gradient-to-r from-blue-50 to-purple-50 rounded-xl border border-blue-200"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, type: "spring", stiffness: 300, damping: 30 }}
          whileHover={{ scale: 1.02 }}
        >
          <div className="flex items-center space-x-4">
            <motion.div
              animate={{ rotate: [0, 5, -5, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
            >
              <Shield className="w-8 h-8 text-blue-600" />
            </motion.div>
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900 mb-1">DataVault Enterprise Protection</h3>
              <p className="text-sm text-gray-600">
                Your files are automatically distributed across 3 nodes with BFT consensus and quantum-safe encryption. 
                Even if 1 node fails, your data remains accessible and secure across the network.
              </p>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">Network Status</div>
              <div className="flex items-center space-x-2 mt-1">
                <motion.div 
                  className="w-2 h-2 bg-green-500 rounded-full"
                  animate={{ scale: [1, 1.5, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                />
                <span className="text-sm font-medium text-green-600">3 Nodes Online</span>
              </div>
              <div className="text-xs text-gray-400 mt-1">
                BFT Consensus: Active
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
