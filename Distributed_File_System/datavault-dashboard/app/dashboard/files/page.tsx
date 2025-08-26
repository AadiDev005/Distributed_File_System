'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, 
  Filter, 
  RefreshCw,
  Loader2,
  Wifi,
  WifiOff,
  File,
  Folder,
  User,
  Clock,
  Shield,
  Sparkles,
  X,
  CheckCircle,
  AlertTriangle,
  Eye,
  Download,
  Share,
  Trash2,
  Upload,
  Settings,
  Zap,
  Lock,
  type LucideIcon
} from 'lucide-react';
import { DataVaultAPI, FileItem, SecurityMode, SecurityModeInfo } from '../utils/api';

interface Notification {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
  duration?: number;
}

interface FeatureItem {
  icon: LucideIcon;
  label: string;
  color: string;
  active?: boolean;
}

interface SecurityStatus {
  pii_detection: boolean;
  abe_encryption: boolean;
  bft_consensus: boolean;
  gdpr_compliance: boolean;
  threshold_sharing: boolean;
  immutable_audit: boolean;
}

// ✅ ENHANCED: Added file statistics interface
interface FileStats {
  totalSize: number;
  encryptedFiles: number;
  sharedFiles: number;
  enterpriseFiles: number;
  simpleFiles: number;
}

export default function FilesPage() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<'online' | 'offline'>('online');
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [dragOver, setDragOver] = useState(false);
  const [sessionId, setSessionId] = useState<string>('');

  // ✅ ENHANCED: Security mode state with better typing
  const [securityMode, setSecurityMode] = useState<SecurityMode>('simple');
  const [securityModeInfo, setSecurityModeInfo] = useState<SecurityModeInfo | null>(null);
  const [showSecurityDetails, setShowSecurityDetails] = useState(false);
  const [securityModeLoading, setSecurityModeLoading] = useState(false);

  const timeoutRefs = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ✅ ENHANCED: Initialize session and security mode
  useEffect(() => {
    const initializeApp = async () => {
      const session = localStorage.getItem('datavault_session_id');
      if (session) {
        setSessionId(session);
      }
      
      // Fetch current security mode
      await fetchSecurityMode();
    };

    initializeApp();
  }, []);

  // ✅ ENHANCED: Better security mode management
  const fetchSecurityMode = useCallback(async () => {
    try {
      const modeInfo = await DataVaultAPI.getSecurityMode();
      setSecurityModeInfo(modeInfo);
      setSecurityMode(modeInfo.current_mode);
      console.log(`🔒 Current security mode: ${modeInfo.current_mode}`);
    } catch (error) {
      console.error('Failed to fetch security mode:', error);
      const cachedMode = DataVaultAPI.getCachedSecurityMode();
      setSecurityMode(cachedMode);
    }
  }, []);

  const toggleSecurityMode = useCallback(async () => {
    if (securityModeLoading) return;
    
    setSecurityModeLoading(true);
    const newMode: SecurityMode = securityMode === 'simple' ? 'enterprise' : 'simple';
    
    try {
      showNotification('info', `🔄 Switching to ${newMode.toUpperCase()} mode...`);
      
      const result = await DataVaultAPI.setSecurityMode(newMode);
      
      if (result.success) {
        setSecurityMode(result.new_mode);
        showNotification('success', `✅ Security mode changed to ${result.new_mode.toUpperCase()}`);
        
        // Update security mode info
        if (securityModeInfo) {
          setSecurityModeInfo({
            ...securityModeInfo,
            current_mode: result.new_mode
          });
        }
        
        // Refresh files to show updated security context
        await loadFiles();
      } else {
        throw new Error(result.message || 'Failed to change security mode');
      }
    } catch (error) {
      console.error('❌ Failed to change security mode:', error);
      showNotification('error', `Failed to change security mode: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setSecurityModeLoading(false);
    }
  }, [securityMode, securityModeInfo, securityModeLoading]);

  // ✅ ENHANCED: Utility functions with better error handling
  const formatBytes = useCallback((bytes?: number): string => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = 2;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }, []);

  const formatDate = useCallback((dateStr: string): string => {
    try {
      const date = new Date(dateStr);
      if (isNaN(date.getTime())) return 'Invalid Date';
      
      const now = new Date();
      const diffHours = (now.getTime() - date.getTime()) / (1000 * 60 * 60);
      
      if (diffHours < 1) return 'Just now';
      if (diffHours < 24) return `${Math.floor(diffHours)} hours ago`;
      if (diffHours < 48) return 'Yesterday';
      
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Invalid Date';
    }
  }, []);

  const getComplianceColor = useCallback((compliance: string): string => {
    const colors = {
      'GDPR': 'bg-blue-100 text-blue-700 border-blue-200',
      'HIPAA': 'bg-green-100 text-green-700 border-green-200',
      'SOX': 'bg-purple-100 text-purple-700 border-purple-200',
      'PCI-DSS': 'bg-orange-100 text-orange-700 border-orange-200'
    };
    return colors[compliance as keyof typeof colors] || 'bg-gray-100 text-gray-700 border-gray-200';
  }, []);

  const getSecurityModeColor = useCallback((mode?: SecurityMode): string => {
    if (mode === 'enterprise') {
      return 'bg-red-100 text-red-700 border-red-200';
    }
    return 'bg-green-100 text-green-700 border-green-200';
  }, []);

  // ✅ ENHANCED: Notification system with cleanup
  const showNotification = useCallback((type: Notification['type'], message: string, duration = 5000) => {
    const id = Math.random().toString(36).substr(2, 9);
    setNotifications(prev => [...prev, { id, type, message, duration }]);
    
    const timer = setTimeout(() => {
      setNotifications(current => current.filter(n => n.id !== id));
      timeoutRefs.current.delete(id);
    }, duration);
    
    timeoutRefs.current.set(id, timer);
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(current => current.filter(n => n.id !== id));
    const timeout = timeoutRefs.current.get(id);
    if (timeout) {
      clearTimeout(timeout);
      timeoutRefs.current.delete(id);
    }
  }, []);

  // ✅ ENHANCED: File operations with better error handling
  const loadFiles = useCallback(async () => {
    setLoading(true);
    try {
      const response = await DataVaultAPI.getFileList();
      if (response.success) {
        setFiles(response.files);
        setConnectionStatus('online');
        setLastRefresh(new Date());
        
        const enterpriseCount = response.files.filter(f => f.security_mode === 'enterprise').length;
        const simpleCount = response.files.length - enterpriseCount;
        
        showNotification('success', 
          `✅ Loaded ${response.files.length} files - ${enterpriseCount} enterprise, ${simpleCount} simple mode`);
      } else {
        showNotification('warning', '⚠️ Failed to load files from backend');
      }
    } catch (error) {
      setConnectionStatus('offline');
      showNotification('error', '❌ Network error - Using cached data');
      console.error('Failed to load files:', error);
    } finally {
      setLoading(false);
    }
  }, [showNotification]);

  const handleFileUpload = useCallback(async (selectedFiles: FileList) => {
    if (selectedFiles.length === 0) return;

    setUploading(true);
    setUploadProgress(0);

    try {
      // ✅ ENHANCED: Security mode context in upload message
      const filesArray = Array.from(selectedFiles);
      const enterpriseFiles = filesArray.filter(f => 
        DataVaultAPI.shouldUseEnterpriseMode(f.name, f.size)
      );
      
      const message = enterpriseFiles.length > 0 
        ? `📤 Uploading ${selectedFiles.length} files - ${enterpriseFiles.length} will use enterprise security...`
        : `📤 Uploading ${selectedFiles.length} files with ${securityMode} security...`;
      
      showNotification('info', message);

      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) return prev;
          return prev + Math.random() * 10 + 5;
        });
      }, 300);

      const response = await DataVaultAPI.uploadFiles(selectedFiles);

      clearInterval(progressInterval);
      setUploadProgress(100);

      if (response.success) {
        const enterpriseUploaded = response.files_by_security_mode?.enterprise || 0;
        const simpleUploaded = response.files_by_security_mode?.simple || 0;
        
        showNotification('success', 
          `🎉 Successfully uploaded ${response.files.length} files! ${enterpriseUploaded} enterprise, ${simpleUploaded} simple mode`);
        
        // Add new files to the list
        setFiles(prev => [...response.files, ...prev]);
        
        // Refresh files list after upload
        setTimeout(() => loadFiles(), 2000);
      } else {
        showNotification('error', '❌ Upload completed but server response was unsuccessful');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      if (errorMessage.includes('Authentication') || errorMessage.includes('Enterprise mode requires')) {
        showNotification('error', `❌ ${errorMessage}`);
      } else {
        showNotification('error', `❌ Upload failed: ${errorMessage}`);
      }
    } finally {
      setUploading(false);
      setTimeout(() => setUploadProgress(0), 2000);
    }
  }, [securityMode, showNotification, loadFiles]);

  const handleFileView = useCallback(async (file: FileItem) => {
    try {
      const securityInfo = file.security_mode === 'enterprise' ? ' (enterprise security)' : '';
      showNotification('info', `👁️ Opening ${file.name}${securityInfo}...`);
      
      await DataVaultAPI.handleFileView(file.id);
      
      showNotification('success', `✅ Opened ${file.name}`);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      if (errorMessage.includes('Authentication') || errorMessage.includes('401')) {
        showNotification('error', `❌ Authentication failed for ${file.name} - please refresh and try again`);
        
        if (confirm('Authentication expired. Would you like to refresh the page?')) {
          window.location.reload();
        }
      } else {
        showNotification('error', `❌ Failed to view ${file.name}: ${errorMessage}`);
      }
      
      console.error('File view error:', error);
    }
  }, [showNotification]);

  const handleFileDownload = useCallback(async (file: FileItem) => {
    try {
      showNotification('info', `⬇️ Downloading ${file.name}...`);
      await DataVaultAPI.downloadFile(file.id, file.name);
      showNotification('success', `✅ Downloaded ${file.name} successfully!`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      showNotification('error', `❌ Failed to download ${file.name}: ${errorMessage}`);
    }
  }, [showNotification]);

  const handleFileShare = useCallback(async (file: FileItem) => {
    try {
      showNotification('info', `🔗 Sharing ${file.name}...`);
      
      const sessionId = localStorage.getItem('datavault_session_id');
      if (!sessionId) {
        throw new Error('No active session - please login first');
      }

      const shareUrl = DataVaultAPI.getFileViewUrl(file.id, sessionId);
      
      await navigator.clipboard.writeText(shareUrl);
      showNotification('success', `✅ Share link copied to clipboard for ${file.name}!`);
      
      setFiles(prev => prev.map(f => 
        f.id === file.id ? { ...f, shared: true } : f
      ));
      
    } catch (error) {
      console.error('Share error:', error);
      
      try {
        const fileInfo = `📄 ${file.name}\n🔒 Security: ${file.security_mode}\n📊 Size: ${formatBytes(file.size)}\n🏢 Owner: ${file.owner}`;
        await navigator.clipboard.writeText(fileInfo);
        showNotification('success', `✅ File details copied to clipboard for ${file.name}!`);
      } catch (clipboardError) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        showNotification('error', `❌ Failed to share ${file.name}: ${errorMessage}`);
      }
    }
  }, [showNotification, formatBytes]);

  const handleFileDelete = useCallback(async (file: FileItem) => {
    if (!confirm(`⚠️ Delete "${file.name}"?\n\nThis will remove the file from all DataVault nodes and cannot be undone.`)) {
      return;
    }

    try {
      showNotification('info', `🗑️ Deleting ${file.name}...`);
      
      // Optimistic update
      setFiles(prev => prev.filter(f => f.id !== file.id));
      
      const result = await DataVaultAPI.deleteFile(file.id);
      
      if (result.success) {
        showNotification('success', `✅ Deleted ${file.name} successfully`);
      } else {
        // Revert optimistic update
        loadFiles();
        showNotification('error', `❌ Failed to delete ${file.name}`);
      }
    } catch (error) {
      // Revert optimistic update
      loadFiles();
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      showNotification('error', `❌ Failed to delete ${file.name}: ${errorMessage}`);
    }
  }, [showNotification, loadFiles]);

  // ✅ ENHANCED: Drag and drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles.length > 0) {
      handleFileUpload(droppedFiles);
    }
  }, [handleFileUpload]);

  // ✅ ENHANCED: Memoized computed values
  const filteredFiles = useMemo(() => {
    if (!searchQuery.trim()) return files;
    const query = searchQuery.toLowerCase();
    return files.filter(file => 
      file.name.toLowerCase().includes(query) ||
      file.owner.toLowerCase().includes(query) ||
      file.compliance.toLowerCase().includes(query) ||
      (file.mimeType && file.mimeType.toLowerCase().includes(query)) ||
      (file.security_mode && file.security_mode.toLowerCase().includes(query))
    );
  }, [files, searchQuery]);

  const fileStats = useMemo((): FileStats => {
    const totalSize = files.reduce((acc, file) => acc + (file.size || 0), 0);
    const encryptedFiles = files.filter(f => f.encrypted).length;
    const sharedFiles = files.filter(f => f.shared).length;
    const enterpriseFiles = files.filter(f => f.security_mode === 'enterprise').length;
    const simpleFiles = files.length - enterpriseFiles;
    
    return { totalSize, encryptedFiles, sharedFiles, enterpriseFiles, simpleFiles };
  }, [files]);

  const securityFeatures = useMemo((): FeatureItem[] => {
    return securityMode === 'enterprise' ? [
      { icon: Shield, label: 'Zero-Trust Security', color: 'text-red-600' },
      { icon: Lock, label: 'ABE Encryption', color: 'text-purple-600' },
      { icon: RefreshCw, label: 'BFT Consensus', color: 'text-blue-600' },
      { icon: Eye, label: 'Threat Detection', color: 'text-orange-600' }
    ] : [
      { icon: Shield, label: 'Quantum Encrypted', color: 'text-green-600' },
      { icon: Sparkles, label: 'Fast Processing', color: 'text-blue-600' },
      { icon: RefreshCw, label: 'Simple Security', color: 'text-purple-600' },
      { icon: Clock, label: 'Immutable Audit', color: 'text-orange-600' }
    ];
  }, [securityMode]);

  // Load files on mount
  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      timeoutRefs.current.forEach(timeout => clearTimeout(timeout));
      timeoutRefs.current.clear();
    };
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Notifications */}
        <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
          <AnimatePresence>
            {notifications.map((notification) => (
              <motion.div
                key={notification.id}
                initial={{ opacity: 0, x: 100, scale: 0.95 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 100, scale: 0.95 }}
                className={`p-4 rounded-lg shadow-lg border backdrop-blur-sm ${
                  notification.type === 'success' 
                    ? 'bg-emerald-50/95 border-emerald-200 text-emerald-800'
                    : notification.type === 'error'
                    ? 'bg-red-50/95 border-red-200 text-red-800'
                    : notification.type === 'warning'
                    ? 'bg-yellow-50/95 border-yellow-200 text-yellow-800'
                    : 'bg-blue-50/95 border-blue-200 text-blue-800'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{notification.message}</span>
                  <button
                    onClick={() => removeNotification(notification.id)}
                    className="ml-2 p-1 hover:bg-black/10 rounded"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8"
        >
          <div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Secure File Management
            </h1>
            <p className="text-gray-600">
              Upload, share, and manage files with enterprise-grade security across the DataVault network
            </p>
          </div>
          
          <div className="flex items-center space-x-4">
            <button
              onClick={loadFiles}
              disabled={loading}
              className="flex items-center space-x-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg transition-all duration-200 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>

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

        {/* ✅ ENHANCED: Security Mode Toggle */}
        <motion.div 
          className={`flex items-center justify-between p-4 rounded-lg border mb-6 transition-all ${
            securityMode === 'enterprise' 
              ? 'bg-red-50 border-red-200' 
              : 'bg-green-50 border-green-200'
          }`}
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <span className="font-medium text-gray-700">Security Mode:</span>
              <button
                onClick={toggleSecurityMode}
                disabled={uploading || securityModeLoading}
                className={`px-4 py-2 rounded-lg font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
                  securityMode === 'simple' 
                    ? 'bg-green-500 hover:bg-green-600 text-white shadow-md' 
                    : 'bg-red-500 hover:bg-red-600 text-white shadow-md'
                } ${!uploading && !securityModeLoading ? 'hover:scale-105' : ''}`}
              >
                {securityModeLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin inline mr-2" />
                    Switching...
                  </>
                ) : (
                  securityMode === 'simple' ? '⚡ Simple Mode' : '🔒 Enterprise Mode'
                )}
              </button>
            </div>
            
            <button
              onClick={() => setShowSecurityDetails(!showSecurityDetails)}
              className="p-1 text-gray-500 hover:text-gray-700 transition-colors"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
          
          <div className="flex items-center space-x-4 text-sm text-gray-600">
            <span>
              {securityMode === 'simple' 
                ? 'Fast & easy file operations' 
                : 'Maximum security & compliance'
              }
            </span>
            <div className="flex items-center space-x-2">
              <span>{fileStats.enterpriseFiles} enterprise</span>
              <span>•</span>
              <span>{fileStats.simpleFiles} simple</span>
            </div>
          </div>
        </motion.div>

        {/* ✅ ENHANCED: Security Mode Details */}
        <AnimatePresence>
          {showSecurityDetails && securityModeInfo && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="bg-white rounded-lg border p-4 space-y-4 mb-6"
            >
              <h4 className="font-medium text-gray-900">Security Mode Details</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(securityModeInfo.features).map(([mode, features]) => (
                  <div key={mode} className={`p-3 rounded-lg border transition-all ${
                    mode === securityMode ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-200'
                  }`}>
                    <h5 className="font-medium mb-2 capitalize">
                      {mode} Mode {mode === securityMode && '(Current)'}
                    </h5>
                    <ul className="space-y-1 text-sm text-gray-600">
                      {features.map((feature: string) => (
                        <li key={feature} className="flex items-center">
                          <CheckCircle className="w-3 h-3 text-green-500 mr-2 flex-shrink-0" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
              <div className="text-xs text-gray-500 border-t pt-3">
                <strong>Auto-Detection:</strong> Files with "confidential", "secret", "classified", "private" in name or larger than 50MB automatically use Enterprise mode.
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ✅ ENHANCED: Upload Area */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={`relative mb-8 p-8 border-2 border-dashed rounded-xl transition-all duration-300 ${
            dragOver 
              ? 'border-blue-400 bg-blue-50' 
              : uploading 
              ? 'border-green-400 bg-green-50'
              : 'border-gray-300 bg-white hover:border-blue-400'
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
          />

          <div className="text-center">
            <motion.div
              animate={dragOver ? { scale: 1.1 } : { scale: 1 }}
              className={`w-16 h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center ${
                securityMode === 'enterprise' 
                  ? 'bg-gradient-to-br from-red-500 to-purple-600'
                  : 'bg-gradient-to-br from-blue-500 to-purple-600'
              }`}
            >
              {uploading ? (
                <RefreshCw className="w-8 h-8 text-white animate-spin" />
              ) : (
                <Upload className="w-8 h-8 text-white" />
              )}
            </motion.div>

            <h3 className="text-xl font-semibold mb-2">
              {dragOver ? 'Drop files here' : uploading ? 'Uploading files...' : `Upload to DataVault (${securityMode.toUpperCase()})`}
            </h3>

            {uploading ? (
              <div className="mb-4">
                <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                  <motion.div
                    className="bg-green-500 h-2 rounded-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${uploadProgress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
                <p className="text-sm text-gray-600">{Math.round(uploadProgress)}% complete</p>
              </div>
            ) : (
              <>
                <p className="text-gray-600 mb-6">
                  Drag and drop files or{' '}
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="text-blue-600 hover:text-blue-800 font-medium"
                  >
                    browse
                  </button>
                </p>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  {securityFeatures.map((feature) => {
                    const Icon = feature.icon;
                    return (
                      <div key={feature.label} className="flex items-center space-x-2">
                        <Icon className={`w-4 h-4 ${feature.color}`} />
                        <span className="text-sm text-gray-600">{feature.label}</span>
                      </div>
                    );
                  })}
                </div>

                {securityMode === 'enterprise' && (
                  <div className="text-xs text-purple-600 font-medium">
                    🔒 Enterprise mode: Files with "confidential/secret" or 50MB auto-detected
                  </div>
                )}
              </>
            )}
          </div>
        </motion.div>

        {/* Search Bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center space-x-4 mb-8"
        >
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Search by filename, owner, compliance, security mode, or file type..."
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-4 top-1/2 transform -translate-y-1/2 p-1 hover:bg-gray-100 rounded-full"
              >
                <X className="w-4 h-4 text-gray-400" />
              </button>
            )}
          </div>
          
          <div className="text-sm text-gray-500">
            {filteredFiles.length} of {files.length} files
          </div>
        </motion.div>

        {/* Files List */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden"
        >
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">
                Files & Folders ({filteredFiles.length})
              </h2>
              <div className="flex items-center space-x-4">
                <div className="flex items-center text-sm text-gray-600">
                  <Shield className="w-4 h-4 mr-1 text-green-600" />
                  All files quantum-encrypted
                </div>
                <div className="text-xs text-gray-400">
                  Last updated: {formatDate(lastRefresh.toISOString())}
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
              </div>
            ) : filteredFiles.length === 0 ? (
              <div className="p-12 text-center">
                <File className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500">
                  {searchQuery ? 'No files match your search' : 'No files uploaded yet'}
                </p>
                {!searchQuery && (
                  <p className="text-sm text-gray-400 mt-2">
                    Upload your first file to get started
                  </p>
                )}
              </div>
            ) : (
              <AnimatePresence>
                {filteredFiles.map((file, index) => (
                  <motion.div
                    key={file.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ delay: Math.min(0.05 * index, 0.3) }}
                    className="p-6 hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                          file.security_mode === 'enterprise' ? 'bg-red-100' : 'bg-blue-100'
                        }`}>
                          {file.type === 'folder' ? (
                            <Folder className={`w-5 h-5 ${
                              file.security_mode === 'enterprise' ? 'text-red-600' : 'text-blue-600'
                            }`} />
                          ) : (
                            <File className={`w-5 h-5 ${
                              file.security_mode === 'enterprise' ? 'text-red-600' : 'text-blue-600'
                            }`} />
                          )}
                        </div>
                        
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
                            {file.security_mode && (
                              <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                                getSecurityModeColor(file.security_mode)
                              }`}>
                                {file.security_mode === 'enterprise' ? '🔒 Enterprise' : '⚡ Simple'}
                              </span>
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
                            {file.size && <span>{formatBytes(file.size)}</span>}
                            {file.mimeType && file.mimeType !== 'application/octet-stream' && (
                              <span className="text-xs bg-gray-100 px-2 py-0.5 rounded">
                                {file.mimeType.split('/')[1]?.toUpperCase() || 'FILE'}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-4">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getComplianceColor(file.compliance)}`}>
                          {file.compliance}
                        </span>
                        
                        <div className="flex items-center space-x-1">
                          {file.encrypted && (
                            <div className="w-2 h-2 bg-green-500 rounded-full" title="Quantum Encrypted" />
                          )}
                          {file.shared && (
                            <div className="w-2 h-2 bg-blue-500 rounded-full" title="Shared" />
                          )}
                        </div>

                        <div className="flex items-center space-x-1">
                          <motion.button
                            onClick={() => handleFileView(file)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all"
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            title="View file"
                            disabled={uploading}
                          >
                            <Eye className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileDownload(file)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all"
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            title="Download file"
                            disabled={uploading}
                          >
                            <Download className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileShare(file)}
                            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-all"
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            title="Share file"
                            disabled={uploading}
                          >
                            <Share className="w-4 h-4" />
                          </motion.button>
                          <motion.button
                            onClick={() => handleFileDelete(file)}
                            className="p-2 text-red-400 hover:text-red-600 hover:bg-red-100 rounded-lg transition-all"
                            whileHover={{ scale: 1.1 }}
                            whileTap={{ scale: 0.9 }}
                            title="Delete file"
                            disabled={uploading}
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

        {/* Statistics */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 md:grid-cols-5 gap-6 mt-8"
        >
          {[
            { label: 'Total Files', value: files.length.toString(), icon: File, color: 'text-blue-600', bg: 'bg-blue-100' },
            { label: 'Storage Used', value: formatBytes(fileStats.totalSize), icon: Folder, color: 'text-green-600', bg: 'bg-green-100' },
            { label: 'Shared Files', value: fileStats.sharedFiles.toString(), icon: Share, color: 'text-purple-600', bg: 'bg-purple-100' },
            { label: 'Enterprise', value: fileStats.enterpriseFiles.toString(), icon: Lock, color: 'text-red-600', bg: 'bg-red-100' },
            { label: 'Simple Mode', value: fileStats.simpleFiles.toString(), icon: Zap, color: 'text-orange-600', bg: 'bg-orange-100' }
          ].map((stat) => {
            const Icon = stat.icon;
            return (
              <motion.div
                key={stat.label}
                className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 text-center hover:shadow-md transition-shadow"
                whileHover={{ scale: 1.02 }}
              >
                <div className={`w-12 h-12 ${stat.bg} rounded-full flex items-center justify-center mx-auto mb-4`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
                <div className="text-2xl font-semibold text-gray-900 mb-1">{stat.value}</div>
                <div className="text-sm text-gray-600">{stat.label}</div>
              </motion.div>
            );
          })}
        </motion.div>

        {/* DataVault Info */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={`mt-8 p-6 rounded-xl border transition-all ${
            securityMode === 'enterprise' 
              ? 'bg-gradient-to-r from-red-50 to-purple-50 border-red-200'
              : 'bg-gradient-to-r from-blue-50 to-purple-50 border-blue-200'
          }`}
        >
          <div className="flex items-center space-x-4">
            <Shield className={`w-8 h-8 ${
              securityMode === 'enterprise' ? 'text-red-600' : 'text-blue-600'
            }`} />
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900 mb-1">
                DataVault Enterprise Protection ({securityMode.toUpperCase()} Mode)
              </h3>
              <p className="text-sm text-gray-600">
                Your files are automatically distributed across multiple nodes with BFT consensus and quantum-safe encryption. 
                {securityMode === 'enterprise' 
                  ? ' Enterprise mode provides maximum security with zero-trust evaluation and compliance automation.'
                  : ' Simple mode offers fast access with essential security features.'
                }
              </p>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">Network Status</div>
              <div className="flex items-center space-x-2 mt-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                <span className="text-sm font-medium text-green-600">All Nodes Online</span>
              </div>
              <div className="text-xs text-gray-400 mt-1">
                BFT Consensus: Active • Mode: {securityMode}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
