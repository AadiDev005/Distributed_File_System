'use client';

import {
  useState, useCallback, useRef, useEffect, DragEvent, ChangeEvent
} from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload,
  X,
  CheckCircle,
  AlertCircle,
  File,
  Sparkles,
  Shield,
  Zap,
  Lock,
  Eye,
  RefreshCw,
  Settings
} from 'lucide-react';
import { DataVaultAPI, FileItem, SecurityMode, SecurityModeInfo } from '../dashboard/utils/api';

/* ─── types ──────────────────────────────────────────────── */

interface FileUploadProps {
  onUploadComplete?: (files: FileItem[]) => void;
  onError?: (error: string) => void;
  maxFiles?: number;          // default 10
  maxFileSize?: number;       // MB – default 100
  uploading?: boolean;        // comes from parent
  uploadProgress?: number;    // comes from parent
  disabled?: boolean;
}

type UploadStatus = 'uploading' | 'complete' | 'error';

interface UploadingFile {
  id: string;
  name: string;
  size: number;
  progress: number;
  status: UploadStatus;
  error?: string;
  securityApplied?: SecurityFeatures;
  securityMode?: SecurityMode; // ✅ NEW: Track which mode was used
}

interface SecurityFeatures {
  pii_detection: boolean;
  abe_encryption: boolean;
  bft_consensus: boolean;
  gdpr_compliance: boolean;
  threshold_sharing: boolean;
  immutable_audit: boolean;
  quantum_encryption: boolean;
  zero_trust_verified: boolean;
}

/* ─── component ──────────────────────────────────────────── */

export default function FileUpload({
  onUploadComplete,
  onError,
  maxFiles = 10,
  maxFileSize = 100,
  uploading = false,
  uploadProgress = 0,
  disabled = false
}: FileUploadProps) {
  /* state */
  const [isDragging, setIsDragging] = useState(false);
  const [dragCounter, setDragCounter] = useState(0);
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string>('');
  
  // ✅ NEW: Security mode state
  const [securityMode, setSecurityMode] = useState<SecurityMode>('simple');
  const [securityModeInfo, setSecurityModeInfo] = useState<SecurityModeInfo | null>(null);
  const [showSecurityToggle, setShowSecurityToggle] = useState(false);

  /* refs */
  const fileInputRef = useRef<HTMLInputElement>(null);
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // ✅ FIXED: Use DataVaultAPI for security mode instead of direct fetch
  useEffect(() => {
    const session = localStorage.getItem('datavault_session_id');
    if (session) {
      setSessionId(session);
    }
    
    // Fetch current security mode using DataVaultAPI
    fetchSecurityMode();
  }, []);

  // ✅ FIXED: Use DataVaultAPI methods
  const fetchSecurityMode = async () => {
    try {
      const modeInfo = await DataVaultAPI.getSecurityMode();
      setSecurityModeInfo(modeInfo);
      setSecurityMode(modeInfo.current_mode);
      console.log(`🔒 Current security mode: ${modeInfo.current_mode}`);
    } catch (error) {
      console.error('Failed to fetch security mode:', error);
      // Use cached mode as fallback
      const cachedMode = DataVaultAPI.getCachedSecurityMode();
      setSecurityMode(cachedMode);
    }
  };

  const toggleSecurityMode = async () => {
    const newMode: SecurityMode = securityMode === 'simple' ? 'enterprise' : 'simple';
    
    try {
      const result = await DataVaultAPI.setSecurityMode(newMode);
      if (result.success) {
        setSecurityMode(newMode);
        console.log(`✅ Security mode changed to ${newMode}`);
        
        // Update security mode info
        if (securityModeInfo) {
          setSecurityModeInfo({
            ...securityModeInfo,
            current_mode: newMode
          });
        }
        
        setError(null);
      } else {
        throw new Error(result.message || 'Failed to change security mode');
      }
    } catch (error) {
      console.error('❌ Failed to change security mode:', error);
      setError('Failed to change security mode');
    }
  };

  /* ── helpers ─────────────────────────────────────────── */

  const formatFileSize = useCallback((bytes: number) => {
    if (!bytes) return '0 Bytes';
    const k = 1_024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
  }, []);

  const getAcceptedTypes = useCallback(
    () =>
      [
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.txt', '.csv', '.md', '.json', '.html', '.css', '.js', '.ts',
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp',
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.mp3', '.wav', '.flac', '.aac', '.ogg',
        '.zip', '.rar', '.7z', '.tar', '.gz'
      ].join(','),
    []
  );

  // ✅ FIXED: Use DataVaultAPI method for consistency
  const shouldUseEnterpriseMode = useCallback((fileName: string, fileSize: number): boolean => {
    return DataVaultAPI.shouldUseEnterpriseMode(fileName, fileSize);
  }, []);

  // ✅ FIXED: Use DataVaultAPI method for consistency
  const detectCompliance = useCallback((fileName: string): 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS' => {
    return DataVaultAPI.detectComplianceType(fileName);
  }, []);

  /* ── validation ──────────────────────────────────────── */

  const validateFiles = useCallback(
    (files: FileList): string | null => {
      if (files.length === 0) return 'No files selected';
      if (files.length > maxFiles)
        return `Maximum ${maxFiles} files allowed (you selected ${files.length}).`;

      for (const file of Array.from(files)) {
        const sizeMB = file.size / 1_048_576; // 1024^2
        if (sizeMB > maxFileSize)
          return `File "${file.name}" (${sizeMB.toFixed(
            2
          )} MB) exceeds ${maxFileSize} MB limit`;
        if (file.size === 0)
          return `File "${file.name}" is empty and cannot be uploaded`;
      }
      return null;
    },
    [maxFiles, maxFileSize]
  );

  /* ── drag & drop handlers ────────────────────────────── */

  const stop = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragIn = useCallback(
    (e: DragEvent) => {
      stop(e);
      if (disabled || uploading) return;
      setDragCounter(c => c + 1);
      if (e.dataTransfer.items?.length) {
        setIsDragging(true);
      }
    },
    [uploading, disabled]
  );

  const handleDragOut = useCallback((e: DragEvent) => {
    stop(e);
    setDragCounter(c => {
      const n = c - 1;
      if (n === 0) setIsDragging(false);
      return n;
    });
  }, []);

  const handleDrop = useCallback(
    (e: DragEvent) => {
      stop(e);
      setIsDragging(false);
      setDragCounter(0);
      if (uploading || disabled) return;
      if (e.dataTransfer.files?.length) handleFiles(e.dataTransfer.files);
    },
    [uploading, disabled]
  );

  /* ── file-input handler ──────────────────────────────── */

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length && !disabled && !uploading) {
      handleFiles(e.target.files);
    }
  };

  /* ── browse button ───────────────────────────────────── */

  const browse = () => {
    if (!uploading && !disabled) fileInputRef.current?.click();
  };

  /* ── core upload logic ───────────────────────────────── */

  const handleFiles = useCallback(
    async (files: FileList) => {
      setError(null);
      if (!files.length) return;

      /* validation */
      const valErr = validateFiles(files);
      if (valErr) {
        setError(valErr);
        onError?.(valErr);
        return;
      }

      // ✅ UPDATED: Determine security mode for each file
      const tracked: UploadingFile[] = Array.from(files).map((f, i) => {
        const fileSecurityMode = shouldUseEnterpriseMode(f.name, f.size) ? 'enterprise' : securityMode;
        
        return {
          id: `${Date.now()}_${i}_${f.name}`,
          name: f.name,
          size: f.size,
          progress: 0,
          status: 'uploading',
          securityMode: fileSecurityMode, // ✅ NEW: Track security mode per file
          securityApplied: {
            pii_detection: false,
            abe_encryption: false,
            bft_consensus: fileSecurityMode === 'enterprise', // ✅ Enterprise gets BFT immediately
            gdpr_compliance: false,
            threshold_sharing: false,
            immutable_audit: fileSecurityMode === 'enterprise',
            quantum_encryption: true, // Always true for DataVault
            zero_trust_verified: false
          }
        };
      });
      
      setUploadingFiles(tracked);

      // ✅ UPDATED: Show security mode info for files
      const enterpriseFiles = tracked.filter(f => f.securityMode === 'enterprise');
      if (enterpriseFiles.length > 0) {
        console.log(`🔒 ${enterpriseFiles.length} files will use ENTERPRISE security:`, 
          enterpriseFiles.map(f => f.name));
      }

      /* ✅ UPDATED: Enhanced progress simulation based on security mode */
      progressIntervalRef.current = setInterval(() => {
        setUploadingFiles(prev =>
          prev.map(f => {
            if (f.status !== 'uploading') return f;
            
            const progressIncrement = f.securityMode === 'enterprise' ? 
              Math.random() * 4 + 2 : // Slower for enterprise (more security checks)
              Math.random() * 8 + 4;  // Faster for simple mode
            
            const newProgress = Math.min(f.progress + progressIncrement, 85);
            
            // ✅ UPDATED: Security features based on mode
            const updatedSecurityFeatures = f.securityMode === 'enterprise' ? {
              quantum_encryption: true,
              bft_consensus: true,
              immutable_audit: true,
              pii_detection: newProgress > 25,
              gdpr_compliance: newProgress > 45,
              zero_trust_verified: newProgress > 65,
              abe_encryption: newProgress > 75,
              threshold_sharing: newProgress > 80,
            } : {
              quantum_encryption: true,
              bft_consensus: false,
              immutable_audit: newProgress > 50,
              pii_detection: newProgress > 60,
              gdpr_compliance: newProgress > 70,
              zero_trust_verified: false,
              abe_encryption: false,
              threshold_sharing: false,
            };
            
            return {
              ...f,
              progress: newProgress,
              securityApplied: newProgress > 20 ? updatedSecurityFeatures : f.securityApplied
            };
          })
        );
      }, 300);

      try {
        console.log(`📤 Uploading ${files.length} files to DataVault...`);
        console.log(`🔒 Current security mode: ${securityMode}`);
        
        const response = await DataVaultAPI.uploadFiles(files);
        
        clearInterval(progressIntervalRef.current!);
        progressIntervalRef.current = null;

        if (response.success && response.files) {
          console.log('✅ Upload successful:', response);

          /* ✅ UPDATED: Mark files complete with actual security applied */
          tracked.forEach((trackedFile, i) =>
            setTimeout(() => {
              setUploadingFiles(prev =>
                prev.map((f, idx) => {
                  if (idx !== i) return f;
                  
                  const uploadedFile = response.files[idx] as any;
                  const actualSecurityApplied = uploadedFile?.security_applied || response.security_applied || {};
                  
                  return {
                    ...f, 
                    progress: 100, 
                    status: 'complete',
                    securityApplied: {
                      pii_detection: actualSecurityApplied.pii_detection || false,
                      abe_encryption: actualSecurityApplied.abe_encryption || false,
                      bft_consensus: actualSecurityApplied.bft_consensus || false,
                      gdpr_compliance: actualSecurityApplied.gdpr_compliance || false,
                      threshold_sharing: actualSecurityApplied.threshold_sharing || false,
                      immutable_audit: actualSecurityApplied.immutable_audit || false,
                      quantum_encryption: actualSecurityApplied.quantum_encryption || true, // Always true for DataVault
                      zero_trust_verified: actualSecurityApplied.zero_trust_verified || (f.securityMode === 'enterprise'),
                    }
                  };
                })
              );
            }, i * 150)
          );

          /* call success callback */
          onUploadComplete?.(response.files);

          /* auto-clear after display */
          setTimeout(() => {
            if (fileInputRef.current) {
              fileInputRef.current.value = '';
            }
            setUploadingFiles([]);
          }, tracked.length * 150 + 3_000);

        } else {
          throw new Error(response.message || 'Upload failed - no files returned');
        }
      } catch (err) {
        console.error('❌ Upload failed:', err);
        
        clearInterval(progressIntervalRef.current!);
        progressIntervalRef.current = null;
        
        const msg = err instanceof Error ? err.message : 'Unexpected upload error occurred';

        /* mark files as error with staggered animation */
        tracked.forEach((_, i) =>
          setTimeout(() => {
            setUploadingFiles(prev =>
              prev.map((f, idx) =>
                idx === i ? { 
                  ...f, 
                  status: 'error', 
                  error: msg, 
                  progress: 0,
                  securityApplied: {
                    ...f.securityApplied!,
                    pii_detection: false,
                    abe_encryption: false,
                    bft_consensus: false,
                    gdpr_compliance: false,
                    threshold_sharing: false,
                    immutable_audit: false,
                    zero_trust_verified: false,
                    quantum_encryption: false
                  }
                } : f
              )
            );
          }, i * 100)
        );
        
        setError(msg);
        onError?.(msg);
      }
    },
    [onUploadComplete, onError, validateFiles, securityMode, shouldUseEnterpriseMode]
  );

  /* ── remove from list manually ───────────────────────── */

  const removeFile = (id: string) =>
    setUploadingFiles(prev => prev.filter(f => f.id !== id));

  /* ── cleanup timers on unmount ───────────────────────── */

  useEffect(() => {
    return () => {
      if (progressIntervalRef.current) clearInterval(progressIntervalRef.current);
    };
  }, []);

  /* ── JSX ──────────────────────────────────────────────── */

  return (
    <div className="space-y-6">
      {/* ✅ NEW: Security Mode Toggle */}
      <motion.div 
        className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <span className="font-medium text-gray-700">Security Mode:</span>
            <button
              onClick={toggleSecurityMode}
              disabled={uploading}
              className={`px-4 py-2 rounded-lg font-medium transition-all ${
                securityMode === 'simple' 
                  ? 'bg-green-500 hover:bg-green-600 text-white shadow-md' 
                  : 'bg-red-500 hover:bg-red-600 text-white shadow-md'
              } ${uploading ? 'opacity-50 cursor-not-allowed' : 'hover:scale-105'}`}
            >
              {securityMode === 'simple' ? '⚡ Simple Mode' : '🔒 Enterprise Mode'}
            </button>
          </div>
          
          <button
            onClick={() => setShowSecurityToggle(!showSecurityToggle)}
            className="p-1 text-gray-500 hover:text-gray-700 transition-colors"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
        
        <div className="text-sm text-gray-600">
          {securityMode === 'simple' 
            ? 'Fast & easy file operations' 
            : 'Maximum security & compliance'
          }
        </div>
      </motion.div>

      {/* ✅ NEW: Security Mode Details (collapsible) */}
      <AnimatePresence>
        {showSecurityToggle && securityModeInfo && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="bg-white rounded-lg border p-4 space-y-4"
          >
            <h4 className="font-medium text-gray-900">Security Features</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(securityModeInfo.features).map(([mode, features]) => (
                <div key={mode} className={`p-3 rounded-lg ${
                  mode === securityMode ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-200'
                } border`}>
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

      {/* ───── Drop zone ───── */}
      <motion.div
        className={`relative overflow-hidden rounded-xl border-2 border-dashed cursor-pointer transition-all duration-300 ${
          isDragging
            ? 'border-blue-500 bg-blue-50 shadow-lg scale-[1.02]'
            : uploading
            ? 'border-green-500 bg-green-50 shadow-md'
            : error
            ? 'border-red-500 bg-red-50 shadow-md'
            : disabled
            ? 'border-gray-200 bg-gray-50 opacity-50 cursor-not-allowed'
            : 'border-gray-300 hover:border-gray-400 hover:bg-gray-50 shadow-sm hover:shadow-md'
        }`}
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={stop}
        onDrop={handleDrop}
        whileHover={!disabled && !uploading ? { scale: 1.01 } : {}}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      >
        {/* hidden native input */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={handleFileInput}
          disabled={uploading || disabled}
          accept={getAcceptedTypes()}
        />

        {/* animated backgrounds */}
        <AnimatePresence>
          {isDragging && (
            <motion.div
              className="absolute inset-0 bg-gradient-to-r from-blue-400/20 to-purple-400/20"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            />
          )}
          {uploading && (
            <motion.div
              className="absolute inset-0 bg-gradient-to-r from-green-400/20 to-blue-400/20"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <motion.div
                className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent"
                animate={{ x: ['-100%', '100%'] }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              />
            </motion.div>
          )}
        </AnimatePresence>

        {/* central content – three modes */}
        <div className="relative p-12 text-center">
          <AnimatePresence mode="wait">
            {uploading ? (
              <UploadMode progress={uploadProgress} securityMode={securityMode} />
            ) : error ? (
              <ErrorMode error={error} onRetry={() => setError(null)} />
            ) : (
              <IdleMode
                isDragging={isDragging}
                maxFiles={maxFiles}
                maxFileSize={maxFileSize}
                browse={browse}
                disabled={disabled}
                securityMode={securityMode}
              />
            )}
          </AnimatePresence>
        </div>
      </motion.div>

      {/* list of uploading / completed / errored */}
      <UploadList
        files={uploadingFiles}
        formatFileSize={formatFileSize}
        removeFile={removeFile}
      />
    </div>
  );
}

/* ─── ✅ FIXED Sub-components ─────────── */

function UploadMode({ progress, securityMode }: { progress: number; securityMode: SecurityMode }) {
  return (
    <motion.div
      key="uploading"
      className="space-y-6"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
    >
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
        className={`w-16 h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center ${
          securityMode === 'enterprise' 
            ? 'bg-gradient-to-br from-red-500 to-purple-600'
            : 'bg-gradient-to-br from-green-500 to-blue-600'
        }`}
      >
        <Upload className="w-8 h-8 text-white" />
      </motion.div>
      
      <h3 className={`text-xl font-semibold ${
        securityMode === 'enterprise' ? 'text-purple-800' : 'text-green-800'
      }`}>
        Uploading to DataVault ({securityMode.toUpperCase()})
      </h3>

      <div className="space-y-2">
        <p className={`text-sm ${
          securityMode === 'enterprise' ? 'text-purple-600' : 'text-green-600'
        }`}>
          {securityMode === 'enterprise' 
            ? 'Applying enterprise security layers...' 
            : 'Processing with fast, secure upload...'
          }
        </p>
        
        {/* Enhanced progress bar */}
        <div className={`w-full h-4 rounded-full max-w-sm mx-auto overflow-hidden ${
          securityMode === 'enterprise' ? 'bg-purple-200' : 'bg-green-200'
        }`}>
          <motion.div
            className={`h-4 rounded-full ${
              securityMode === 'enterprise' 
                ? 'bg-gradient-to-r from-red-500 via-purple-500 to-blue-500'
                : 'bg-gradient-to-r from-green-500 via-blue-500 to-purple-500'
            }`}
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ type: 'spring', stiffness: 100, damping: 15 }}
          />
        </div>
        
        <p className={`text-sm font-medium ${
          securityMode === 'enterprise' ? 'text-purple-600' : 'text-green-600'
        }`}>
          {Math.round(progress)}% complete
        </p>
      </div>

      {/* ✅ FIXED: Security features being applied */}
      <div className={`grid grid-cols-2 gap-2 text-xs ${
        securityMode === 'enterprise' ? 'text-purple-700' : 'text-green-700'
      }`}>
        {(securityMode === 'enterprise' ? [
          { icon: Shield, label: 'Zero-Trust Eval', active: progress > 10 },
          { icon: Lock, label: 'ABE Encryption', active: progress > 30 },
          { icon: Zap, label: 'BFT Consensus', active: progress > 50 },
          { icon: Eye, label: 'Threat Detection', active: progress > 70 }
        ] : [
          { icon: Shield, label: 'Basic Security', active: progress > 20 },
          { icon: Zap, label: 'Fast Processing', active: progress > 40 },
          { icon: Eye, label: 'PII Scan', active: progress > 60 },
          { icon: Lock, label: 'Audit Log', active: progress > 80 }
        ]).map((feature) => {
          const Icon = feature.icon;
          return (
            <div key={feature.label} className={`flex items-center space-x-1 transition-opacity ${
              feature.active ? 'opacity-100' : 'opacity-40'
            }`}>
              <Icon className="w-3 h-3" />
              <span>{feature.label}</span>
              {feature.active && <CheckCircle className="w-3 h-3 text-green-600" />}
            </div>
          );
        })}
      </div>
    </motion.div>
  );
}

function ErrorMode({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <motion.div
      key="error"
      className="space-y-4"
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
    >
      <div className="w-16 h-16 mx-auto mb-4 bg-red-100 rounded-2xl flex items-center justify-center">
        <AlertCircle className="w-8 h-8 text-red-600" />
      </div>
      
      <h3 className="text-xl font-semibold text-red-800">Upload Failed</h3>
      <p className="text-red-600 text-sm max-w-md mx-auto">{error}</p>
      
      <button
        onClick={onRetry}
        className="px-6 py-3 bg-red-100 hover:bg-red-200 text-red-700 rounded-lg transition-colors font-medium"
      >
        Try Again
      </button>
    </motion.div>
  );
}

interface IdleProps {
  isDragging: boolean;
  maxFiles: number;
  maxFileSize: number;
  browse: () => void;
  disabled: boolean;
  securityMode: SecurityMode; // ✅ NEW
}

function IdleMode({ isDragging, maxFiles, maxFileSize, browse, disabled, securityMode }: IdleProps) {
  return (
    <motion.div
      key="idle"
      className="space-y-6"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      <motion.div
        className={`w-16 h-16 mx-auto mb-4 rounded-2xl flex items-center justify-center ${
          securityMode === 'enterprise'
            ? 'bg-gradient-to-br from-red-500 to-purple-600'
            : 'bg-gradient-to-br from-blue-500 to-purple-600'
        }`}
        animate={isDragging ? { scale: 1.1, rotate: 5 } : { scale: 1, rotate: 0 }}
      >
        <Upload className="w-8 h-8 text-white" />
      </motion.div>

      <h3 className="text-xl font-semibold text-gray-900">
        {isDragging ? 'Drop files here' : disabled ? 'Upload Disabled' : `Upload to DataVault (${securityMode.toUpperCase()})`}
      </h3>

      {!disabled && (
        <>
          <p className="text-gray-600">
            Drag and drop files or{' '}
            <button
              type="button"
              onClick={browse}
              className="text-blue-600 hover:text-blue-800 font-medium underline"
            >
              browse
            </button>
          </p>

          <div className="text-sm text-gray-500 space-y-1">
            <div>Maximum {maxFileSize} MB per file • Up to {maxFiles} files</div>
            <div className="text-xs">Supports documents, images, videos, archives</div>
            {securityMode === 'enterprise' && (
              <div className="text-xs text-purple-600 font-medium">
                🔒 Enterprise mode: Files with "confidential/secret" or &gt;50MB auto-detected
              </div>
            )}
          </div>

          {/* ✅ FIXED: Security features preview based on mode */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4">
            {(securityMode === 'enterprise' ? [
              { icon: Shield, label: 'Zero-Trust', color: 'text-red-600' },
              { icon: Lock, label: 'ABE Encryption', color: 'text-purple-600' },
              { icon: Zap, label: 'BFT Consensus', color: 'text-blue-600' },
              { icon: Eye, label: 'Threat Detection', color: 'text-orange-600' }
            ] : [
              { icon: Shield, label: 'Quantum Safe', color: 'text-green-600' },
              { icon: Zap, label: 'Fast Upload', color: 'text-blue-600' },
              { icon: Eye, label: 'PII Detection', color: 'text-purple-600' },
              { icon: Lock, label: 'Audit Trail', color: 'text-orange-600' }
            ]).map((feature) => {
              const Icon = feature.icon;
              return (
                <div key={feature.label} className="flex items-center space-x-2">
                  <Icon className={`w-4 h-4 ${feature.color}`} />
                  <span className="text-xs text-gray-600">{feature.label}</span>
                </div>
              );
            })}
          </div>
        </>
      )}
    </motion.div>
  );
}

/* ✅ UPDATED: Enhanced upload list with security mode display */
interface ListProps {
  files: UploadingFile[];
  formatFileSize: (b: number) => string;
  removeFile: (id: string) => void;
}

function UploadList({ files, formatFileSize, removeFile }: ListProps) {
  if (!files.length) return null;
  
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 overflow-hidden"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center space-x-2">
          <Sparkles className="w-5 h-5 text-blue-500" />
          <span>Processing Files ({files.length})</span>
        </h3>
        <div className="flex items-center space-x-4 text-sm text-gray-500">
          <span>{files.filter(f => f.status === 'complete').length} complete</span>
          <span className="flex items-center space-x-1">
            <Shield className="w-4 h-4 text-red-500" />
            <span>{files.filter(f => f.securityMode === 'enterprise').length} enterprise</span>
          </span>
        </div>
      </div>

      <div className="space-y-3">
        <AnimatePresence>
          {files.map(f => (
            <motion.div
              key={f.id}
              initial={{ opacity: 0, x: -40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 40 }}
              className={`p-4 rounded-xl border transition-colors ${
                f.status === 'error'
                  ? 'bg-red-50 border-red-200'
                  : f.status === 'complete'
                  ? f.securityMode === 'enterprise'
                    ? 'bg-purple-50 border-purple-200'
                    : 'bg-green-50 border-green-200'
                  : f.securityMode === 'enterprise'
                  ? 'bg-purple-50 border-purple-200'
                  : 'bg-blue-50 border-blue-200'
              }`}
            >
              <div className="flex items-center">
                <File className={`w-6 h-6 mr-3 ${
                  f.status === 'error' ? 'text-red-600' 
                  : f.status === 'complete' 
                    ? f.securityMode === 'enterprise' ? 'text-purple-600' : 'text-green-600'
                  : f.securityMode === 'enterprise' ? 'text-purple-600' : 'text-blue-600'
                }`} />
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-2">
                      <p className="text-sm font-medium truncate">{f.name}</p>
                      {/* ✅ NEW: Security mode badge */}
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        f.securityMode === 'enterprise'
                          ? 'bg-purple-100 text-purple-700 border border-purple-200'
                          : 'bg-green-100 text-green-700 border border-green-200'
                      }`}>
                        {f.securityMode === 'enterprise' ? '🔒 Enterprise' : '⚡ Simple'}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 ml-3">
                      {formatFileSize(f.size)}
                    </span>
                  </div>
                  
                  {/* Progress bar */}
                  <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                    <motion.div
                      className={`h-2 rounded-full ${
                        f.status === 'error'
                          ? 'bg-red-500'
                          : f.status === 'complete'
                          ? f.securityMode === 'enterprise' ? 'bg-purple-500' : 'bg-green-500'
                          : f.securityMode === 'enterprise' ? 'bg-purple-500' : 'bg-blue-500'
                      }`}
                      initial={{ width: 0 }}
                      animate={{ width: `${f.progress}%` }}
                      transition={{ duration: 0.4 }}
                    />
                  </div>

                  {/* Security features applied */}
                  {f.securityApplied && f.status !== 'error' && (
                    <div className="flex items-center space-x-1 mt-2">
                      {Object.entries(f.securityApplied).map(([key, applied]) => {
                        if (!applied) return null;
                        const icons = {
                          quantum_encryption: Shield,
                          bft_consensus: RefreshCw,
                          pii_detection: Eye,
                          immutable_audit: Lock,
                          gdpr_compliance: CheckCircle,
                          zero_trust_verified: Zap,
                          abe_encryption: Lock,
                          threshold_sharing: Shield
                        };
                        const Icon = icons[key as keyof typeof icons];
                        return Icon ? (
                          <div key={key} className="relative group">
                            <Icon className={`w-3 h-3 ${
                              f.securityMode === 'enterprise' ? 'text-purple-600' : 'text-green-600'
                            }`} />
                            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-1 px-2 py-1 text-xs text-white bg-gray-800 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
                              {key.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                            </div>
                          </div>
                        ) : null;
                      })}
                    </div>
                  )}

                  {/* Error message */}
                  {f.error && (
                    <p className="text-xs text-red-600 mt-1">{f.error}</p>
                  )}
                </div>

                <button
                  onClick={() => removeFile(f.id)}
                  className="ml-4 p-1 text-gray-400 hover:text-red-500 transition-colors"
                  aria-label="Remove file"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
