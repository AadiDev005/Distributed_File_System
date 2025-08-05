/* FileUpload.tsx – fully optimised */
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
  Zap
} from 'lucide-react';

/* ─── types ──────────────────────────────────────────────── */

interface FileUploadProps {
  onFilesUploaded: (files: FileList) => Promise<void> | void;
  maxFiles?: number;          // default 10
  maxFileSize?: number;       // MB – default 100
  uploading?: boolean;        // comes from parent
  uploadProgress?: number;    // comes from parent
}

type UploadStatus = 'uploading' | 'complete' | 'error';

interface UploadingFile {
  id: string;
  name: string;
  size: number;
  progress: number;
  status: UploadStatus;
  error?: string;
}

/* ─── component ──────────────────────────────────────────── */

export default function FileUpload({
  onFilesUploaded,
  maxFiles = 10,
  maxFileSize = 100,
  uploading = false,
  uploadProgress = 0
}: FileUploadProps) {
  /* state */
  const [isDragging, setIsDragging] = useState(false);
  const [dragCounter, setDragCounter] = useState(0);
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([]);
  const [error, setError] = useState<string | null>(null);

  /* refs */
  const fileInputRef = useRef<HTMLInputElement>(null);
  const progressIntervalRef = useRef<NodeJS.Timeout | null>(null);

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
        '.txt', '.csv', '.md', '.json', '.html', '.css', '.js',
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
        '.zip', '.rar'
      ].join(','),
    []
  );

  /* ── validation ──────────────────────────────────────── */

  const validateFiles = useCallback(
    (files: FileList): string | null => {
      if (files.length === 0) return 'No files selected';
      if (files.length > maxFiles)
        return `Maximum ${maxFiles} files allowed (you selected ${files.length}).`;

      for (const file of Array.from(files)) {
        const sizeMB = file.size / 1_048_576; // 1024^2
        if (sizeMB > maxFileSize)
          return `File “${file.name}” (${sizeMB.toFixed(
            2
          )} MB) exceeds ${maxFileSize} MB limit`;
        if (file.size === 0)
          return `File “${file.name}” is empty and cannot be uploaded`;
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
      setDragCounter(c => c + 1);
      if (e.dataTransfer.items?.length) {
        if (!uploading) setIsDragging(true);
      }
    },
    [uploading]
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
      if (uploading) return;
      if (e.dataTransfer.files?.length) handleFiles(e.dataTransfer.files);
    },
    [uploading]
  );

  /* ── file-input handler ──────────────────────────────── */

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.length) handleFiles(e.target.files);
  };

  /* ── browse button ───────────────────────────────────── */

  const browse = () => {
    if (!uploading) fileInputRef.current?.click();
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
        return;
      }

      /* build local tracking list */
      const tracked: UploadingFile[] = Array.from(files).map((f, i) => ({
        id: `${Date.now()}_${i}_${f.name}`,
        name: f.name,
        size: f.size,
        progress: 0,
        status: 'uploading'
      }));
      setUploadingFiles(tracked);

      /* fake progress until backend updates parent */
      progressIntervalRef.current = setInterval(() => {
        setUploadingFiles(prev =>
          prev.map(f =>
            f.status === 'uploading'
              ? { ...f, progress: Math.min(f.progress + Math.random() * 10 + 5, 88) }
              : f
          )
        );
      }, 180);

      try {
        await onFilesUploaded(files);
        clearInterval(progressIntervalRef.current!);
        progressIntervalRef.current = null;

        /* mark complete staggered */
        tracked.forEach((_, i) =>
          setTimeout(() => {
            setUploadingFiles(prev =>
              prev.map((f, idx) =>
                idx === i ? { ...f, progress: 100, status: 'complete' } : f
              )
            );
          }, i * 120)
        );

        /* auto-clear after display */
        setTimeout(() => {
          fileInputRef.current && (fileInputRef.current.value = '');
          setUploadingFiles([]);
        }, tracked.length * 120 + 2_000);
      } catch (err) {
        clearInterval(progressIntervalRef.current!);
        progressIntervalRef.current = null;
        const msg =
          err instanceof Error ? err.message : 'Unexpected upload error';

        tracked.forEach((_, i) =>
          setTimeout(() => {
            setUploadingFiles(prev =>
              prev.map((f, idx) =>
                idx === i ? { ...f, status: 'error', error: msg, progress: 0 } : f
              )
            );
          }, i * 100)
        );
        setError(msg);
      }
    },
    [onFilesUploaded, validateFiles]
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
      {/* ───── Drop zone ───── */}
      <motion.div
        className={`apple-card border-2 border-dashed cursor-pointer relative overflow-hidden transition-all ${
          isDragging
            ? 'border-blue-500 bg-blue-50 shadow-lg scale-[1.02]'
            : uploading
            ? 'border-green-500 bg-green-50 shadow-md'
            : error
            ? 'border-red-500 bg-red-50 shadow-md'
            : 'border-gray-300 hover:border-gray-400 hover:bg-gray-50'
        }`}
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={stop}
        onDrop={handleDrop}
        whileHover={{ scale: uploading ? 1 : 1.01 }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      >
        {/* hidden native input */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          onChange={handleFileInput}
          disabled={uploading}
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
          {/* 1. uploading */}
          <AnimatePresence mode="wait">
            {uploading ? (
              <UploadMode progress={uploadProgress} />
            ) : error ? (
              /* 2. error */
              <ErrorMode error={error} onRetry={() => setError(null)} />
            ) : (
              /* 3. idle */
              <IdleMode
                isDragging={isDragging}
                maxFiles={maxFiles}
                maxFileSize={maxFileSize}
                browse={browse}
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

/* ─── sub-components (kept outside main render for clarity) ─────────── */

function UploadMode({ progress }: { progress: number }) {
  return (
    <motion.div
      key="uploading"
      className="space-y-6"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
    >
      <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}>
        <Upload className="w-16 h-16 text-green-600 mx-auto" />
      </motion.div>
      <h3 className="text-xl font-semibold text-green-800">
        Uploading to DataVault Network…
      </h3>

      {/* progress bar */}
      <div className="w-full bg-green-200 h-4 rounded-full max-w-xs mx-auto overflow-hidden">
        <motion.div
          className="bg-gradient-to-r from-green-500 to-blue-500 h-4 rounded-full"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ type: 'spring', stiffness: 100, damping: 15 }}
        />
      </div>
      <p className="text-sm text-green-600">{progress}% complete</p>
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
      <AlertCircle className="w-16 h-16 text-red-500 mx-auto" />
      <h3 className="text-xl font-semibold text-red-800">Upload Error</h3>
      <p className="text-red-600">{error}</p>
      <button
        onClick={onRetry}
        className="px-6 py-3 bg-red-100 hover:bg-red-200 text-red-700 rounded-lg transition"
      >
        Try again
      </button>
    </motion.div>
  );
}

interface IdleProps {
  isDragging: boolean;
  maxFiles: number;
  maxFileSize: number;
  browse: () => void;
}
function IdleMode({ isDragging, maxFiles, maxFileSize, browse }: IdleProps) {
  return (
    <motion.div
      key="idle"
      className="space-y-4"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -10 }}
    >
      <Upload
        className={`w-16 h-16 mx-auto ${
          isDragging ? 'text-blue-600 scale-110' : 'text-gray-400'
        } transition`}
      />
      <h3 className="text-xl font-semibold text-gray-900">
        {isDragging ? 'Drop files here' : 'Upload files to DataVault'}
      </h3>
      <p className="text-gray-600">
        Drag & drop, or{' '}
        <button
          type="button"
          onClick={browse}
          className="text-blue-600 underline font-medium"
        >
          browse
        </button>
      </p>
      <div className="text-sm text-gray-500">
        Max {maxFileSize} MB • {maxFiles} files
      </div>
    </motion.div>
  );
}

/* list component */
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
      className="apple-card p-6 overflow-hidden"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold flex items-center space-x-2">
          <Sparkles className="w-5 h-5 text-blue-500" />
          <span>Processing Files ({files.length})</span>
        </h3>
        <span className="text-sm text-gray-500">
          {files.filter(f => f.status === 'complete').length} complete
        </span>
      </div>

      <div className="space-y-3">
        <AnimatePresence>
          {files.map(f => (
            <motion.div
              key={f.id}
              initial={{ opacity: 0, x: -40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 40 }}
              className="flex items-center p-4 rounded-xl bg-blue-50 border border-blue-200"
            >
              <File className="w-6 h-6 text-blue-600 mr-3" />
              <div className="flex-1">
                <p className="text-sm font-medium truncate">{f.name}</p>
                <div className="h-2 bg-gray-200 rounded-full mt-2 overflow-hidden">
                  <motion.div
                    className={`h-2 rounded-full ${
                      f.status === 'error'
                        ? 'bg-red-500'
                        : f.status === 'complete'
                        ? 'bg-green-500'
                        : 'bg-blue-500'
                    }`}
                    initial={{ width: 0 }}
                    animate={{ width: `${f.progress}%` }}
                    transition={{ duration: 0.4 }}
                  />
                </div>
              </div>
              <span className="text-xs text-gray-500 ml-3">
                {formatFileSize(f.size)}
              </span>
              <button
                onClick={() => removeFile(f.id)}
                className="ml-4 text-gray-400 hover:text-red-500"
                title="Remove"
              >
                <X className="w-4 h-4" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
