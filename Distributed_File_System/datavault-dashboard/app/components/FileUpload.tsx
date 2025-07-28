'use client';

import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, X, CheckCircle, AlertCircle, File } from 'lucide-react';
import { FileItem } from '../types';
import { FileUploadService } from '../lib/fileUpload';

interface FileUploadProps {
  onFilesUploaded: (files: FileItem[]) => void;
  maxFiles?: number;
  maxFileSize?: number; // in MB
}

export default function FileUpload({ 
  onFilesUploaded, 
  maxFiles = 10, 
  maxFileSize = 100 
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadingFiles, setUploadingFiles] = useState<FileItem[]>([]);

  const fileUploadService = FileUploadService.getInstance();

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDragIn = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragOut = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    handleFiles(files);
  }, []);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      handleFiles(files);
    }
  }, []);

  const handleFiles = async (files: File[]) => {
    // Validate files
    const validFiles = files.filter(file => {
      if (file.size > maxFileSize * 1024 * 1024) {
        alert(`File ${file.name} is too large. Maximum size is ${maxFileSize}MB.`);
        return false;
      }
      return true;
    }).slice(0, maxFiles);

    if (validFiles.length === 0) return;

    try {
      // Upload files one by one
      const uploadedFileItems: FileItem[] = [];
      
      for (let i = 0; i < validFiles.length; i++) {
        const file = validFiles[i];

        // Create initial file item for UI
        const initialFileItem: FileItem = {
          id: Date.now().toString() + i,
          name: file.name,
          type: 'file',
          size: file.size,
          lastModified: new Date(),
          owner: 'Current User',
          compliance: 'GDPR',
          encrypted: true,
          shared: false,
          status: 'uploading',
          progress: 0
        };

        setUploadingFiles(prev => [...prev, initialFileItem]);

        const uploadedFile = await fileUploadService.uploadFile(
          file,
          (progress) => {
            setUploadingFiles(prev => 
              prev.map(f => 
                f.id === initialFileItem.id 
                  ? { ...f, progress, status: progress === 100 ? 'complete' : 'uploading' }
                  : f
              )
            );
          }
        );

        uploadedFileItems.push(uploadedFile);
      }

      // Remove completed files from uploading list
      setTimeout(() => {
        setUploadingFiles(prev => prev.filter(f => !uploadedFileItems.find(uf => uf.name === f.name)));
      }, 2000);
      
      // Notify parent
      onFilesUploaded(uploadedFileItems);

    } catch (error) {
      console.error('Upload failed:', error);
      setUploadingFiles(prev => 
        prev.map(f => ({ ...f, status: 'error' as const }))
      );
    }
  };

  const removeFile = (fileId: string) => {
    setUploadingFiles(prev => prev.filter(f => f.id !== fileId));
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      {/* Upload Zone */}
      <div
        className={`apple-card border-2 border-dashed transition-all duration-300 cursor-pointer ${
          isDragging 
            ? 'border-blue-500 bg-blue-50' 
            : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="p-12 text-center">
          <input
            type="file"
            multiple
            onChange={handleFileInput}
            className="hidden"
            id="file-upload"
          />
          
          <motion.div
            animate={{ scale: isDragging ? 1.05 : 1 }}
            transition={{ duration: 0.2 }}
          >
            <Upload className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-gray-900 mb-2">
              {isDragging ? 'Drop files here' : 'Upload Files'}
            </h3>
            <p className="text-gray-600 mb-6">
              Drag and drop files here, or{' '}
              <label htmlFor="file-upload" className="text-blue-600 hover:text-blue-700 cursor-pointer font-medium">
                browse
              </label>
            </p>
            <div className="text-sm text-gray-500">
              Maximum file size: {maxFileSize}MB • Maximum files: {maxFiles}
            </div>
          </motion.div>
        </div>
      </div>

      {/* Upload Progress */}
      <AnimatePresence>
        {uploadingFiles.length > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="apple-card p-6"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Uploading Files ({uploadingFiles.length})
            </h3>
            <div className="space-y-3">
              {uploadingFiles.map((file) => (
                <motion.div
                  key={file.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="flex items-center space-x-4 p-3 bg-gray-50 rounded-lg"
                >
                  <File className="w-8 h-8 text-blue-600 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {file.name}
                    </p>
                    <div className="flex items-center space-x-2 mt-1">
                      <div className="flex-1 apple-progress">
                        <motion.div
                          className="apple-progress-fill"
                          initial={{ width: 0 }}
                          animate={{ width: `${file.progress || 0}%` }}
                          transition={{ duration: 0.3 }}
                        />
                      </div>
                      <span className="text-xs text-gray-500">
                        {Math.round(file.progress || 0)}%
                      </span>
                    </div>
                    {file.size && (
                      <p className="text-xs text-gray-500">
                        {formatFileSize(file.size)}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center space-x-2">
                    {file.status === 'complete' && (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    )}
                    {file.status === 'error' && (
                      <AlertCircle className="w-5 h-5 text-red-500" />
                    )}
                    <button
                      onClick={() => removeFile(file.id)}
                      className="p-1 text-gray-400 hover:text-red-500 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
