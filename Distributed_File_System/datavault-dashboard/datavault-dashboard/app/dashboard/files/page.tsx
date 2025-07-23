'use client';

import { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { 
  Upload, 
  File, 
  Folder, 
  Download, 
  Share, 
  Lock, 
  Shield,
  Search,
  Filter,
  MoreVertical,
  Eye,
  Trash2
} from 'lucide-react';
import { useDropzone } from 'react-dropzone';

interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size: string;
  modified: string;
  encrypted: boolean;
  shared: boolean;
  compliance: string[];
}

const mockFiles: FileItem[] = [
  {
    id: '1',
    name: 'Patient_Records_Q1_2025.pdf',
    type: 'file',
    size: '15.2 MB',
    modified: '2 hours ago',
    encrypted: true,
    shared: false,
    compliance: ['HIPAA', 'GDPR']
  },
  {
    id: '2',
    name: 'Financial_Reports',
    type: 'folder',
    size: '245 MB',
    modified: '1 day ago',
    encrypted: true,
    shared: true,
    compliance: ['SOX', 'PCI-DSS']
  },
  {
    id: '3',
    name: 'Employee_Contracts.zip',
    type: 'file',
    size: '8.7 MB',
    modified: '3 days ago',
    encrypted: true,
    shared: false,
    compliance: ['GDPR']
  }
];

export default function FilesPage() {
  const [files, setFiles] = useState<FileItem[]>(mockFiles);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    acceptedFiles.forEach((file) => {
      const newFile: FileItem = {
        id: Date.now().toString(),
        name: file.name,
        type: 'file',
        size: `${(file.size / 1024 / 1024).toFixed(1)} MB`,
        modified: 'Just now',
        encrypted: true,
        shared: false,
        compliance: ['Auto-detected']
      };
      setFiles(prev => [newFile, ...prev]);
    });
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: true
  });

  const filteredFiles = files.filter(file =>
    file.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <motion.div
        className="flex items-center justify-between"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div>
          <h1 className="text-3xl font-bold neon-text">Secure File Vault</h1>
          <p className="text-gray-400 mt-1">Enterprise file storage with quantum encryption</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-400">
            Total: {files.length} files • Encrypted: 100%
          </div>
        </div>
      </motion.div>

      {/* Upload Area */}
      <motion.div
        {...getRootProps()}
        className={`cyber-card rounded-2xl p-8 border-2 border-dashed transition-all cursor-pointer ${
          isDragActive 
            ? 'border-cyan-400 bg-cyan-500/10' 
            : 'border-cyan-500/30 hover:border-cyan-400/50'
        }`}
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.2 }}
        whileHover={{ scale: 1.02 }}
      >
        <input {...getInputProps()} />
        <div className="text-center">
          <motion.div
            className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyan-500/20 mb-4"
            animate={{ y: isDragActive ? -5 : 0 }}
          >
            <Upload className="w-8 h-8 text-cyan-400" />
          </motion.div>
          <h3 className="text-xl font-semibold text-white mb-2">
            {isDragActive ? 'Drop files here...' : 'Upload Secure Files'}
          </h3>
          <p className="text-gray-400 mb-4">
            Drag & drop files or click to browse. All files are automatically encrypted.
          </p>
          <div className="flex items-center justify-center space-x-4 text-sm text-gray-500">
            <div className="flex items-center">
              <Shield className="w-4 h-4 mr-1 text-green-400" />
              Quantum Encrypted
            </div>
            <div className="flex items-center">
              <Lock className="w-4 h-4 mr-1 text-blue-400" />
              GDPR Compliant
            </div>
          </div>
        </div>
      </motion.div>

      {/* Search and Filters */}
      <motion.div
        className="flex items-center space-x-4"
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.4 }}
      >
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search files..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-gray-800/50 border border-cyan-500/30 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400"
          />
        </div>
        <button className="cyber-button">
          <Filter className="w-4 h-4 mr-2" />
          Filter
        </button>
      </motion.div>

      {/* File List */}
      <motion.div
        className="cyber-card rounded-2xl overflow-hidden"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
      >
        <div className="p-4 border-b border-cyan-500/30">
          <h3 className="text-lg font-semibold text-white">Files & Folders</h3>
        </div>
        
        <div className="divide-y divide-gray-700/50">
          {filteredFiles.map((file, index) => (
            <motion.div
              key={file.id}
              className="p-4 hover:bg-cyan-500/5 transition-colors group"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <div className="flex items-center space-x-4">
                {/* File Icon */}
                <div className="flex-shrink-0">
                  {file.type === 'folder' ? (
                    <Folder className="w-8 h-8 text-blue-400" />
                  ) : (
                    <File className="w-8 h-8 text-cyan-400" />
                  )}
                </div>

                {/* File Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2">
                    <h4 className="text-white font-medium truncate">{file.name}</h4>
                    {file.encrypted && (
                      <Shield className="w-4 h-4 text-green-400" title="Encrypted" />
                    )}
                    {file.shared && (
                      <Share className="w-4 h-4 text-blue-400" title="Shared" />
                    )}
                  </div>
                  <div className="flex items-center space-x-4 mt-1 text-sm text-gray-400">
                    <span>{file.size}</span>
                    <span>Modified {file.modified}</span>
                    <div className="flex space-x-1">
                      {file.compliance.map((comp) => (
                        <span
                          key={comp}
                          className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs"
                        >
                          {comp}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
                    <Eye className="w-4 h-4 text-gray-400" />
                  </button>
                  <button className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
                    <Download className="w-4 h-4 text-gray-400" />
                  </button>
                  <button className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
                    <Share className="w-4 h-4 text-gray-400" />
                  </button>
                  <button className="p-2 hover:bg-gray-700 rounded-lg transition-colors">
                    <MoreVertical className="w-4 h-4 text-gray-400" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
}
