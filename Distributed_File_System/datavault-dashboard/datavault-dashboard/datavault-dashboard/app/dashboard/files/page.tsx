'use client';

import { motion } from 'framer-motion';
import { useState, useCallback } from 'react';
import { 
  Upload, 
  File, 
  Folder, 
  Search, 
  Shield, 
  Clock, 
  Users, 
  MoreVertical,
  Download,
  Share,
  Lock
} from 'lucide-react';

interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size: string;
  lastModified: string;
  owner: string;
  securityLevel: 'public' | 'confidential' | 'classified';
  collaborators: number;
}

const mockFiles: FileItem[] = [
  {
    id: '1',
    name: 'Q4 Financial Reports',
    type: 'folder',
    size: '2.4 GB',
    lastModified: '2 hours ago',
    owner: 'John Smith',
    securityLevel: 'confidential',
    collaborators: 8
  },
  {
    id: '2',
    name: 'Medical Research Data.pdf',
    type: 'file',
    size: '15.2 MB',
    lastModified: '1 day ago',
    owner: 'Dr. Sarah Johnson',
    securityLevel: 'classified',
    collaborators: 3
  },
  {
    id: '3',
    name: 'Project Quantum Specs',
    type: 'folder',
    size: '1.8 GB',
    lastModified: '3 days ago',
    owner: 'Alice Chen',
    securityLevel: 'classified',
    collaborators: 12
  }
];

export default function FilesPage() {
  const [files, setFiles] = useState<FileItem[]>(mockFiles);
  const [searchQuery, setSearchQuery] = useState('');
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    console.log('Files dropped:', droppedFiles);
    
    // Here you would implement actual file upload logic
    // For now, we'll just simulate adding to the list
    droppedFiles.forEach((file, index) => {
      const newFile: FileItem = {
        id: Date.now().toString() + index,
        name: file.name,
        type: 'file',
        size: (file.size / 1024 / 1024).toFixed(1) + ' MB',
        lastModified: 'Just now',
        owner: 'You',
        securityLevel: 'confidential',
        collaborators: 1
      };
      setFiles(prev => [newFile, ...prev]);
    });
  }, []);

  const getSecurityColor = (level: string) => {
    switch (level) {
      case 'public': return 'text-green-400 bg-green-400/20';
      case 'confidential': return 'text-yellow-400 bg-yellow-400/20';
      case 'classified': return 'text-red-400 bg-red-400/20';
      default: return 'text-gray-400 bg-gray-400/20';
    }
  };

  const filteredFiles = files.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
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
          <h1 className="text-3xl font-bold text-white mb-2">Secure File Vault</h1>
          <p className="text-gray-400">Quantum-encrypted file storage and collaboration</p>
        </div>
        <div className="flex items-center space-x-4">
          <motion.button
            className="bg-gradient-to-r from-blue-600 to-purple-600 text-white px-6 py-3 rounded-lg font-semibold hover:from-blue-700 hover:to-purple-700 transition-all flex items-center space-x-2"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Upload className="w-5 h-5" />
            <span>Upload Files</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Search Bar */}
      <motion.div
        className="relative"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-12 pr-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all backdrop-blur-md"
          placeholder="Search files and folders with encrypted content indexing..."
        />
      </motion.div>

      {/* Upload Zone */}
      <motion.div
        className={`border-2 border-dashed rounded-2xl p-12 text-center transition-all ${
          isDragging 
            ? 'border-blue-400 bg-blue-400/10' 
            : 'border-gray-600 hover:border-gray-500'
        }`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <motion.div
          animate={{ scale: isDragging ? 1.1 : 1 }}
          transition={{ duration: 0.2 }}
        >
          <Upload className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">
            {isDragging ? 'Drop files here' : 'Drag & drop files here'}
          </h3>
          <p className="text-gray-400 mb-4">
            Files are automatically encrypted with quantum-resistant algorithms
          </p>
          <div className="flex items-center justify-center space-x-6 text-sm text-gray-500">
            <div className="flex items-center space-x-1">
              <Shield className="w-4 h-4" />
              <span>AES-256 + Quantum</span>
            </div>
            <div className="flex items-center space-x-1">
              <Lock className="w-4 h-4" />
              <span>Zero-Trust Access</span>
            </div>
            <div className="flex items-center space-x-1">
              <Users className="w-4 h-4" />
              <span>Real-time Collaboration</span>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Files List */}
      <motion.div
        className="bg-white/10 backdrop-blur-md rounded-2xl border border-white/20 overflow-hidden"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <div className="p-6 border-b border-white/20">
          <h3 className="text-lg font-semibold text-white">Recent Files & Folders</h3>
        </div>
        
        <div className="divide-y divide-white/10">
          {filteredFiles.map((file, index) => (
            <motion.div
              key={file.id}
              className="p-6 hover:bg-white/5 transition-colors cursor-pointer"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.1 * index }}
              whileHover={{ x: 5 }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="p-3 bg-blue-500/20 rounded-lg">
                    {file.type === 'folder' ? (
                      <Folder className="w-6 h-6 text-blue-400" />
                    ) : (
                      <File className="w-6 h-6 text-blue-400" />
                    )}
                  </div>
                  
                  <div>
                    <h4 className="font-semibold text-white">{file.name}</h4>
                    <div className="flex items-center space-x-4 text-sm text-gray-400 mt-1">
                      <span>{file.size}</span>
                      <span>•</span>
                      <span>Modified {file.lastModified}</span>
                      <span>•</span>
                      <span>by {file.owner}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-4">
                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSecurityColor(file.securityLevel)}`}>
                    {file.securityLevel.toUpperCase()}
                  </span>
                  
                  <div className="flex items-center space-x-1 text-gray-400">
                    <Users className="w-4 h-4" />
                    <span className="text-sm">{file.collaborators}</span>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <motion.button
                      className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <Download className="w-4 h-4" />
                    </motion.button>
                    <motion.button
                      className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <Share className="w-4 h-4" />
                    </motion.button>
                    <motion.button
                      className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                      whileHover={{ scale: 1.1 }}
                      whileTap={{ scale: 0.9 }}
                    >
                      <MoreVertical className="w-4 h-4" />
                    </motion.button>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Security Info */}
      <motion.div
        className="bg-gradient-to-r from-green-900/20 to-emerald-900/20 border border-green-500/30 rounded-2xl p-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <div className="flex items-center space-x-3 mb-4">
          <Shield className="w-6 h-6 text-green-400" />
          <h3 className="text-lg font-semibold text-green-400">Enterprise Security Features</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <h4 className="font-semibold text-white mb-2">Quantum-Resistant Encryption</h4>
            <p className="text-gray-300 text-sm">All files protected with CRYSTALS-Dilithium post-quantum cryptography</p>
          </div>
          <div>
            <h4 className="font-semibold text-white mb-2">Real-time Collaboration</h4>
            <p className="text-gray-300 text-sm">Secure document sharing with operational transforms and conflict resolution</p>
          </div>
          <div>
            <h4 className="font-semibold text-white mb-2">Encrypted Search</h4>
            <p className="text-gray-300 text-sm">Advanced content indexing with homomorphic encryption for privacy</p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
