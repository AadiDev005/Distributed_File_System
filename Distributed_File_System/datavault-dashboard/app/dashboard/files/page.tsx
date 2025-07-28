'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';
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
  Shield
} from 'lucide-react';
import { FileItem } from '../../types';
import FileUpload from '../../components/FileUpload';

const initialFiles: FileItem[] = [
  {
    id: '1',
    name: 'Q4_Financial_Report.pdf',
    type: 'file',
    size: 2400000,
    lastModified: new Date('2025-01-15'),
    owner: 'John Smith',
    compliance: 'SOX',
    encrypted: true,
    shared: false,
    status: 'complete'
  },
  {
    id: '2',
    name: 'Patient_Records_2025',
    type: 'folder',
    lastModified: new Date('2025-01-14'),
    owner: 'Dr. Sarah Johnson',
    compliance: 'HIPAA',
    encrypted: true,
    shared: true,
    status: 'complete'
  },
  {
    id: '3',
    name: 'Government_Contract_Draft.docx',
    type: 'file',
    size: 856000,
    lastModified: new Date('2025-01-13'),
    owner: 'Michael Brown',
    compliance: 'GDPR',
    encrypted: true,
    shared: true,
    status: 'complete'
  },
  {
    id: '4',
    name: 'Payment_Processing_Data.xlsx',
    type: 'file',
    size: 1200000,
    lastModified: new Date('2025-01-12'),
    owner: 'Emma Davis',
    compliance: 'PCI-DSS',
    encrypted: true,
    shared: false,
    status: 'complete'
  }
];

export default function FilesPage() {
  const [files, setFiles] = useState<FileItem[]>(initialFiles);
  const [searchQuery, setSearchQuery] = useState('');

  const handleFilesUploaded = (newFiles: FileItem[]) => {
    setFiles(prev => [...newFiles, ...prev]);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const getComplianceColor = (compliance: string) => {
    switch (compliance) {
      case 'SOX': return 'bg-blue-100 text-blue-700';
      case 'HIPAA': return 'bg-green-100 text-green-700';
      case 'GDPR': return 'bg-purple-100 text-purple-700';
      case 'PCI-DSS': return 'bg-orange-100 text-orange-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  };

  const filteredFiles = files.filter(file => 
    file.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="apple-section">
        {/* Header */}
        <motion.div
          className="flex items-center justify-between mb-8"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div>
            <h1 className="apple-headline mb-2">Secure File Management</h1>
            <p className="apple-subheadline">
              Upload, share, and manage files with quantum-proof encryption
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <div className="text-sm text-gray-600">
              {files.length} files • All encrypted
            </div>
          </div>
        </motion.div>

        {/* File Upload Component */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-8"
        >
          <FileUpload
            onFilesUploaded={handleFilesUploaded}
            maxFiles={10}
            maxFileSize={100}
          />
        </motion.div>

        {/* Search and Filter Bar */}
        <motion.div
          className="flex items-center space-x-4 mb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="flex-1 relative">
            <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="apple-input pl-12"
              placeholder="Search files and folders..."
            />
          </div>
          <button className="apple-button-secondary">
            <Filter className="w-4 h-4 mr-2" />
            Filter
          </button>
        </motion.div>

        {/* Files List */}
        <motion.div
          className="apple-card overflow-hidden"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Files & Folders ({filteredFiles.length})</h2>
              <div className="flex items-center text-sm text-gray-600">
                <Shield className="w-4 h-4 mr-1 text-green-600" />
                All files quantum-encrypted
              </div>
            </div>
          </div>
          
          <div className="divide-y divide-gray-100">
            {filteredFiles.map((file, index) => (
              <motion.div
                key={file.id}
                className="p-6 hover:bg-gray-50 transition-colors apple-hover"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.1 * index }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                      {file.type === 'folder' ? (
                        <Folder className="w-5 h-5 text-blue-600" />
                      ) : (
                        <File className="w-5 h-5 text-blue-600" />
                      )}
                    </div>
                    
                    <div>
                      <h3 className="font-medium text-gray-900">{file.name}</h3>
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
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getComplianceColor(file.compliance)}`}>
                      {file.compliance}
                    </span>
                    
                    <div className="flex items-center space-x-1">
                      {file.encrypted && (
                        <div className="w-2 h-2 bg-green-500 rounded-full" title="Encrypted" />
                      )}
                      {file.shared && (
                        <div className="w-2 h-2 bg-blue-500 rounded-full" title="Shared" />
                      )}
                    </div>

                    <div className="flex items-center space-x-2">
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <Eye className="w-4 h-4" />
                      </motion.button>
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <Download className="w-4 h-4" />
                      </motion.button>
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <Share className="w-4 h-4" />
                      </motion.button>
                      <motion.button
                        className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                      >
                        <MoreHorizontal className="w-4 h-4" />
                      </motion.button>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Storage Statistics */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          {[
            { label: 'Total Files', value: files.length.toString(), icon: File, color: 'text-blue-600' },
            { label: 'Storage Used', value: '2.4 TB', icon: Folder, color: 'text-green-600' },
            { label: 'Shared Files', value: files.filter(f => f.shared).length.toString(), icon: Share, color: 'text-purple-600' },
            { label: 'Encrypted', value: '100%', icon: Shield, color: 'text-orange-600' }
          ].map((stat, index) => (
            <div key={stat.label} className="apple-card p-6 text-center apple-hover">
              <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </div>
              <div className="text-2xl font-semibold text-gray-900 mb-1">{stat.value}</div>
              <div className="text-sm text-gray-600">{stat.label}</div>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}
