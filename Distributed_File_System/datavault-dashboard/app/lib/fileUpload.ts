import { FileItem } from '../types';

export class FileUploadService {
  private static instance: FileUploadService;
  private uploadQueue: Map<string, FileItem> = new Map();

  static getInstance() {
    if (!FileUploadService.instance) {
      FileUploadService.instance = new FileUploadService();
    }
    return FileUploadService.instance;
  }

  async uploadFile(file: File, onProgress?: (progress: number) => void): Promise<FileItem> {
    const fileId = this.generateFileId();
    
    const fileItem: FileItem = {
      id: fileId,
      name: file.name,
      type: 'file',
      size: file.size,
      lastModified: new Date(),
      owner: 'Current User',
      compliance: this.detectCompliance(file.name),
      encrypted: true,
      shared: false,
      status: 'uploading',
      progress: 0
    };

    this.uploadQueue.set(fileId, fileItem);

    try {
      // Simulate file upload with progress
      await this.simulateUpload(fileId, onProgress);
      
      // Mark as complete
      fileItem.status = 'complete';
      fileItem.progress = 100;
      
      return fileItem;
    } catch (error) {
      fileItem.status = 'error';
      throw error;
    }
  }

  private async simulateUpload(fileId: string, onProgress?: (progress: number) => void): Promise<void> {
    return new Promise((resolve) => {
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 15 + 5; // Progress 5-20% each step
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          resolve();
        }
        
        const fileItem = this.uploadQueue.get(fileId);
        if (fileItem) {
          fileItem.progress = progress;
          onProgress?.(progress);
        }
      }, 300);
    });
  }

  private detectCompliance(fileName: string): 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS' {
    const lowerName = fileName.toLowerCase();
    if (lowerName.includes('medical') || lowerName.includes('patient') || lowerName.includes('health')) {
      return 'HIPAA';
    }
    if (lowerName.includes('financial') || lowerName.includes('sox') || lowerName.includes('audit')) {
      return 'SOX';
    }
    if (lowerName.includes('payment') || lowerName.includes('card') || lowerName.includes('transaction')) {
      return 'PCI-DSS';
    }
    return 'GDPR';
  }

  private generateFileId(): string {
    return Date.now().toString() + Math.random().toString(36).substr(2, 9);
  }

  getUploadStatus(fileId: string): FileItem | undefined {
    return this.uploadQueue.get(fileId);
  }

  getAllUploads(): FileItem[] {
    return Array.from(this.uploadQueue.values());
  }
}
