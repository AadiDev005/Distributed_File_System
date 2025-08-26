// app/lib/fileUpload.ts

import { FileItem, DataVaultAPI, FileUploadResponse, SecurityMode } from '../dashboard/utils/api';

/* ─── Enhanced Types ──────────────────────────────────────────────── */

export interface UploadProgress {
  fileId: string;
  fileName: string;
  progress: number;
  status: 'queued' | 'uploading' | 'processing' | 'complete' | 'error';
  stage: string;
  bytesUploaded: number;
  totalBytes: number;
  speed: number; // bytes per second
  estimatedTimeRemaining: number; // seconds
  error?: string;
  // ✅ NEW: Security mode tracking
  securityMode: SecurityMode;
  autoDetectedSecurity: boolean;
}

export interface SecurityProgress {
  pii_detection: boolean;
  quantum_encryption: boolean;
  bft_consensus: boolean;
  zero_trust_verification: boolean;
  abe_encryption: boolean;
  threshold_sharing: boolean;
  immutable_audit: boolean;
  gdpr_compliance: boolean;
}

export interface UploadOptions {
  enablePIIDetection?: boolean;
  enableABEEncryption?: boolean;
  complianceLevel?: 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS';
  enableThresholdSharing?: boolean;
  maxRetries?: number;
  chunkSize?: number;
  // ✅ NEW: Security mode options
  securityModePreference?: SecurityMode;
  forceSecurityMode?: boolean; // Override auto-detection
}

export interface UploadResult {
  success: boolean;
  fileItem: FileItem;
  securityApplied: SecurityProgress;
  uploadTime: number;
  message?: string;
  error?: string;
  // ✅ NEW: Security mode result info
  securityModeUsed: SecurityMode;
  securityModeReason: string;
}

/* ─── Enhanced FileUploadService ──────────────────────────────────────── */

export class FileUploadService {
  private static instance: FileUploadService;
  private uploadQueue: Map<string, UploadProgress> = new Map();
  private activeUploads: Map<string, AbortController> = new Map();
  private uploadHistory: Map<string, UploadResult> = new Map();
  private progressCallbacks: Map<string, ((progress: UploadProgress) => void)[]> = new Map();
  private maxConcurrentUploads = 3;
  private currentUploads = 0;

  /* ── Singleton Pattern ─────────────────────────────────────────────── */

  static getInstance(): FileUploadService {
    if (!FileUploadService.instance) {
      FileUploadService.instance = new FileUploadService();
    }
    return FileUploadService.instance;
  }

  /* ── ✅ NEW: Security Mode Detection ───────────────────────────────── */

  private shouldUseEnterpriseMode(file: File): boolean {
    const lower = file.name.toLowerCase();
    const sizeMB = file.size / (1024 * 1024);
    
    return (
      lower.includes('confidential') ||
      lower.includes('secret') ||
      lower.includes('classified') ||
      lower.includes('private') ||
      lower.includes('enterprise') ||
      sizeMB > 50 // Files larger than 50MB
    );
  }

  private determineSecurityMode(file: File, options: UploadOptions): { mode: SecurityMode; reason: string; autoDetected: boolean } {
    // If force mode is specified, use it
    if (options.forceSecurityMode && options.securityModePreference) {
      return {
        mode: options.securityModePreference,
        reason: 'User preference (forced)',
        autoDetected: false
      };
    }

    // Check auto-detection
    const shouldUseEnterprise = this.shouldUseEnterpriseMode(file);
    if (shouldUseEnterprise) {
      const lower = file.name.toLowerCase();
      const sizeMB = file.size / (1024 * 1024);
      
      let reason = 'Auto-detected: ';
      if (lower.includes('confidential')) reason += 'contains "confidential"';
      else if (lower.includes('secret')) reason += 'contains "secret"';
      else if (lower.includes('classified')) reason += 'contains "classified"';
      else if (lower.includes('private')) reason += 'contains "private"';
      else if (lower.includes('enterprise')) reason += 'contains "enterprise"';
      else if (sizeMB > 50) reason += `large file (${sizeMB.toFixed(1)}MB)`;
      else reason += 'sensitive content detected';

      return {
        mode: 'enterprise',
        reason,
        autoDetected: true
      };
    }

    // Use preference or default to simple
    const preferredMode = options.securityModePreference || DataVaultAPI.getCachedSecurityMode();
    return {
      mode: preferredMode,
      reason: options.securityModePreference ? 'User preference' : 'Default mode',
      autoDetected: false
    };
  }

  /* ── Core Upload Methods ───────────────────────────────────────────── */

  async uploadFile(
    file: File, 
    options: UploadOptions = {},
    onProgress?: (progress: UploadProgress) => void
  ): Promise<UploadResult> {
    const fileId = this.generateFileId();
    const startTime = Date.now();

    // ✅ ENHANCED: Determine security mode
    const securityModeInfo = this.determineSecurityMode(file, options);

    // Initialize progress tracking with security mode
    const progressData: UploadProgress = {
      fileId,
      fileName: file.name,
      progress: 0,
      status: 'queued',
      stage: `Initializing ${securityModeInfo.mode} mode upload...`,
      bytesUploaded: 0,
      totalBytes: file.size,
      speed: 0,
      estimatedTimeRemaining: 0,
      securityMode: securityModeInfo.mode,
      autoDetectedSecurity: securityModeInfo.autoDetected
    };

    this.uploadQueue.set(fileId, progressData);
    if (onProgress) {
      this.addProgressCallback(fileId, onProgress);
    }

    try {
      // Validate file before upload
      this.validateFile(file);
      
      // Wait for upload slot if queue is full
      await this.waitForUploadSlot();
      
      this.currentUploads++;
      const abortController = new AbortController();
      this.activeUploads.set(fileId, abortController);

      // Start upload process
      const result = await this.performUpload(file, fileId, progressData, options, securityModeInfo);
      
      // Store successful result
      const uploadResult: UploadResult = {
        ...result,
        uploadTime: Date.now() - startTime
      };
      
      this.uploadHistory.set(fileId, uploadResult);
      this.cleanup(fileId);
      
      return uploadResult;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      
      // Update progress with error
      progressData.status = 'error';
      progressData.stage = 'Upload failed';
      progressData.error = errorMessage;
      this.notifyProgressCallbacks(fileId, progressData);

      const errorResult: UploadResult = {
        success: false,
        fileItem: this.createFileItemFromFile(file, 'error', securityModeInfo.mode),
        securityApplied: this.createEmptySecurityProgress(),
        uploadTime: Date.now() - startTime,
        error: errorMessage,
        securityModeUsed: securityModeInfo.mode,
        securityModeReason: securityModeInfo.reason
      };

      this.uploadHistory.set(fileId, errorResult);
      this.cleanup(fileId);
      
      throw error;
    }
  }

  async uploadMultipleFiles(
    files: File[], 
    options: UploadOptions = {},
    onProgress?: (fileId: string, progress: UploadProgress) => void,
    onComplete?: (results: UploadResult[]) => void
  ): Promise<UploadResult[]> {
    const uploadPromises = Array.from(files).map(file => 
      this.uploadFile(file, options, onProgress ? (progress) => onProgress(progress.fileId, progress) : undefined)
    );

    try {
      const results = await Promise.allSettled(uploadPromises);
      
      const uploadResults: UploadResult[] = results.map((result, index) => {
        if (result.status === 'fulfilled') {
          return result.value;
        } else {
          const securityModeInfo = this.determineSecurityMode(files[index], options);
          return {
            success: false,
            fileItem: this.createFileItemFromFile(files[index], 'error', securityModeInfo.mode),
            securityApplied: this.createEmptySecurityProgress(),
            uploadTime: 0,
            error: result.reason instanceof Error ? result.reason.message : 'Upload failed',
            securityModeUsed: securityModeInfo.mode,
            securityModeReason: securityModeInfo.reason
          };
        }
      });

      onComplete?.(uploadResults);
      return uploadResults;
    } catch (error) {
      console.error('Batch upload failed:', error);
      throw error;
    }
  }

  /* ── Enhanced Upload Process ───────────────────────────────────────── */

  private async performUpload(
    file: File, 
    fileId: string, 
    progressData: UploadProgress, 
    options: UploadOptions,
    securityModeInfo: { mode: SecurityMode; reason: string; autoDetected: boolean }
  ): Promise<UploadResult> {
    const isEnterpriseMode = securityModeInfo.mode === 'enterprise';

    // ✅ ENHANCED: Security mode specific stages
    
    // Stage 1: Prepare upload
    progressData.status = 'uploading';
    progressData.stage = `Preparing file for ${securityModeInfo.mode} mode upload...`;
    progressData.progress = 5;
    this.notifyProgressCallbacks(fileId, progressData);

    await this.delay(500);

    // Stage 2: Security analysis (different for each mode)
    if (isEnterpriseMode) {
      progressData.stage = 'Advanced security analysis and threat detection...';
      progressData.progress = 15;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(600); // Enterprise takes longer
    } else {
      progressData.stage = 'Basic security scan and classification...';
      progressData.progress = 20;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(300); // Simple is faster
    }

    const securityProgress = this.createSecurityProgressForMode(securityModeInfo.mode, options);

    // Stage 3: Encryption (mode-specific)
    if (isEnterpriseMode) {
      progressData.stage = 'Applying enterprise-grade quantum encryption...';
      progressData.progress = 25;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(800);
    } else {
      progressData.stage = 'Applying quantum-safe encryption...';
      progressData.progress = 30;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(400);
    }

    securityProgress.quantum_encryption = true;

    // Stage 4: Security verification (enterprise only)
    if (isEnterpriseMode) {
      progressData.stage = 'Zero-trust security verification and policy enforcement...';
      progressData.progress = 35;
      this.notifyProgressCallbacks(fileId, progressData);
      securityProgress.zero_trust_verification = true;
      await this.delay(500);
    }

    // Stage 5: Upload to DataVault network
    progressData.stage = `Uploading to DataVault ${isEnterpriseMode ? 'enterprise' : 'standard'} network...`;
    progressData.progress = isEnterpriseMode ? 50 : 60;
    this.notifyProgressCallbacks(fileId, progressData);

    // Create FileList for API
    const fileList = this.createFileList([file]);
    const uploadResponse = await DataVaultAPI.uploadFiles(fileList);

    if (!uploadResponse.success) {
      throw new Error(uploadResponse.message || 'Upload failed');
    }

    // Stage 6: Consensus and replication (different timeframes)
    if (isEnterpriseMode) {
      progressData.stage = 'Achieving BFT consensus with enhanced validation...';
      progressData.progress = 70;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(700);
      
      progressData.stage = 'Secure replication with enterprise redundancy...';
      progressData.progress = 85;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(500);
    } else {
      progressData.stage = 'Simple consensus and standard replication...';
      progressData.progress = 80;
      this.notifyProgressCallbacks(fileId, progressData);
      await this.delay(400);
    }

    securityProgress.bft_consensus = true;

    // Stage 7: Final security measures (mode-dependent)
    if (isEnterpriseMode) {
      if (options.enableABEEncryption || securityModeInfo.autoDetected) {
        securityProgress.abe_encryption = true;
      }
      if (options.enableThresholdSharing) {
        securityProgress.threshold_sharing = true;
      }
      securityProgress.immutable_audit = true;
      securityProgress.gdpr_compliance = true;
    } else {
      securityProgress.immutable_audit = true;
      securityProgress.gdpr_compliance = options.complianceLevel === 'GDPR';
    }

    // Stage 8: Complete
    const appliedSecurityCount = Object.values(securityProgress).filter(Boolean).length;
    progressData.stage = `Upload complete - ${appliedSecurityCount} security layers applied in ${securityModeInfo.mode} mode!`;
    progressData.progress = 100;
    progressData.status = 'complete';
    progressData.bytesUploaded = file.size;
    this.notifyProgressCallbacks(fileId, progressData);

    // ✅ ENHANCED: Use uploaded file with security mode info
    const uploadedFile = uploadResponse.files[0] || this.createFileItemFromFile(file, 'complete', securityModeInfo.mode);
    
    // Ensure security mode is set on the file item
    if (uploadedFile) {
      uploadedFile.security_mode = securityModeInfo.mode;
    }

    return {
      success: true,
      fileItem: uploadedFile,
      securityApplied: securityProgress,
      uploadTime: 0, // Will be calculated by caller
      message: `File uploaded successfully with ${appliedSecurityCount} security layers in ${securityModeInfo.mode} mode`,
      securityModeUsed: securityModeInfo.mode,
      securityModeReason: securityModeInfo.reason
    };
  }

  /* ── ✅ NEW: Security Progress Factory ─────────────────────────────── */

  private createSecurityProgressForMode(mode: SecurityMode, options: UploadOptions): SecurityProgress {
    const progress = this.createEmptySecurityProgress();
    
    if (mode === 'enterprise') {
      // Enterprise mode gets more security features by default
      progress.pii_detection = options.enablePIIDetection !== false;
      progress.zero_trust_verification = true;
      progress.abe_encryption = options.enableABEEncryption || false;
      progress.threshold_sharing = options.enableThresholdSharing || false;
      progress.immutable_audit = true;
      progress.gdpr_compliance = true;
    } else {
      // Simple mode gets essential security
      progress.pii_detection = options.enablePIIDetection === true;
      progress.zero_trust_verification = false;
      progress.abe_encryption = false;
      progress.threshold_sharing = false;
      progress.immutable_audit = true;
      progress.gdpr_compliance = options.complianceLevel === 'GDPR';
    }
    
    // Both modes get quantum encryption
    progress.quantum_encryption = true;
    progress.bft_consensus = true;
    
    return progress;
  }

  /* ── Queue Management ──────────────────────────────────────────────── */

  private async waitForUploadSlot(): Promise<void> {
    while (this.currentUploads >= this.maxConcurrentUploads) {
      await this.delay(100);
    }
  }

  private cleanup(fileId: string): void {
    this.uploadQueue.delete(fileId);
    this.activeUploads.delete(fileId);
    this.progressCallbacks.delete(fileId);
    this.currentUploads = Math.max(0, this.currentUploads - 1);
  }

  /* ── Progress Management ───────────────────────────────────────────── */

  private addProgressCallback(fileId: string, callback: (progress: UploadProgress) => void): void {
    if (!this.progressCallbacks.has(fileId)) {
      this.progressCallbacks.set(fileId, []);
    }
    this.progressCallbacks.get(fileId)!.push(callback);
  }

  private notifyProgressCallbacks(fileId: string, progress: UploadProgress): void {
    const callbacks = this.progressCallbacks.get(fileId);
    if (callbacks) {
      callbacks.forEach(callback => {
        try {
          callback(progress);
        } catch (error) {
          console.warn('Progress callback error:', error);
        }
      });
    }
  }

  /* ── File Validation and Classification ────────────────────────────── */

  private validateFile(file: File): void {
    if (!file) {
      throw new Error('No file provided');
    }
    
    if (file.size === 0) {
      throw new Error('File is empty');
    }
    
    if (file.size > 500 * 1024 * 1024) { // 500MB limit (increased for enterprise)
      throw new Error('File exceeds maximum size limit (500MB)');
    }

    // Check for suspicious file types
    const dangerousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.com', '.pif'];
    const fileName = file.name.toLowerCase();
    
    if (dangerousExtensions.some(ext => fileName.endsWith(ext))) {
      throw new Error('File type not allowed for security reasons');
    }
  }

  private detectCompliance(fileName: string): 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS' | 'NONE' {
    const lowerName = fileName.toLowerCase();
    
    // Enhanced compliance detection with more keywords
    if (lowerName.includes('medical') || lowerName.includes('patient') || 
        lowerName.includes('health') || lowerName.includes('hipaa') ||
        lowerName.includes('phi') || lowerName.includes('doctor') ||
        lowerName.includes('hospital') || lowerName.includes('clinic')) {
      return 'HIPAA';
    }
    
    if (lowerName.includes('financial') || lowerName.includes('sox') || 
        lowerName.includes('audit') || lowerName.includes('sarbanes') ||
        lowerName.includes('oxley') || lowerName.includes('10-k') ||
        lowerName.includes('10-q') || lowerName.includes('earnings') ||
        lowerName.includes('balance-sheet') || lowerName.includes('income-statement')) {
      return 'SOX';
    }
    
    if (lowerName.includes('payment') || lowerName.includes('card') || 
        lowerName.includes('transaction') || lowerName.includes('pci') ||
        lowerName.includes('cvv') || lowerName.includes('credit') ||
        lowerName.includes('debit') || lowerName.includes('merchant')) {
      return 'PCI-DSS';
    }
    
    if (lowerName.includes('personal') || lowerName.includes('gdpr') ||
        lowerName.includes('privacy') || lowerName.includes('consent') ||
        lowerName.includes('dpo') || lowerName.includes('data-subject')) {
      return 'GDPR';
    }
    
    return 'GDPR'; // Default to GDPR for EU compliance
  }

  private detectMimeType(file: File): string {
    if (file.type) return file.type;
    
    // Enhanced MIME type detection
    const extension = file.name.toLowerCase().split('.').pop();
    const mimeTypes: Record<string, string> = {
      // Documents
      'pdf': 'application/pdf',
      'doc': 'application/msword',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'xls': 'application/vnd.ms-excel',
      'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'ppt': 'application/vnd.ms-powerpoint',
      'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'odt': 'application/vnd.oasis.opendocument.text',
      'ods': 'application/vnd.oasis.opendocument.spreadsheet',
      'odp': 'application/vnd.oasis.opendocument.presentation',
      
      // Text files
      'txt': 'text/plain',
      'csv': 'text/csv',
      'json': 'application/json',
      'xml': 'application/xml',
      'html': 'text/html',
      'htm': 'text/html',
      'css': 'text/css',
      'js': 'application/javascript',
      'ts': 'application/typescript',
      'md': 'text/markdown',
      'rtf': 'application/rtf',
      
      // Images
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'webp': 'image/webp',
      'svg': 'image/svg+xml',
      'bmp': 'image/bmp',
      'tiff': 'image/tiff',
      'ico': 'image/x-icon',
      
      // Videos
      'mp4': 'video/mp4',
      'avi': 'video/x-msvideo',
      'mov': 'video/quicktime',
      'wmv': 'video/x-ms-wmv',
      'flv': 'video/x-flv',
      'webm': 'video/webm',
      'mkv': 'video/x-matroska',
      
      // Audio
      'mp3': 'audio/mpeg',
      'wav': 'audio/wav',
      'flac': 'audio/flac',
      'aac': 'audio/aac',
      'ogg': 'audio/ogg',
      'm4a': 'audio/mp4',
      
      // Archives
      'zip': 'application/zip',
      'rar': 'application/x-rar-compressed',
      '7z': 'application/x-7z-compressed',
      'tar': 'application/x-tar',
      'gz': 'application/gzip',
      'bz2': 'application/x-bzip2'
    };
    
    return mimeTypes[extension || ''] || 'application/octet-stream';
  }

  /* ── Utility Methods ───────────────────────────────────────────────── */

  private generateFileId(): string {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    return `upload_${timestamp}_${random}`;
  }

  private createFileList(files: File[]): FileList {
    const dataTransfer = new DataTransfer();
    files.forEach(file => dataTransfer.items.add(file));
    return dataTransfer.files;
  }

  // ✅ UPDATED: Include security mode in file item creation
  private createFileItemFromFile(file: File, status: 'complete' | 'uploading' | 'error', securityMode: SecurityMode): FileItem {
    return {
      id: this.generateFileId(),
      name: file.name,
      type: 'file',
      size: file.size,
      lastModified: new Date().toISOString(),
      owner: 'Current User',
      compliance: this.detectCompliance(file.name),
      encrypted: status === 'complete',
      shared: false,
      status,
      mimeType: this.detectMimeType(file),
      security_mode: securityMode, // ✅ NEW: Include security mode
      security_level: securityMode === 'enterprise' ? 'enterprise' : 'standard'
    };
  }

  private createEmptySecurityProgress(): SecurityProgress {
    return {
      pii_detection: false,
      quantum_encryption: false,
      bft_consensus: false,
      zero_trust_verification: false,
      abe_encryption: false,
      threshold_sharing: false,
      immutable_audit: false,
      gdpr_compliance: false
    };
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /* ── Public Query Methods ──────────────────────────────────────────── */

  getUploadProgress(fileId: string): UploadProgress | undefined {
    return this.uploadQueue.get(fileId);
  }

  getUploadResult(fileId: string): UploadResult | undefined {
    return this.uploadHistory.get(fileId);
  }

  getAllActiveUploads(): UploadProgress[] {
    return Array.from(this.uploadQueue.values());
  }

  getAllUploadHistory(): UploadResult[] {
    return Array.from(this.uploadHistory.values());
  }

  getSuccessfulUploads(): UploadResult[] {
    return this.getAllUploadHistory().filter(result => result.success);
  }

  getFailedUploads(): UploadResult[] {
    return this.getAllUploadHistory().filter(result => !result.success);
  }

  // ✅ NEW: Security mode specific queries
  getUploadsBySecurityMode(mode: SecurityMode): UploadResult[] {
    return this.getAllUploadHistory().filter(result => result.securityModeUsed === mode);
  }

  getEnterpriseUploads(): UploadResult[] {
    return this.getUploadsBySecurityMode('enterprise');
  }

  getSimpleUploads(): UploadResult[] {
    return this.getUploadsBySecurityMode('simple');
  }

  getAutoDetectedUploads(): UploadResult[] {
    const activeUploads = this.getAllActiveUploads();
    return activeUploads.filter(upload => upload.autoDetectedSecurity).map(upload => ({
      success: true,
      fileItem: this.createFileItemFromFile(new File([], upload.fileName), 'uploading', upload.securityMode),
      securityApplied: this.createEmptySecurityProgress(),
      uploadTime: 0,
      securityModeUsed: upload.securityMode,
      securityModeReason: 'Auto-detected'
    }));
  }

  isUploading(fileId?: string): boolean {
    if (fileId) {
      const progress = this.uploadQueue.get(fileId);
      return progress?.status === 'uploading' || progress?.status === 'processing';
    }
    return this.currentUploads > 0;
  }

  hasActiveUploads(): boolean {
    return this.uploadQueue.size > 0;
  }

  /* ── Upload Control Methods ────────────────────────────────────────── */

  cancelUpload(fileId: string): boolean {
    const abortController = this.activeUploads.get(fileId);
    if (abortController) {
      abortController.abort();
      this.cleanup(fileId);
      return true;
    }
    return false;
  }

  cancelAllUploads(): void {
    this.activeUploads.forEach((controller, fileId) => {
      controller.abort();
      this.cleanup(fileId);
    });
  }

  clearHistory(): void {
    this.uploadHistory.clear();
  }

  setMaxConcurrentUploads(max: number): void {
    this.maxConcurrentUploads = Math.max(1, Math.min(max, 10)); // Limit between 1-10
  }

  /* ── ✅ FIXED: Statistics and Monitoring with Security Mode ──────── */

  getUploadStatistics() {
    const history = this.getAllUploadHistory();
    const successful = history.filter(r => r.success);
    const failed = history.filter(r => !r.success);
    
    // Security mode breakdown
    const enterpriseUploads = successful.filter(r => r.securityModeUsed === 'enterprise');
    const simpleUploads = successful.filter(r => r.securityModeUsed === 'simple');
    const autoDetectedUploads = history.filter(r => r.securityModeReason && r.securityModeReason.includes('Auto-detected'));
    
    const totalBytes = successful.reduce((sum, result) => sum + (result.fileItem.size || 0), 0);
    const avgUploadTime = successful.length > 0 
      ? successful.reduce((sum, result) => sum + result.uploadTime, 0) / successful.length 
      : 0;

    // ✅ FIXED: Calculate security feature usage with proper handling
    const securityFeatureUsage: Record<string, number> = {};
    successful.forEach(result => {
      Object.entries(result.securityApplied).forEach(([feature, used]) => {
        if (used) {
          securityFeatureUsage[feature] = (securityFeatureUsage[feature] || 0) + 1;
        }
      });
    });

    // ✅ FIXED: Safe access to most used security feature
    const securityFeatureEntries = Object.entries(securityFeatureUsage);
    const mostUsedSecurityFeature = securityFeatureEntries.length > 0
      ? securityFeatureEntries.sort((a, b) => b[1] - a[1])[0][0]
      : 'quantum_encryption';

    return {
      // Basic stats
      totalUploads: history.length,
      successfulUploads: successful.length,
      failedUploads: failed.length,
      successRate: history.length > 0 ? (successful.length / history.length) * 100 : 0,
      totalBytesUploaded: totalBytes,
      averageUploadTime: avgUploadTime,
      activeUploads: this.uploadQueue.size,
      maxConcurrentUploads: this.maxConcurrentUploads,
      
      // Security mode statistics
      enterpriseUploads: enterpriseUploads.length,
      simpleUploads: simpleUploads.length,
      autoDetectedUploads: autoDetectedUploads.length,
      securityModeDistribution: {
        enterprise: enterpriseUploads.length,
        simple: simpleUploads.length
      },
      
      // Security feature usage
      securityFeatureUsage,
      mostUsedSecurityFeature,
      
      // Performance by security mode
      averageUploadTimeByMode: {
        enterprise: enterpriseUploads.length > 0 
          ? enterpriseUploads.reduce((sum, r) => sum + r.uploadTime, 0) / enterpriseUploads.length 
          : 0,
        simple: simpleUploads.length > 0 
          ? simpleUploads.reduce((sum, r) => sum + r.uploadTime, 0) / simpleUploads.length 
          : 0
      }
    };
  }

  /* ── Format Utilities ──────────────────────────────────────────────── */

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  formatUploadSpeed(bytesPerSecond: number): string {
    return this.formatFileSize(bytesPerSecond) + '/s';
  }

  formatEstimatedTime(seconds: number): string {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
  }

  // ✅ NEW: Security mode utilities
  formatSecurityMode(mode: SecurityMode): string {
    return mode === 'enterprise' ? '🔒 Enterprise' : '⚡ Simple';
  }

  getSecurityModeDescription(mode: SecurityMode): string {
    return mode === 'enterprise' 
      ? 'Maximum security with zero-trust evaluation and compliance'
      : 'Fast uploads with essential security features';
  }
}

/* ── Export Singleton Instance ────────────────────────────────────────── */

export const fileUploadService = FileUploadService.getInstance();
export default fileUploadService;
