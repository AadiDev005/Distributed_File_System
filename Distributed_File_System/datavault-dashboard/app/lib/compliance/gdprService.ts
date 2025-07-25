import { DataSubjectRequest, AuditEvent } from '../../types/compliance';

export class GDPRComplianceService {
  private static instance: GDPRComplianceService;
  private auditLog: AuditEvent[] = [];
  private dataSubjectRequests: DataSubjectRequest[] = [];

  static getInstance(): GDPRComplianceService {
    if (!GDPRComplianceService.instance) {
      GDPRComplianceService.instance = new GDPRComplianceService();
    }
    return GDPRComplianceService.instance;
  }

  // Right to Access (Article 15)
  async processAccessRequest(subjectEmail: string): Promise<DataSubjectRequest> {
    const request: DataSubjectRequest = {
      id: this.generateRequestId(),
      type: 'access',
      subjectId: this.hashEmail(subjectEmail),
      subjectEmail,
      status: 'pending',
      requestDate: new Date(),
      affectedFiles: await this.findUserFiles(subjectEmail),
      legalBasis: 'Article 15 GDPR - Right of Access',
      notes: 'Automated processing initiated'
    };

    this.dataSubjectRequests.push(request);
    this.logAuditEvent('create', 'data-subject-request', request.id, {
      type: 'access',
      subjectEmail: this.maskEmail(subjectEmail)
    });

    // Auto-process if safe
    setTimeout(() => this.autoProcessAccessRequest(request.id), 1000);
    
    return request;
  }

  // Right to Erasure (Article 17)
  async processErasureRequest(subjectEmail: string, reason: string): Promise<DataSubjectRequest> {
    const request: DataSubjectRequest = {
      id: this.generateRequestId(),
      type: 'erasure',
      subjectId: this.hashEmail(subjectEmail),
      subjectEmail,
      status: 'pending',
      requestDate: new Date(),
      affectedFiles: await this.findUserFiles(subjectEmail),
      legalBasis: 'Article 17 GDPR - Right to Erasure',
      notes: `Reason: ${reason}`
    };

    this.dataSubjectRequests.push(request);
    this.logAuditEvent('create', 'data-subject-request', request.id, {
      type: 'erasure',
      reason,
      subjectEmail: this.maskEmail(subjectEmail)
    });

    return request;
  }

  // Right to Data Portability (Article 20)
  async processPortabilityRequest(subjectEmail: string, format: 'json' | 'csv' | 'xml' = 'json'): Promise<DataSubjectRequest> {
    const request: DataSubjectRequest = {
      id: this.generateRequestId(),
      type: 'portability',
      subjectId: this.hashEmail(subjectEmail),
      subjectEmail,
      status: 'processing',
      requestDate: new Date(),
      affectedFiles: await this.findUserFiles(subjectEmail),
      legalBasis: 'Article 20 GDPR - Right to Data Portability',
      notes: `Export format: ${format}`
    };

    this.dataSubjectRequests.push(request);
    
    // Start export process
    setTimeout(() => this.processDataExport(request.id, format), 2000);
    
    return request;
  }

  // Audit Trail for Compliance
  logAuditEvent(action: AuditEvent['action'], resourceType: string, resourceId: string, metadata: Record<string, any>): void {
    const event: AuditEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      userId: 'system', // In real app, would get from auth context
      action,
      resourceId,
      resourceType: resourceType as AuditEvent['resourceType'],
      metadata,
      complianceFlags: this.detectComplianceFlags(action, resourceType, metadata),
      ipAddress: '127.0.0.1', // In real app, would get from request
      userAgent: 'DataVault-System'
    };

    this.auditLog.push(event);
    
    // In production, would send to secure audit storage
    console.log('🔍 Audit Event:', event);
  }

  // Get compliance status
  getComplianceStatus(): {
    totalRequests: number;
    pendingRequests: number;
    processingTime: number;
    complianceScore: number;
  } {
    const total = this.dataSubjectRequests.length;
    const pending = this.dataSubjectRequests.filter(r => r.status === 'pending').length;
    const completed = this.dataSubjectRequests.filter(r => r.status === 'completed');
    
    // Calculate average processing time
    const avgProcessingTime = completed.length > 0 
      ? completed.reduce((sum, req) => {
          if (req.completionDate) {
            return sum + (req.completionDate.getTime() - req.requestDate.getTime());
          }
          return sum;
        }, 0) / completed.length / (1000 * 60 * 60 * 24) // Convert to days
      : 0;

    // Calculate compliance score based on response times and completion rates
    const completionRate = total > 0 ? (completed.length / total) * 100 : 100;
    const timelinessScore = avgProcessingTime <= 30 ? 100 : Math.max(0, 100 - (avgProcessingTime - 30) * 2);
    const complianceScore = (completionRate * 0.7 + timelinessScore * 0.3);

    return {
      totalRequests: total,
      pendingRequests: pending,
      processingTime: Math.round(avgProcessingTime * 10) / 10,
      complianceScore: Math.round(complianceScore)
    };
  }

  // Private helper methods
  private async autoProcessAccessRequest(requestId: string): Promise<void> {
    const request = this.dataSubjectRequests.find(r => r.id === requestId);
    if (!request) return;

    request.status = 'processing';
    
    // Simulate data collection and preparation
    setTimeout(() => {
      request.status = 'completed';
      request.completionDate = new Date();
      
      this.logAuditEvent('update', 'data-subject-request', requestId, {
        status: 'completed',
        filesProvided: request.affectedFiles.length
      });
    }, 3000);
  }

  private async processDataExport(requestId: string, format: string): Promise<void> {
    const request = this.dataSubjectRequests.find(r => r.id === requestId);
    if (!request) return;

    // Simulate data export
    setTimeout(() => {
      request.status = 'completed';
      request.completionDate = new Date();
      request.notes += ` | Export completed in ${format} format`;
      
      this.logAuditEvent('update', 'data-subject-request', requestId, {
        status: 'completed',
        exportFormat: format,
        filesExported: request.affectedFiles.length
      });
    }, 5000);
  }

  private async findUserFiles(email: string): Promise<string[]> {
    // In real implementation, would query database for user's files
    // For now, return mock file IDs
    return [
      `file_${this.hashEmail(email)}_1`,
      `file_${this.hashEmail(email)}_2`,
      `file_${this.hashEmail(email)}_3`
    ];
  }

  private detectComplianceFlags(action: string, resourceType: string, metadata: any): string[] {
    const flags: string[] = [];
    
    if (action === 'delete' && resourceType === 'file') {
      flags.push('data-deletion');
    }
    
    if (metadata.piiDetected) {
      flags.push('pii-processing');
    }
    
    if (metadata.crossBorder) {
      flags.push('cross-border-transfer');
    }
    
    return flags;
  }

  private generateRequestId(): string {
    return 'dsr_' + Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
  }

  private generateEventId(): string {
    return 'evt_' + Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
  }

  private hashEmail(email: string): string {
    // Simple hash for demo - in production would use proper cryptographic hash
    return btoa(email).substr(0, 16);
  }

  private maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    return `${local.substr(0, 2)}***@${domain}`;
  }

  // Public methods to get data for UI
  getAllRequests(): DataSubjectRequest[] {
    return [...this.dataSubjectRequests].sort((a, b) => b.requestDate.getTime() - a.requestDate.getTime());
  }

  getAuditLog(): AuditEvent[] {
    return [...this.auditLog].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }
}
