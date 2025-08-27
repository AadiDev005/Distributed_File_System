export interface ComplianceRule {
  id: string;
  name: string;
  regulation: 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS' | 'CCPA';
  category: 'data-protection' | 'access-control' | 'audit' | 'retention' | 'deletion';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  automated: boolean;
  lastCheck: Date;
  status: 'compliant' | 'warning' | 'violation' | 'pending';
}

export interface PIIDetectionResult {
  fileId: string;
  fileName: string;
  piiFound: PIIType[];
  confidenceScore: number;
  recommendedActions: string[];
  complianceRisk: 'low' | 'medium' | 'high' | 'critical';
}

export interface PIIType {
  type: 'ssn' | 'email' | 'phone' | 'address' | 'credit-card' | 'medical-id' | 'passport';
  value: string;
  location: {
    line: number;
    column: number;
    context: string;
  };
  confidence: number;
  regulation: string[];
}

export interface AuditEvent {
  id: string;
  timestamp: Date;
  userId: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'share' | 'download';
  resourceId: string;
  resourceType: 'file' | 'folder' | 'user' | 'permission' | 'system' | 'blockchain' | 'audit-chain';
  metadata: Record<string, any>;
  complianceFlags: string[];
  ipAddress: string;
  userAgent: string;
}

export interface DataSubjectRequest {
  id: string;
  type: 'access' | 'portability' | 'rectification' | 'erasure' | 'restriction';
  subjectId: string;
  subjectEmail: string;
  status: 'pending' | 'processing' | 'completed' | 'rejected';
  requestDate: Date;
  completionDate?: Date;
  affectedFiles: string[];
  legalBasis: string;
  notes: string;
}
