export interface ComplianceRegulation {
  id: string;
  name: string;
  fullName: string;
  jurisdiction: string[];
  category: 'data-protection' | 'financial' | 'healthcare' | 'security' | 'industry-specific';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  requirements: ComplianceRequirement[];
  lastUpdated: Date;
  nextReview: Date;
  penalties: {
    financial: string;
    operational: string;
    reputational: string;
  };
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  article?: string;
  section?: string;
  status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
  score: number; // 0-100
  lastAssessment: Date;
  nextAssessment: Date;
  evidence: ComplianceEvidence[];
  remediation?: RemediationPlan;
  automationLevel: 'fully-automated' | 'semi-automated' | 'manual';
}

export interface ComplianceEvidence {
  id: string;
  type: 'policy' | 'procedure' | 'technical-control' | 'audit-log' | 'certification';
  title: string;
  description: string;
  source: string;
  collectedAt: Date;
  validUntil: Date;
  confidence: number; // 0-100
  automated: boolean;
}

export interface RemediationPlan {
  id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  estimatedCost: number;
  estimatedTime: string;
  assignedTo: string;
  dueDate: Date;
  status: 'planned' | 'in-progress' | 'completed' | 'blocked';
  progress: number; // 0-100
  tasks: RemediationTask[];
}

export interface RemediationTask {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'in-progress' | 'completed';
  assignedTo: string;
  dueDate: Date;
  completedAt?: Date;
}

export interface ComplianceAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: 'violation' | 'expiring-evidence' | 'new-requirement' | 'status-change' | 'audit-finding';
  regulation: string;
  requirement: string;
  title: string;
  description: string;
  impact: string;
  recommendedAction: string;
  createdAt: Date;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  assignedTo?: string;
}

export interface ComplianceMetrics {
  overallScore: number;
  totalRequirements: number;
  compliantRequirements: number;
  partialRequirements: number;
  nonCompliantRequirements: number;
  criticalViolations: number;
  upcomingDeadlines: number;
  automationLevel: number;
  lastFullAssessment: Date;
  nextFullAssessment: Date;
  trendsData: ComplianceTrend[];
}

export interface ComplianceTrend {
  date: Date;
  overallScore: number;
  regulationScores: { [regulationId: string]: number };
  violations: number;
  remediations: number;
}

export class ComplianceMonitoringService {
  private static instance: ComplianceMonitoringService;
  private regulations: ComplianceRegulation[] = [];
  private alerts: ComplianceAlert[] = [];
  private metrics: ComplianceMetrics | null = null;
  private monitoringInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.initializeRegulations();
    this.startRealTimeMonitoring();
  }

  static getInstance(): ComplianceMonitoringService {
    if (!ComplianceMonitoringService.instance) {
      ComplianceMonitoringService.instance = new ComplianceMonitoringService();
    }
    return ComplianceMonitoringService.instance;
  }

  private initializeRegulations(): void {
    this.regulations = [
      {
        id: 'gdpr',
        name: 'GDPR',
        fullName: 'General Data Protection Regulation',
        jurisdiction: ['EU', 'EEA'],
        category: 'data-protection',
        criticality: 'critical',
        lastUpdated: new Date('2024-01-15'),
        nextReview: new Date('2025-01-15'),
        penalties: {
          financial: 'Up to €20M or 4% of global revenue',
          operational: 'Data processing restrictions',
          reputational: 'Public disclosure of violations'
        },
        requirements: [
          {
            id: 'gdpr-art-5',
            title: 'Data Processing Principles',
            description: 'Personal data must be processed lawfully, fairly, and transparently',
            article: 'Article 5',
            status: 'compliant',
            score: 98,
            lastAssessment: new Date('2024-12-01'),
            nextAssessment: new Date('2025-03-01'),
            automationLevel: 'fully-automated',
            evidence: [
              {
                id: 'gdpr-art-5-ev-1',
                type: 'technical-control',
                title: 'Automated PII Detection',
                description: 'AI-powered system detects and classifies personal data',
                source: 'DataVault PII Engine',
                collectedAt: new Date('2024-12-01'),
                validUntil: new Date('2025-12-01'),
                confidence: 95,
                automated: true
              }
            ]
          },
          {
            id: 'gdpr-art-17',
            title: 'Right to Erasure',
            description: 'Individuals can request deletion of their personal data',
            article: 'Article 17',
            status: 'compliant',
            score: 99,
            lastAssessment: new Date('2024-11-15'),
            nextAssessment: new Date('2025-02-15'),
            automationLevel: 'fully-automated',
            evidence: [
              {
                id: 'gdpr-art-17-ev-1',
                type: 'procedure',
                title: 'Automated Erasure Workflow',
                description: 'System automatically processes and executes erasure requests',
                source: 'DataVault Compliance Engine',
                collectedAt: new Date('2024-11-15'),
                validUntil: new Date('2025-11-15'),
                confidence: 99,
                automated: true
              }
            ]
          },
          {
            id: 'gdpr-art-30',
            title: 'Records of Processing Activities',
            description: 'Maintain comprehensive records of all data processing',
            article: 'Article 30',
            status: 'compliant',
            score: 97,
            lastAssessment: new Date('2024-12-15'),
            nextAssessment: new Date('2025-03-15'),
            automationLevel: 'fully-automated',
            evidence: [
              {
                id: 'gdpr-art-30-ev-1',
                type: 'audit-log',
                title: 'Immutable Audit Trail',
                description: 'Blockchain-based immutable record of all processing activities',
                source: 'DataVault Audit Blockchain',
                collectedAt: new Date('2024-12-15'),
                validUntil: new Date('2025-12-15'),
                confidence: 100,
                automated: true
              }
            ]
          }
        ]
      },
      {
        id: 'hipaa',
        name: 'HIPAA',
        fullName: 'Health Insurance Portability and Accountability Act',
        jurisdiction: ['US'],
        category: 'healthcare',
        criticality: 'critical',
        lastUpdated: new Date('2024-01-10'),
        nextReview: new Date('2025-01-10'),
        penalties: {
          financial: 'Up to $1.5M per incident',
          operational: 'Loss of healthcare contracts',
          reputational: 'Public health sector blacklisting'
        },
        requirements: [
          {
            id: 'hipaa-164-312-a',
            title: 'Access Control',
            description: 'Unique user identification, emergency procedures, automatic logoff',
            section: '164.312(a)',
            status: 'compliant',
            score: 96,
            lastAssessment: new Date('2024-11-20'),
            nextAssessment: new Date('2025-02-20'),
            automationLevel: 'semi-automated',
            evidence: [
              {
                id: 'hipaa-access-ev-1',
                type: 'technical-control',
                title: 'Zero-Trust Access System',
                description: 'Multi-factor authentication with behavioral biometrics',
                source: 'DataVault Security Gateway',
                collectedAt: new Date('2024-11-20'),
                validUntil: new Date('2025-11-20'),
                confidence: 96,
                automated: true
              }
            ]
          },
          {
            id: 'hipaa-164-312-b',
            title: 'Audit Controls',
            description: 'Hardware, software, and procedural mechanisms for audit logs',
            section: '164.312(b)',
            status: 'compliant',
            score: 98,
            lastAssessment: new Date('2024-12-01'),
            nextAssessment: new Date('2025-03-01'),
            automationLevel: 'fully-automated',
            evidence: [
              {
                id: 'hipaa-audit-ev-1',
                type: 'audit-log',
                title: 'Comprehensive Audit System',
                description: 'Real-time audit logging with tamper-proof storage',
                source: 'DataVault Audit System',
                collectedAt: new Date('2024-12-01'),
                validUntil: new Date('2025-12-01'),
                confidence: 98,
                automated: true
              }
            ]
          }
        ]
      },
      {
        id: 'sox',
        name: 'SOX',
        fullName: 'Sarbanes-Oxley Act',
        jurisdiction: ['US'],
        category: 'financial',
        criticality: 'critical',
        lastUpdated: new Date('2024-01-05'),
        nextReview: new Date('2025-01-05'),
        penalties: {
          financial: 'Up to $5M and 20 years imprisonment',
          operational: 'SEC sanctions and delisting',
          reputational: 'Loss of investor confidence'
        },
        requirements: [
          {
            id: 'sox-302',
            title: 'Corporate Responsibility for Financial Reports',
            description: 'CEO and CFO certification of financial controls',
            section: 'Section 302',
            status: 'compliant',
            score: 99,
            lastAssessment: new Date('2024-12-10'),
            nextAssessment: new Date('2025-03-10'),
            automationLevel: 'semi-automated',
            evidence: [
              {
                id: 'sox-302-ev-1',
                type: 'procedure',
                title: 'Executive Certification Process',
                description: 'Digital workflow for executive sign-off on financial controls',
                source: 'DataVault Workflow Engine',
                collectedAt: new Date('2024-12-10'),
                validUntil: new Date('2025-12-10'),
                confidence: 99,
                automated: false
              }
            ]
          },
          {
            id: 'sox-404',
            title: 'Management Assessment of Internal Controls',
            description: 'Annual assessment of internal control effectiveness',
            section: 'Section 404',
            status: 'partial',
            score: 87,
            lastAssessment: new Date('2024-10-15'),
            nextAssessment: new Date('2025-01-15'),
            automationLevel: 'manual',
            evidence: [
              {
                id: 'sox-404-ev-1',
                type: 'audit-log',
                title: 'Internal Control Testing',
                description: 'Quarterly testing of financial data controls',
                source: 'Internal Audit Team',
                collectedAt: new Date('2024-10-15'),
                validUntil: new Date('2025-10-15'),
                confidence: 87,
                automated: false
              }
            ],
            remediation: {
              id: 'sox-404-rem-1',
              title: 'Enhance Internal Control Automation',
              description: 'Implement automated testing of financial data controls',
              priority: 'high',
              estimatedCost: 75000,
              estimatedTime: '8-10 weeks',
              assignedTo: 'Internal Audit Team',
              dueDate: new Date('2025-02-28'),
              status: 'in-progress',
              progress: 45,
              tasks: [
                {
                  id: 'sox-404-task-1',
                  title: 'Design automated control tests',
                  description: 'Create automated test procedures for key financial controls',
                  status: 'completed',
                  assignedTo: 'Audit Manager',
                  dueDate: new Date('2025-01-15'),
                  completedAt: new Date('2024-12-20')
                },
                {
                  id: 'sox-404-task-2',
                  title: 'Implement testing framework',
                  description: 'Deploy automated testing infrastructure',
                  status: 'in-progress',
                  assignedTo: 'IT Security Team',
                  dueDate: new Date('2025-02-15')
                }
              ]
            }
          }
        ]
      },
      {
        id: 'pci-dss',
        name: 'PCI-DSS',
        fullName: 'Payment Card Industry Data Security Standard',
        jurisdiction: ['Global'],
        category: 'financial',
        criticality: 'high',
        lastUpdated: new Date('2024-02-01'),
        nextReview: new Date('2025-02-01'),
        penalties: {
          financial: 'Up to $100,000 per month in fines',
          operational: 'Loss of card processing privileges',
          reputational: 'Customer trust erosion'
        },
        requirements: [
          {
            id: 'pci-req-3',
            title: 'Protect Stored Cardholder Data',
            description: 'Encrypt cardholder data at rest and in transit',
            section: 'Requirement 3',
            status: 'non-compliant',
            score: 65,
            lastAssessment: new Date('2024-11-01'),
            nextAssessment: new Date('2025-02-01'),
            automationLevel: 'manual',
            evidence: [
              {
                id: 'pci-req-3-ev-1',
                type: 'technical-control',
                title: 'Encryption Assessment',
                description: 'Current encryption methods for cardholder data',
                source: 'Security Assessment Team',
                collectedAt: new Date('2024-11-01'),
                validUntil: new Date('2025-11-01'),
                confidence: 65,
                automated: false
              }
            ],
            remediation: {
              id: 'pci-req-3-rem-1',
              title: 'Implement Advanced Encryption',
              description: 'Deploy quantum-resistant encryption for all cardholder data',
              priority: 'critical',
              estimatedCost: 150000,
              estimatedTime: '12-16 weeks',
              assignedTo: 'Security Architecture Team',
              dueDate: new Date('2025-03-31'),
              status: 'planned',
              progress: 0,
              tasks: [
                {
                  id: 'pci-req-3-task-1',
                  title: 'Assess current cardholder data inventory',
                  description: 'Complete inventory of all systems storing cardholder data',
                  status: 'pending',
                  assignedTo: 'Data Security Officer',
                  dueDate: new Date('2025-01-31')
                }
              ]
            }
          }
        ]
      }
    ];

    this.generateInitialMetrics();
    this.generateInitialAlerts();
  }

  private generateInitialMetrics(): void {
    const totalRequirements = this.regulations.reduce((sum, reg) => sum + reg.requirements.length, 0);
    const compliantRequirements = this.regulations.reduce((sum, reg) => 
      sum + reg.requirements.filter(req => req.status === 'compliant').length, 0);
    const partialRequirements = this.regulations.reduce((sum, reg) => 
      sum + reg.requirements.filter(req => req.status === 'partial').length, 0);
    const nonCompliantRequirements = this.regulations.reduce((sum, reg) => 
      sum + reg.requirements.filter(req => req.status === 'non-compliant').length, 0);

    const overallScore = this.regulations.reduce((sum, reg) => {
      const regScore = reg.requirements.reduce((reqSum, req) => reqSum + req.score, 0) / reg.requirements.length;
      return sum + regScore;
    }, 0) / this.regulations.length;

    const criticalViolations = this.regulations.reduce((sum, reg) => 
      sum + reg.requirements.filter(req => req.status === 'non-compliant' && reg.criticality === 'critical').length, 0);

    const fullyAutomated = this.regulations.reduce((sum, reg) => 
      sum + reg.requirements.filter(req => req.automationLevel === 'fully-automated').length, 0);
    const automationLevel = (fullyAutomated / totalRequirements) * 100;

    // Generate historical trend data
    const trendsData: ComplianceTrend[] = [];
    for (let i = 30; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      
      trendsData.push({
        date,
        overallScore: Math.max(75, overallScore + (Math.random() - 0.5) * 10),
        regulationScores: {
          'gdpr': Math.max(85, 98 + (Math.random() - 0.5) * 8),
          'hipaa': Math.max(80, 97 + (Math.random() - 0.5) * 10),
          'sox': Math.max(70, 93 + (Math.random() - 0.5) * 15),
          'pci-dss': Math.max(50, 65 + (Math.random() - 0.5) * 20)
        },
        violations: Math.floor(Math.random() * 3),
        remediations: Math.floor(Math.random() * 5)
      });
    }

    this.metrics = {
      overallScore: Math.round(overallScore),
      totalRequirements,
      compliantRequirements,
      partialRequirements,
      nonCompliantRequirements,
      criticalViolations,
      upcomingDeadlines: 3,
      automationLevel: Math.round(automationLevel),
      lastFullAssessment: new Date('2024-12-01'),
      nextFullAssessment: new Date('2025-03-01'),
      trendsData
    };
  }

  private generateInitialAlerts(): void {
    this.alerts = [
      {
        id: 'alert-1',
        severity: 'critical',
        type: 'violation',
        regulation: 'PCI-DSS',
        requirement: 'Requirement 3',
        title: 'Non-compliant Cardholder Data Encryption',
        description: 'Current encryption methods do not meet PCI-DSS Requirement 3 standards for cardholder data protection.',
        impact: 'Risk of losing card processing privileges and potential fines up to $100,000/month',
        recommendedAction: 'Implement quantum-resistant encryption for all cardholder data storage and transmission',
        createdAt: new Date('2024-12-20T10:30:00Z'),
        assignedTo: 'Security Architecture Team'
      },
      {
        id: 'alert-2',
        severity: 'high',
        type: 'expiring-evidence',
        regulation: 'HIPAA',
        requirement: '164.312(a)',
        title: 'Access Control Evidence Expiring',
        description: 'Technical control evidence for HIPAA access control requirements expires in 45 days.',
        impact: 'Potential compliance gap if not renewed before expiration',
        recommendedAction: 'Schedule renewal of access control testing and documentation',
        createdAt: new Date('2024-12-18T14:15:00Z'),
        assignedTo: 'Compliance Team'
      },
      {
        id: 'alert-3',
        severity: 'medium',
        type: 'status-change',
        regulation: 'SOX',
        requirement: 'Section 404',
        title: 'Internal Control Status Updated',
        description: 'SOX Section 404 compliance status changed from compliant to partial due to incomplete testing.',
        impact: 'May affect quarterly financial reporting certification',
        recommendedAction: 'Complete internal control testing and implement automated controls',
        createdAt: new Date('2024-12-15T09:45:00Z'),
        assignedTo: 'Internal Audit Team'
      },
      {
        id: 'alert-4',
        severity: 'info',
        type: 'new-requirement',
        regulation: 'GDPR',
        requirement: 'Article 25',
        title: 'New Data Protection by Design Guidance',
        description: 'EU authorities published new guidance on implementing data protection by design principles.',
        impact: 'Opportunity to enhance GDPR compliance score',
        recommendedAction: 'Review new guidance and assess current implementation',
        createdAt: new Date('2024-12-10T16:20:00Z')
      }
    ];
  }

  private startRealTimeMonitoring(): void {
    this.monitoringInterval = setInterval(() => {
      this.updateMetrics();
      this.checkForNewAlerts();
    }, 30000); // Update every 30 seconds
  }

  private updateMetrics(): void {
    if (!this.metrics) return;

    // Simulate slight changes in compliance scores
    this.regulations.forEach(regulation => {
      regulation.requirements.forEach(requirement => {
        if (requirement.status === 'partial' || requirement.status === 'non-compliant') {
          // Gradual improvement for non-compliant items
          requirement.score = Math.min(100, requirement.score + Math.random() * 2);
          
          if (requirement.score > 95 && requirement.status === 'partial') {
            requirement.status = 'compliant';
          } else if (requirement.score > 80 && requirement.status === 'non-compliant') {
            requirement.status = 'partial';
          }
        }
      });
    });

    // Recalculate overall metrics
    this.generateInitialMetrics();
  }

  private checkForNewAlerts(): void {
    // Simulate occasional new alerts
    if (Math.random() < 0.05) { // 5% chance every 30 seconds
      const alertTypes: ComplianceAlert['type'][] = ['violation', 'expiring-evidence', 'status-change', 'audit-finding'];
      const severities: ComplianceAlert['severity'][] = ['low', 'medium', 'high'];
      const regulations = ['GDPR', 'HIPAA', 'SOX', 'PCI-DSS'];

      const newAlert: ComplianceAlert = {
        id: `alert-${Date.now()}`,
        severity: severities[Math.floor(Math.random() * severities.length)],
        type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
        regulation: regulations[Math.floor(Math.random() * regulations.length)],
        requirement: 'Various',
        title: 'Automated Compliance Check',
        description: 'Automated system detected a compliance status change requiring attention.',
        impact: 'Minor impact on overall compliance posture',
        recommendedAction: 'Review and acknowledge this automated alert',
        createdAt: new Date()
      };

      this.alerts.unshift(newAlert);
      
      // Keep only the latest 20 alerts
      if (this.alerts.length > 20) {
        this.alerts = this.alerts.slice(0, 20);
      }
    }
  }

  // Public API methods
  getRegulations(): ComplianceRegulation[] {
    return [...this.regulations];
  }

  getRegulationById(id: string): ComplianceRegulation | undefined {
    return this.regulations.find(reg => reg.id === id);
  }

  getMetrics(): ComplianceMetrics | null {
    return this.metrics ? { ...this.metrics } : null;
  }

  getAlerts(): ComplianceAlert[] {
    return [...this.alerts];
  }

  getUnacknowledgedAlerts(): ComplianceAlert[] {
    return this.alerts.filter(alert => !alert.acknowledgedAt);
  }

  acknowledgeAlert(alertId: string): void {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledgedAt = new Date();
    }
  }

  resolveAlert(alertId: string): void {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.resolvedAt = new Date();
    }
  }

  getComplianceByRegulation(): { [regulationId: string]: number } {
    const result: { [regulationId: string]: number } = {};
    
    this.regulations.forEach(regulation => {
      const totalScore = regulation.requirements.reduce((sum, req) => sum + req.score, 0);
      result[regulation.id] = Math.round(totalScore / regulation.requirements.length);
    });
    
    return result;
  }

  getUpcomingDeadlines(): Array<{
    regulation: string;
    requirement: string;
    type: 'assessment' | 'evidence-renewal' | 'remediation';
    dueDate: Date;
    priority: 'critical' | 'high' | 'medium' | 'low';
  }> {
    const deadlines: Array<any> = [];
    
    this.regulations.forEach(regulation => {
      regulation.requirements.forEach(requirement => {
        // Assessment deadlines
        const daysUntilAssessment = Math.ceil(
          (requirement.nextAssessment.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        );
        
        if (daysUntilAssessment <= 30) {
          deadlines.push({
            regulation: regulation.name,
            requirement: requirement.title,
            type: 'assessment',
            dueDate: requirement.nextAssessment,
            priority: daysUntilAssessment <= 7 ? 'critical' : 
                     daysUntilAssessment <= 14 ? 'high' : 'medium'
          });
        }
        
        // Evidence renewal deadlines
        requirement.evidence.forEach(evidence => {
          const daysUntilExpiry = Math.ceil(
            (evidence.validUntil.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
          );
          
          if (daysUntilExpiry <= 60) {
            deadlines.push({
              regulation: regulation.name,
              requirement: requirement.title,
              type: 'evidence-renewal',
              dueDate: evidence.validUntil,
              priority: daysUntilExpiry <= 14 ? 'critical' : 
                       daysUntilExpiry <= 30 ? 'high' : 'medium'
            });
          }
        });
        
        // Remediation deadlines
        if (requirement.remediation) {
          const daysUntilRemediation = Math.ceil(
            (requirement.remediation.dueDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
          );
          
          if (daysUntilRemediation <= 45) {
            deadlines.push({
              regulation: regulation.name,
              requirement: requirement.title,
              type: 'remediation',
              dueDate: requirement.remediation.dueDate,
              priority: requirement.remediation.priority
            });
          }
        }
      });
    });
    
    return deadlines.sort((a, b) => a.dueDate.getTime() - b.dueDate.getTime());
  }

  stopMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
  }
}
