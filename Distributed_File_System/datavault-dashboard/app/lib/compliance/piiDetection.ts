import { PIIDetectionResult, PIIType } from '../../types/compliance';

export class PIIDetectionService {
  private static instance: PIIDetectionService;
  
  // PII Detection Patterns (simplified for demo - in production would use ML models)
  private readonly patterns = {
    ssn: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
    creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    medicalId: /\b[A-Z]{2}\d{8}\b/g,
    passport: /\b[A-Z]{1,2}\d{6,9}\b/g
  };

  static getInstance(): PIIDetectionService {
    if (!PIIDetectionService.instance) {
      PIIDetectionService.instance = new PIIDetectionService();
    }
    return PIIDetectionService.instance;
  }

  async analyzeFile(fileId: string, fileName: string, content: string): Promise<PIIDetectionResult> {
    const piiFound: PIIType[] = [];
    
    // Analyze content for each PII type
    for (const [type, pattern] of Object.entries(this.patterns)) {
      const matches = Array.from(content.matchAll(pattern));
      
      matches.forEach((match, index) => {
        const location = this.getLocation(content, match.index || 0);
        piiFound.push({
          type: type as PIIType['type'],
          value: this.maskSensitiveData(match[0]),
          location,
          confidence: this.calculateConfidence(type, match[0]),
          regulation: this.getApplicableRegulations(type as PIIType['type'])
        });
      });
    }

    const result: PIIDetectionResult = {
      fileId,
      fileName,
      piiFound,
      confidenceScore: this.calculateOverallConfidence(piiFound),
      recommendedActions: this.generateRecommendations(piiFound),
      complianceRisk: this.assessComplianceRisk(piiFound)
    };

    return result;
  }

  private getLocation(content: string, index: number) {
    const beforeMatch = content.substring(0, index);
    const line = beforeMatch.split('\n').length;
    const column = beforeMatch.split('\n').pop()?.length || 0;
    
    // Get context around the match
    const contextStart = Math.max(0, index - 50);
    const contextEnd = Math.min(content.length, index + 50);
    const context = content.substring(contextStart, contextEnd);

    return { line, column, context };
  }

  private maskSensitiveData(value: string): string {
    if (value.length <= 4) return '***';
    return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
  }

  private calculateConfidence(type: string, value: string): number {
    // Simplified confidence calculation
    const baseConfidence = {
      ssn: 0.95,
      email: 0.9,
      phone: 0.85,
      creditCard: 0.9,
      medicalId: 0.8,
      passport: 0.75
    };
    
    return baseConfidence[type as keyof typeof baseConfidence] || 0.5;
  }

  private getApplicableRegulations(type: PIIType['type']): string[] {
    const regulationMap = {
      ssn: ['GDPR', 'CCPA'],
      email: ['GDPR', 'CCPA', 'CAN-SPAM'],
      phone: ['GDPR', 'CCPA', 'TCPA'],
      address: ['GDPR', 'CCPA'],
      'credit-card': ['PCI-DSS', 'GDPR'],
      'medical-id': ['HIPAA', 'GDPR'],
      passport: ['GDPR', 'Government']
    };
    
    return regulationMap[type] || ['GDPR'];
  }

  private calculateOverallConfidence(piiFound: PIIType[]): number {
    if (piiFound.length === 0) return 1.0;
    
    const avgConfidence = piiFound.reduce((sum, pii) => sum + pii.confidence, 0) / piiFound.length;
    return Math.round(avgConfidence * 100) / 100;
  }

  private generateRecommendations(piiFound: PIIType[]): string[] {
    const recommendations: string[] = [];
    
    if (piiFound.length === 0) {
      recommendations.push('No PII detected - file is safe for general access');
      return recommendations;
    }

    const piiTypes = [...new Set(piiFound.map(p => p.type))];
    
    if (piiTypes.includes('ssn')) {
      recommendations.push('⚠️ SSN detected - Restrict access and enable audit logging');
      recommendations.push('📋 Required: Data Processing Agreement for GDPR compliance');
    }
    
    if (piiTypes.includes('credit-card')) {
      recommendations.push('🔒 Credit card data detected - PCI-DSS compliance required');
      recommendations.push('🛡️ Enable encryption at rest and in transit');
    }
    
    if (piiTypes.includes('medical-id')) {
      recommendations.push('🏥 Medical data detected - HIPAA compliance required');
      recommendations.push('👥 Limit access to authorized healthcare personnel only');
    }

    recommendations.push('📊 Enable compliance monitoring and regular audits');
    recommendations.push('🔄 Set up automatic data retention policies');
    
    return recommendations;
  }

  private assessComplianceRisk(piiFound: PIIType[]): 'low' | 'medium' | 'high' | 'critical' {
    if (piiFound.length === 0) return 'low';
    
    const highRiskTypes = ['ssn', 'credit-card', 'medical-id', 'passport'];
    const hasHighRisk = piiFound.some(pii => highRiskTypes.includes(pii.type));
    
    if (hasHighRisk && piiFound.length > 5) return 'critical';
    if (hasHighRisk) return 'high';
    if (piiFound.length > 3) return 'medium';
    return 'low';
  }
}
