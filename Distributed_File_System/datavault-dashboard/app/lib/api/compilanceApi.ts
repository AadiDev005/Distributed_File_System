const API_BASE = 'http://localhost:8080/api';

export const complianceApi = {
  async getComplianceStatus() {
    const response = await fetch(`${API_BASE}/compliance/status`);
    if (!response.ok) throw new Error('Failed to fetch compliance status');
    return response.json();
  },

  async getGDPRData() {
    const response = await fetch(`${API_BASE}/compliance/gdpr`);
    if (!response.ok) throw new Error('Failed to fetch GDPR data');
    return response.json();
  },

  async getAuditTrail() {
    const response = await fetch(`${API_BASE}/compliance/audit-trail`);
    if (!response.ok) throw new Error('Failed to fetch audit trail');
    return response.json();
  },

  async getBlockchainAudit() {
    const response = await fetch(`${API_BASE}/audit/blockchain`);
    if (!response.ok) throw new Error('Failed to fetch blockchain audit');
    return response.json();
  },

  async getPolicyRecommendations() {
    const response = await fetch(`${API_BASE}/policy/recommendations`);
    if (!response.ok) throw new Error('Failed to fetch policy recommendations');
    return response.json();
  }
};
