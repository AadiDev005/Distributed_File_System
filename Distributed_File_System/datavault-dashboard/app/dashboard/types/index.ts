// API Response Types
export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'critical';
  uptime: number;
  version: string;
  timestamp: string;
}

export interface BFTStatus {
  consensus_active: boolean;
  node_count: number;
  primary_node: string;
  view_number: number;
  committed_blocks: number;
}

export interface QuantumStatus {
  algorithm: string;
  key_generation_time: number;
  signature_time: number;
  verification_time: number;
  quantum_resistant: boolean;
}

export interface ShardingStatus {
  total_shards: number;
  replication_factor: number;
  virtual_nodes: number;
  max_shard_size: number;
  active_shards: number;
  total_storage: number;
}

export interface ZeroTrustStatus {
  gateway_active: boolean;
  security_zones: number;
  active_policies: number;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  trust_score: number;
  authenticated_users: number;
}

export interface ComplianceStatus {
  gdpr_compliant: boolean;
  pii_detection_active: boolean;
  audit_trail_integrity: number;
  policy_violations: number;
  data_retention_compliance: number;
  last_audit: string;
}

// Dashboard Metrics
export interface PerformanceMetrics {
  efficiency_improvement: number;
  security_enhancement: number;
  performance_boost: number;
  audit_compliance: number;
  availability: number;
}
