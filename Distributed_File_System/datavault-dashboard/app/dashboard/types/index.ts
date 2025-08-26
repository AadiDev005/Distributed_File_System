// app/dashboard/types/index.ts

/* ─── Core System Types ──────────────────────────────────────────────── */

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'critical' | 'operational';
  uptime: number;
  version: string;
  timestamp: string;
  peers?: number;
  transport_addr?: string;
  web_api_port?: string;
  enterprise_features?: string[];
  node_id?: string;
  last_health?: string;
  requests?: number;
}

export interface SystemStatus {
  server: {
    node_id: string;
    status: 'operational' | 'degraded' | 'critical';
    version: string;
    uptime: string;
    requests: number;
    last_health: string;
  };
  components: {
    bft_consensus?: BFTComponentStatus;
    post_quantum_crypto?: QuantumComponentStatus;
    dynamic_sharding?: ShardingComponentStatus;
    // ✅ NEW: Dual-mode security component
    dual_mode_security?: DualModeSecurityStatus;
  };
  security_layers: string[];
  timestamp: string;
}

/* ─── ✅ NEW: Security Mode Types ────────────────────────────────────── */

export type SecurityMode = 'simple' | 'enterprise';

export interface SecurityModeInfo {
  current_mode: SecurityMode;
  available_modes: string[];
  description: Record<string, string>;
  features: Record<string, string[]>;
  statistics?: {
    total_files: number;
    enterprise_files: number;
    simple_files: number;
  };
  auto_detection?: {
    triggers: string[];
    enabled: boolean;
  };
}

export interface DualModeSecurityStatus {
  current_mode: SecurityMode;
  auto_detection_enabled: boolean;
  mode_switches_today: number;
  enterprise_triggers: string[];
  status: 'operational' | 'degraded' | 'critical';
  files_by_mode: {
    enterprise: number;
    simple: number;
  };
  security_policies_active: number;
  last_mode_change: string;
}

export interface SecurityModeChangeRequest {
  mode: SecurityMode;
  reason?: string;
  force?: boolean;
}

export interface SecurityModeChangeResponse {
  success: boolean;
  message: string;
  new_mode: SecurityMode;
  previous_mode: SecurityMode;
  timestamp: string;
}

/* ─── Byzantine Fault Tolerance Types ────────────────────────────────── */

export interface BFTStatus {
  consensus_active: boolean;
  node_count: number;
  primary_node: string;
  view_number: number;
  committed_blocks: number;
  total_operations?: number;
  sequence?: number;
  pending_proposals?: number;
  fault_threshold?: number;
  suspected_nodes?: number;
  last_heartbeat?: string;
  average_latency_ms?: number;
  is_primary?: boolean;
}

export interface BFTComponentStatus {
  active_nodes: number;
  committed_blocks: number;
  current_view: number;
  fault_threshold: number;
  is_primary: boolean;
  last_heartbeat: string;
  node_status: 'operational' | 'degraded' | 'critical';
  pending_proposals: number;
  sequence: number;
  suspected_nodes: number;
  total_nodes: number;
  total_operations: number;
  average_latency_ms: number;
}

/* ─── Post-Quantum Cryptography Types ────────────────────────────────── */

export interface QuantumStatus {
  algorithm: string;
  key_generation_time: number;
  signature_time: number;
  verification_time: number;
  quantum_resistant: boolean;
  implementation?: string;
  nist_standardized?: boolean;
  security_level?: string;
  key_pairs?: number;
  signatures_created?: number;
  verifications_performed?: number;
  private_key_size?: number;
  public_key_size?: number;
  signature_cache_size?: number;
  avg_signing_time_ms?: number;
  avg_verification_time_ms?: number;
}

export interface QuantumComponentStatus {
  algorithm: string;
  avg_signing_time_ms: number;
  avg_verification_time_ms: number;
  implementation: string;
  key_generation_time: string;
  key_pairs: number;
  nist_standardized: boolean;
  private_key_size: number;
  public_key_size: number;
  quantum_resistant: boolean;
  security_level: string;
  signature_cache_size: number;
  signatures_created: number;
  status: 'operational' | 'degraded' | 'critical';
  verifications_performed: number;
}

/* ─── Dynamic Sharding Types ─────────────────────────────────────────── */

export interface ShardingStatus {
  total_shards: number;
  replication_factor: number;
  virtual_nodes: number;
  max_shard_size: number;
  active_shards: number;
  total_storage: number;
  hash_ring_size?: number;
  last_rebalance?: string;
  rebalance_count?: number;
  performance_monitoring?: string;
  unhealthy_shards?: number;
  average_shard_size_mb?: number;
  total_data_size_mb?: number;
  total_files?: number;
  total_operations?: number;
  average_latency_ms?: number;
  last_health_check?: string;
  sharding_status?: 'operational' | 'degraded' | 'critical';
  max_shard_size_mb?: number;
}

export interface ShardingComponentStatus {
  active_shards: number;
  average_latency_ms: number;
  average_shard_size_mb: number;
  hash_ring_size: number;
  last_health_check: string;
  last_rebalance: string;
  max_shard_size_mb: number;
  performance_monitoring: string;
  rebalance_count: number;
  replication_factor: number;
  sharding_status: 'operational' | 'degraded' | 'critical';
  total_data_size_mb: number;
  total_files: number;
  total_operations: number;
  total_shards: number;
  unhealthy_shards: number;
  virtual_nodes: number;
}

/* ─── Zero-Trust Security Types ──────────────────────────────────────── */

export interface ZeroTrustStatus {
  gateway_active: boolean;
  security_zones: number;
  active_policies: number;
  threat_level: 'low' | 'medium' | 'high' | 'critical';
  trust_score: number;
  authenticated_users: number;
  node_id?: string;
  status?: 'operational' | 'degraded' | 'critical';
  behavioral_analytics?: boolean;
  compliance_ready?: boolean;
  continuous_monitoring?: boolean;
  device_fingerprinting?: boolean;
  features?: string[];
  geolocation_verification?: boolean;
  last_health_check?: string;
  ml_threat_detection?: boolean;
  quantum_safe_crypto?: boolean;
  risk_based_access?: boolean;
  security_level?: string;
  zero_trust_enabled?: boolean;
  // ✅ NEW: Security mode awareness
  security_mode?: SecurityMode;
  enterprise_policies_active?: number;
}

/* ─── Security and Compliance Types ──────────────────────────────────── */

export interface SecurityModule {
  name: string;
  status: 'Active' | 'Online' | 'Learning' | 'Monitoring' | 'Offline' | 'Error';
  level: number;
  color: 'green' | 'blue' | 'purple' | 'orange' | 'red' | 'yellow';
  // ✅ NEW: Security mode specific info
  available_in_modes?: SecurityMode[];
  enterprise_only?: boolean;
}

export interface ComplianceStatus {
  gdpr_compliant: boolean;
  pii_detection_active: boolean;
  audit_trail_integrity: number;
  policy_violations: number;
  data_retention_compliance: number;
  last_audit: string;
  hipaa_compliant?: boolean;
  sox_compliant?: boolean;
  pci_dss_compliant?: boolean;
  compliance_score?: number;
  // ✅ NEW: Security mode compliance
  enterprise_compliance_active?: boolean;
  simple_mode_compliance_score?: number;
}

/* ─── Performance and Metrics Types ──────────────────────────────────── */

export interface SystemMetrics {
  security_score: number;
  active_users: number;
  data_processed: number;
  compliance_rate: number;
  uptime: number;
  nodes_active: number;
  bft_consensus: boolean;
  timestamp: string;
  total_requests?: number;
  uptime_seconds?: number;
  // ✅ NEW: Security mode metrics
  current_security_mode?: SecurityMode;
  enterprise_mode_usage?: number;
  simple_mode_usage?: number;
  auto_detections_today?: number;
}

export interface PerformanceMetrics {
  efficiency_improvement: number;
  security_enhancement: number;
  performance_boost: number;
  audit_compliance: number;
  availability: number;
  response_time?: number;
  throughput?: number;
  error_rate?: number;
  resource_utilization?: number;
  // ✅ NEW: Mode-specific performance
  enterprise_mode_latency?: number;
  simple_mode_latency?: number;
  security_processing_overhead?: number;
}

/* ─── ✅ ENHANCED: File and Storage Types with Security Mode ──────────── */

export interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size?: number;
  lastModified: string;
  owner: string;
  compliance: 'SOX' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'NONE';
  encrypted: boolean;
  shared: boolean;
  status: 'complete' | 'uploading' | 'error' | 'processing';
  mimeType?: string;
  path?: string;
  pii_risk?: number;
  abe_encrypted?: boolean;
  security_level?: 'standard' | 'enterprise' | 'critical';
  // ✅ NEW: Security mode tracking
  security_mode?: SecurityMode;
  auto_detected_enterprise?: boolean;
  enterprise_reason?: string;
}

export interface FileUploadResponse {
  success: boolean;
  files: FileItem[];
  message?: string;
  total?: number;
  security_applied?: {
    abe_encryption: boolean;
    bft_consensus: boolean;
    gdpr_compliance: boolean;
    immutable_audit: boolean;
    pii_detection: boolean;
    threshold_sharing: boolean;
    // ✅ NEW: Enhanced security tracking
    quantum_encryption?: boolean;
    zero_trust_verified?: boolean;
  };
  // ✅ NEW: Security mode info in response
  security_mode_used?: SecurityMode;
  files_by_security_mode?: {
    simple: number;
    enterprise: number;
  };
  auto_detected_files?: number;
}

export interface FileListResponse {
  success: boolean;
  files: FileItem[];
  total: number;
  // ✅ NEW: Security breakdown in file list
  security_summary?: {
    total_files: number;
    enterprise_files: number;
    simple_files: number;
    encrypted_files: number;
    auto_detected_enterprise: number;
  };
}

/* ─── ✅ ENHANCED: Authentication and User Types ─────────────────────── */

export type UserRole = 'user' | 'admin' | 'superadmin';

export interface User {
  id: string;
  username: string;
  role: UserRole;
  permissions?: string[];
  created_at?: string;
  last_login?: string;
  // ✅ NEW: Security preferences
  preferred_security_mode?: SecurityMode;
  can_change_security_mode?: boolean;
  security_clearance_level?: 'basic' | 'elevated' | 'enterprise';
}

export interface LoginResponse {
  success: boolean;
  session_id: string;
  expires_at: string;
  user: User;
  message?: string;
  // ✅ NEW: Security context in login
  default_security_mode?: SecurityMode;
  available_security_modes?: SecurityMode[];
}

/* ─── Network and Node Types ─────────────────────────────────────────── */

export interface NodeStatus {
  node: number;
  url: string;
  status: 'healthy' | 'error' | 'degraded';
  responseTime?: number;
  active: boolean;
  last_check?: string;
  services?: string[];
  version?: string;
  // ✅ NEW: Security mode support
  supports_enterprise_mode?: boolean;
  current_security_mode?: SecurityMode;
}

export interface NetworkTopology {
  nodes: Array<{
    id: string;
    port: number;
    status: 'healthy' | 'unhealthy' | 'degraded';
    bft_active: boolean;
    responseTime?: number;
    // ✅ NEW: Security mode per node
    security_mode?: SecurityMode;
    enterprise_capable?: boolean;
  }>;
  consensus_active: boolean;
  total_shards: number;
  timestamp: string;
  // ✅ NEW: Network-wide security info
  network_security_mode?: SecurityMode;
  enterprise_nodes_count?: number;
}

/* ─── ✅ NEW: Upload Progress and Security Types ─────────────────────── */

export interface UploadProgress {
  fileId: string;
  fileName: string;
  progress: number;
  status: 'queued' | 'uploading' | 'processing' | 'complete' | 'error';
  stage: string;
  bytesUploaded: number;
  totalBytes: number;
  speed: number;
  estimatedTimeRemaining: number;
  error?: string;
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
  securityModePreference?: SecurityMode;
  forceSecurityMode?: boolean;
}

export interface UploadResult {
  success: boolean;
  fileItem: FileItem;
  securityApplied: SecurityProgress;
  uploadTime: number;
  message?: string;
  error?: string;
  securityModeUsed: SecurityMode;
  securityModeReason: string;
}

/* ─── ✅ NEW: Security Status Response Types ─────────────────────────── */

export interface SecurityStatusResponse {
  success: boolean;
  data: {
    zero_trust: {
      status: string;
      active: boolean;
      features: string[];
    };
    abe: {
      status: string;
      active: boolean;
      features: string[];
    };
    threshold_sharing: {
      status: string;
      active: boolean;
      features: string[];
    };
    immutable_audit: {
      status: string;
      active: boolean;
      features: string[];
    };
    // ✅ NEW: Security mode status
    dual_mode_security?: {
      current_mode: SecurityMode;
      status: string;
      active: boolean;
      features: string[];
    };
  };
  timestamp: string;
  current_security_mode?: SecurityMode;
}

/* ─── API Response Types ─────────────────────────────────────────────── */

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp?: string;
  component?: string;
  status?: string;
  // ✅ NEW: Security context in API responses
  security_mode?: SecurityMode;
  requires_enterprise?: boolean;
}

export interface ErrorResponse {
  success: false;
  error: string;
  message: string;
  timestamp: string;
  code?: number;
  details?: any;
  // ✅ NEW: Security-related error info
  security_violation?: boolean;
  required_security_mode?: SecurityMode;
}

/* ─── ✅ NEW: Dashboard and UI Types ─────────────────────────────────── */

export interface DashboardState {
  securityMode: SecurityMode;
  securityModeInfo: SecurityModeInfo | null;
  systemHealth: SystemHealth | null;
  systemStatus: SystemStatus | null;
  isLoading: boolean;
  error: string | null;
  lastUpdated: Date | null;
}

export interface NotificationState {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
  duration?: number;
  securityRelated?: boolean;
  securityMode?: SecurityMode;
}

/* ─── ✅ NEW: Component Props Types ──────────────────────────────────── */

export interface SecurityModeToggleProps {
  currentMode: SecurityMode;
  onModeChange: (mode: SecurityMode) => Promise<void>;
  disabled?: boolean;
  loading?: boolean;
}

export interface FileUploadProps {
  onUploadComplete?: (files: FileItem[]) => void;
  onError?: (error: string) => void;
  maxFiles?: number;
  maxFileSize?: number;
  uploading?: boolean;
  uploadProgress?: number;
  disabled?: boolean;
  securityMode?: SecurityMode;
}

export interface SecurityBadgeProps {
  mode: SecurityMode;
  autoDetected?: boolean;
  className?: string;
}

/* ─── ✅ NEW: Utility Types ──────────────────────────────────────────── */

export type SecurityModeDetectionTrigger = 
  | 'filename_contains_confidential'
  | 'filename_contains_secret' 
  | 'filename_contains_classified'
  | 'filename_contains_private'
  | 'filename_contains_enterprise'
  | 'file_size_over_50mb'
  | 'user_preference'
  | 'admin_override';

export interface SecurityModeDetectionResult {
  mode: SecurityMode;
  reason: string;
  triggers: SecurityModeDetectionTrigger[];
  autoDetected: boolean;
  confidence: number;
}

export interface SecurityAuditEntry {
  id: string;
  timestamp: string;
  user_id: string;
  action: string;
  resource_id: string;
  security_mode: SecurityMode;
  result: 'success' | 'failure' | 'blocked';
  details: Record<string, any>;
  risk_score?: number;
}


