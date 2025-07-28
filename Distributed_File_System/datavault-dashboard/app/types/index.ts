export interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size?: number;
  lastModified: Date;
  owner: string;
  compliance: 'GDPR' | 'HIPAA' | 'SOX' | 'PCI-DSS';
  encrypted: boolean;
  shared: boolean;
  status: 'uploading' | 'processing' | 'complete' | 'error';
  progress?: number;
}

export interface User {
  id: string;
  email: string;
  role: 'admin' | 'user';
  name: string;
}

export interface SecurityMetric {
  title: string;
  value: string;
  change?: string;
  trend: 'up' | 'down' | 'stable';
  icon: any;
  color: string;
}
