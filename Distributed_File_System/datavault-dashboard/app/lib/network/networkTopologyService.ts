export interface NetworkNode {
  id: string;
  name: string;
  type: 'datacenter' | 'edge' | 'cdn' | 'gateway' | 'client';
  region: string;
  country: string;
  position: {
    x: number;
    y: number;
    z: number;
  };
  status: 'online' | 'offline' | 'maintenance' | 'warning';
  metrics: {
    cpu: number;
    memory: number;
    bandwidth: number;
    latency: number;
    connections: number;
    throughput: number; // GB/s
    uptime: number; // percentage
  };
  security: {
    threatLevel: 'low' | 'medium' | 'high' | 'critical';
    encryptionStatus: 'quantum-resistant' | 'standard' | 'legacy';
    complianceLevel: number; // percentage
  };
  connections: string[]; // connected node IDs
}

export interface NetworkConnection {
  id: string;
  source: string;
  target: string;
  type: 'fiber' | 'satellite' | 'wireless' | 'quantum';
  bandwidth: number; // Mbps
  latency: number; // ms
  utilization: number; // percentage
  security: 'encrypted' | 'quantum-encrypted' | 'plain';
  status: 'active' | 'congested' | 'failed';
}

export interface DataFlow {
  id: string;
  source: string;
  target: string;
  size: number; // MB
  type: 'file_transfer' | 'backup' | 'sync' | 'compliance_report';
  priority: 'low' | 'medium' | 'high' | 'critical';
  progress: number; // percentage
  estimatedTime: number; // seconds
}

export class NetworkTopologyService {
  private static instance: NetworkTopologyService;
  private nodes: NetworkNode[] = [];
  private connections: NetworkConnection[] = [];
  private dataFlows: DataFlow[] = [];
  private updateInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.initializeNetwork();
    this.startRealTimeUpdates();
  }

  static getInstance(): NetworkTopologyService {
    if (!NetworkTopologyService.instance) {
      NetworkTopologyService.instance = new NetworkTopologyService();
    }
    return NetworkTopologyService.instance;
  }

  private initializeNetwork(): void {
    // Global datacenter nodes
    this.nodes = [
      {
        id: 'dc-us-east',
        name: 'US East (Virginia)',
        type: 'datacenter',
        region: 'North America',
        country: 'United States',
        position: { x: -2, y: 1, z: 0 },
        status: 'online',
        metrics: {
          cpu: 45,
          memory: 67,
          bandwidth: 10000,
          latency: 12,
          connections: 1247,
          throughput: 8.5,
          uptime: 99.99
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'quantum-resistant',
          complianceLevel: 98
        },
        connections: ['dc-us-west', 'dc-eu-central', 'edge-us-east-1']
      },
      {
        id: 'dc-us-west',
        name: 'US West (California)',
        type: 'datacenter',
        region: 'North America',
        country: 'United States',
        position: { x: -4, y: 1, z: -1 },
        status: 'online',
        metrics: {
          cpu: 52,
          memory: 71,
          bandwidth: 12000,
          latency: 8,
          connections: 934,
          throughput: 9.2,
          uptime: 99.97
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'quantum-resistant',
          complianceLevel: 99
        },
        connections: ['dc-us-east', 'dc-apac', 'edge-us-west-1']
      },
      {
        id: 'dc-eu-central',
        name: 'EU Central (Frankfurt)',
        type: 'datacenter',
        region: 'Europe',
        country: 'Germany',
        position: { x: 1, y: 2, z: 1 },
        status: 'online',
        metrics: {
          cpu: 38,
          memory: 59,
          bandwidth: 8000,
          latency: 15,
          connections: 843,
          throughput: 7.1,
          uptime: 99.98
        },
        security: {
          threatLevel: 'medium',
          encryptionStatus: 'quantum-resistant',
          complianceLevel: 97
        },
        connections: ['dc-us-east', 'dc-apac', 'edge-eu-1']
      },
      {
        id: 'dc-apac',
        name: 'APAC (Singapore)',
        type: 'datacenter',
        region: 'Asia Pacific',
        country: 'Singapore',
        position: { x: 3, y: 0, z: 2 },
        status: 'online',
        metrics: {
          cpu: 61,
          memory: 78,
          bandwidth: 6000,
          latency: 22,
          connections: 567,
          throughput: 5.8,
          uptime: 99.95
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'quantum-resistant',
          complianceLevel: 96
        },
        connections: ['dc-us-west', 'dc-eu-central', 'edge-apac-1']
      },
      // Edge nodes
      {
        id: 'edge-us-east-1',
        name: 'Edge NYC',
        type: 'edge',
        region: 'North America',
        country: 'United States',
        position: { x: -1.5, y: 2, z: 0.5 },
        status: 'online',
        metrics: {
          cpu: 23,
          memory: 34,
          bandwidth: 1000,
          latency: 3,
          connections: 234,
          throughput: 1.2,
          uptime: 99.8
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'standard',
          complianceLevel: 89
        },
        connections: ['dc-us-east']
      },
      {
        id: 'edge-us-west-1',
        name: 'Edge LA',
        type: 'edge',
        region: 'North America',
        country: 'United States',
        position: { x: -3.5, y: 0.5, z: -0.5 },
        status: 'online',
        metrics: {
          cpu: 41,
          memory: 56,
          bandwidth: 1200,
          latency: 4,
          connections: 198,
          throughput: 1.8,
          uptime: 99.7
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'standard',
          complianceLevel: 92
        },
        connections: ['dc-us-west']
      },
      {
        id: 'edge-eu-1',
        name: 'Edge London',
        type: 'edge',
        region: 'Europe',
        country: 'United Kingdom',
        position: { x: 0.5, y: 2.5, z: 0.8 },
        status: 'warning',
        metrics: {
          cpu: 78,
          memory: 89,
          bandwidth: 800,
          latency: 6,
          connections: 156,
          throughput: 0.9,
          uptime: 98.5
        },
        security: {
          threatLevel: 'medium',
          encryptionStatus: 'standard',
          complianceLevel: 94
        },
        connections: ['dc-eu-central']
      },
      {
        id: 'edge-apac-1',
        name: 'Edge Tokyo',
        type: 'edge',
        region: 'Asia Pacific',
        country: 'Japan',
        position: { x: 4, y: 1, z: 2.5 },
        status: 'online',
        metrics: {
          cpu: 55,
          memory: 67,
          bandwidth: 900,
          latency: 8,
          connections: 123,
          throughput: 1.1,
          uptime: 99.2
        },
        security: {
          threatLevel: 'low',
          encryptionStatus: 'quantum-resistant',
          complianceLevel: 95
        },
        connections: ['dc-apac']
      }
    ];

    // Network connections
    this.connections = [
      {
        id: 'conn-1',
        source: 'dc-us-east',
        target: 'dc-us-west',
        type: 'fiber',
        bandwidth: 10000,
        latency: 45,
        utilization: 67,
        security: 'quantum-encrypted',
        status: 'active'
      },
      {
        id: 'conn-2',
        source: 'dc-us-east',
        target: 'dc-eu-central',
        type: 'fiber',
        bandwidth: 8000,
        latency: 89,
        utilization: 54,
        security: 'quantum-encrypted',
        status: 'active'
      },
      {
        id: 'conn-3',
        source: 'dc-us-west',
        target: 'dc-apac',
        type: 'fiber',
        bandwidth: 6000,
        latency: 156,
        utilization: 73,
        security: 'quantum-encrypted',
        status: 'congested'
      },
      {
        id: 'conn-4',
        source: 'dc-eu-central',
        target: 'dc-apac',
        type: 'fiber',
        bandwidth: 7000,
        latency: 198,
        utilization: 41,
        security: 'quantum-encrypted',
        status: 'active'
      }
    ];

    // Active data flows
    this.dataFlows = [
      {
        id: 'flow-1',
        source: 'dc-us-east',
        target: 'dc-eu-central',
        size: 2400,
        type: 'compliance_report',
        priority: 'high',
        progress: 67,
        estimatedTime: 45
      },
      {
        id: 'flow-2',
        source: 'edge-us-west-1',
        target: 'dc-us-west',
        size: 156,
        type: 'sync',
        priority: 'medium',
        progress: 23,
        estimatedTime: 120
      }
    ];
  }

  private startRealTimeUpdates(): void {
    this.updateInterval = setInterval(() => {
      this.updateMetrics();
      this.updateDataFlows();
    }, 2000);
  }

  private updateMetrics(): void {
    this.nodes.forEach(node => {
      // Simulate real-time metric updates
      node.metrics.cpu = Math.max(0, Math.min(100, 
        node.metrics.cpu + (Math.random() - 0.5) * 10
      ));
      node.metrics.memory = Math.max(0, Math.min(100, 
        node.metrics.memory + (Math.random() - 0.5) * 8
      ));
      node.metrics.latency = Math.max(1, 
        node.metrics.latency + (Math.random() - 0.5) * 2
      );
      
      // Update status based on metrics
      if (node.metrics.cpu > 90 || node.metrics.memory > 95) {
        node.status = 'warning';
      } else if (node.metrics.cpu < 80 && node.metrics.memory < 85) {
        node.status = 'online';
      }
    });

    this.connections.forEach(connection => {
      connection.utilization = Math.max(0, Math.min(100,
        connection.utilization + (Math.random() - 0.5) * 15
      ));
      
      if (connection.utilization > 85) {
        connection.status = 'congested';
      } else {
        connection.status = 'active';
      }
    });
  }

  private updateDataFlows(): void {
    this.dataFlows.forEach(flow => {
      if (flow.progress < 100) {
        flow.progress = Math.min(100, flow.progress + Math.random() * 5);
        flow.estimatedTime = Math.max(0, flow.estimatedTime - 2);
      }
    });

    // Remove completed flows and add new ones occasionally
    this.dataFlows = this.dataFlows.filter(flow => flow.progress < 100);
    
    if (Math.random() < 0.1 && this.dataFlows.length < 5) {
      this.addRandomDataFlow();
    }
  }

  private addRandomDataFlow(): void {
    const sourceNodes = this.nodes.filter(n => n.type === 'datacenter');
    const targetNodes = this.nodes.filter(n => n.type === 'datacenter' || n.type === 'edge');
    
    if (sourceNodes.length > 0 && targetNodes.length > 0) {
      const source = sourceNodes[Math.floor(Math.random() * sourceNodes.length)];
      const target = targetNodes[Math.floor(Math.random() * targetNodes.length)];
      
      if (source.id !== target.id) {
        const flowTypes: DataFlow['type'][] = ['file_transfer', 'backup', 'sync', 'compliance_report'];
        const priorities: DataFlow['priority'][] = ['low', 'medium', 'high'];
        
        this.dataFlows.push({
          id: `flow-${Date.now()}`,
          source: source.id,
          target: target.id,
          size: Math.floor(Math.random() * 5000) + 100,
          type: flowTypes[Math.floor(Math.random() * flowTypes.length)],
          priority: priorities[Math.floor(Math.random() * priorities.length)],
          progress: 0,
          estimatedTime: Math.floor(Math.random() * 300) + 30
        });
      }
    }
  }

  // Public API methods
  getNetworkTopology(): {
    nodes: NetworkNode[];
    connections: NetworkConnection[];
    dataFlows: DataFlow[];
  } {
    return {
      nodes: [...this.nodes],
      connections: [...this.connections],
      dataFlows: [...this.dataFlows]
    };
  }

  getNetworkStats(): {
    totalNodes: number;
    activeNodes: number;
    totalConnections: number;
    activeConnections: number;
    totalThroughput: number;
    averageLatency: number;
    globalUptime: number;
  } {
    const activeNodes = this.nodes.filter(n => n.status === 'online').length;
    const activeConnections = this.connections.filter(c => c.status === 'active').length;
    const totalThroughput = this.nodes.reduce((sum, n) => sum + n.metrics.throughput, 0);
    const averageLatency = this.nodes.reduce((sum, n) => sum + n.metrics.latency, 0) / this.nodes.length;
    const globalUptime = this.nodes.reduce((sum, n) => sum + n.metrics.uptime, 0) / this.nodes.length;

    return {
      totalNodes: this.nodes.length,
      activeNodes,
      totalConnections: this.connections.length,
      activeConnections,
      totalThroughput: Math.round(totalThroughput * 10) / 10,
      averageLatency: Math.round(averageLatency * 10) / 10,
      globalUptime: Math.round(globalUptime * 100) / 100
    };
  }

  getNodeById(id: string): NetworkNode | undefined {
    return this.nodes.find(node => node.id === id);
  }

  getSecurityOverview(): {
    quantumResistantNodes: number;
    highThreatNodes: number;
    averageComplianceLevel: number;
    encryptedConnections: number;
  } {
    const quantumResistantNodes = this.nodes.filter(
      n => n.security.encryptionStatus === 'quantum-resistant'
    ).length;
    
    const highThreatNodes = this.nodes.filter(
      n => n.security.threatLevel === 'high' || n.security.threatLevel === 'critical'
    ).length;
    
    const averageComplianceLevel = this.nodes.reduce(
      (sum, n) => sum + n.security.complianceLevel, 0
    ) / this.nodes.length;
    
    const encryptedConnections = this.connections.filter(
      c => c.security.includes('encrypted')
    ).length;

    return {
      quantumResistantNodes,
      highThreatNodes,
      averageComplianceLevel: Math.round(averageComplianceLevel),
      encryptedConnections
    };
  }

  stopUpdates(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }
}
