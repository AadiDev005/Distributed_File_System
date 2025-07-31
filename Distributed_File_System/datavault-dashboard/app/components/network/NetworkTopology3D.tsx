'use client';

import React, { useRef, useEffect, useState, Suspense } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Text, Sphere, Box, Line } from '@react-three/drei';
import { motion } from 'framer-motion';
import * as THREE from 'three';

// ✅ Type definitions
type NodeStatus = 'online' | 'warning' | 'offline' | 'maintenance';
type NodeType = 'datacenter' | 'edge' | 'cdn' | 'gateway' | 'client';
type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';
type EncryptionStatus = 'quantum-resistant' | 'standard' | 'legacy';

interface NetworkNode {
  id: string;
  name: string;
  type: NodeType;
  status: NodeStatus;
  region: string;
  country: string;
  position: { x: number; y: number; z: number };
  metrics: {
    cpu: number;
    memory: number;
    latency: number;
    uptime: number;
    throughput: number;
    connections: number;
    bandwidth: number;
  };
  security: {
    threatLevel: ThreatLevel;
    encryptionStatus: EncryptionStatus;
    complianceLevel: number;
  };
}

interface NetworkConnection {
  id: string;
  source: string;
  target: string;
  status: string;
  utilization: number;
}

// ✅ ENHANCED: More spread out node positions for better 3D visibility
const createMockNetworkData = () => ({
  nodes: [
    {
      id: 'datacenter-1',
      name: 'Primary DC',
      type: 'datacenter' as NodeType,
      status: 'online' as NodeStatus,
      region: 'US-East',
      country: 'United States',
      position: { x: 0, y: 0, z: 0 },
      metrics: {
        cpu: 45.2, memory: 67.8, latency: 12.5, uptime: 99.98,
        throughput: 8.5, connections: 1247, bandwidth: 100000
      },
      security: {
        threatLevel: 'low' as ThreatLevel,
        encryptionStatus: 'quantum-resistant' as EncryptionStatus,
        complianceLevel: 98
      }
    },
    {
      id: 'edge-1',
      name: 'Edge SF',
      type: 'edge' as NodeType,
      status: 'online' as NodeStatus,
      region: 'US-West',
      country: 'United States',
      position: { x: -6, y: 3, z: 4 },
      metrics: {
        cpu: 32.1, memory: 54.3, latency: 8.2, uptime: 99.95,
        throughput: 5.2, connections: 892, bandwidth: 50000
      },
      security: {
        threatLevel: 'low' as ThreatLevel,
        encryptionStatus: 'quantum-resistant' as EncryptionStatus,
        complianceLevel: 96
      }
    },
    {
      id: 'gateway-1',
      name: 'Gateway EU',
      type: 'gateway' as NodeType,
      status: 'online' as NodeStatus,
      region: 'EU-Central',
      country: 'Germany',
      position: { x: 6, y: -2, z: -5 },
      metrics: {
        cpu: 58.7, memory: 71.2, latency: 15.8, uptime: 99.92,
        throughput: 6.8, connections: 1543, bandwidth: 75000
      },
      security: {
        threatLevel: 'medium' as ThreatLevel,
        encryptionStatus: 'quantum-resistant' as EncryptionStatus,
        complianceLevel: 94
      }
    },
    {
      id: 'cdn-1',
      name: 'CDN Asia',
      type: 'cdn' as NodeType,
      status: 'warning' as NodeStatus,
      region: 'Asia-Pacific',
      country: 'Singapore',
      position: { x: 4, y: 5, z: -3 },
      metrics: {
        cpu: 78.4, memory: 85.7, latency: 32.1, uptime: 99.89,
        throughput: 12.3, connections: 2156, bandwidth: 120000
      },
      security: {
        threatLevel: 'medium' as ThreatLevel,
        encryptionStatus: 'quantum-resistant' as EncryptionStatus,
        complianceLevel: 92
      }
    },
    {
      id: 'client-1',
      name: 'Client LA',
      type: 'client' as NodeType,
      status: 'online' as NodeStatus,
      region: 'US-West',
      country: 'United States',
      position: { x: -4, y: -5, z: 3 },
      metrics: {
        cpu: 23.1, memory: 34.5, latency: 5.2, uptime: 99.99,
        throughput: 2.1, connections: 156, bandwidth: 10000
      },
      security: {
        threatLevel: 'low' as ThreatLevel,
        encryptionStatus: 'standard' as EncryptionStatus,
        complianceLevel: 88
      }
    }
  ],
  connections: [
    { id: 'conn-1', source: 'datacenter-1', target: 'edge-1', status: 'active', utilization: 65 },
    { id: 'conn-2', source: 'datacenter-1', target: 'gateway-1', status: 'active', utilization: 45 },
    { id: 'conn-3', source: 'edge-1', target: 'gateway-1', status: 'active', utilization: 30 },
    { id: 'conn-4', source: 'datacenter-1', target: 'cdn-1', status: 'congested', utilization: 89 },
    { id: 'conn-5', source: 'edge-1', target: 'client-1', status: 'active', utilization: 25 }
  ],
  dataFlows: [
    { id: 'flow-1', source: 'datacenter-1', target: 'edge-1', priority: 'high', progress: 75 },
    { id: 'flow-2', source: 'datacenter-1', target: 'cdn-1', priority: 'critical', progress: 45 }
  ]
});

// ✅ REAL 3D: Node Component with actual Three.js meshes
function Node3D({ node, isSelected, onSelect }: { 
  node: NetworkNode; 
  isSelected: boolean;
  onSelect: (node: NetworkNode) => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null!);
  const [hovered, setHovered] = useState(false);

  // ✅ REAL 3D: Animation with actual mesh manipulation
  useEffect(() => {
    let animationFrame: number;
    
    const animate = () => {
      if (meshRef.current) {
        // Continuous rotation
        meshRef.current.rotation.y += 0.01;
        
        if (node.status === 'online') {
          const time = Date.now() * 0.001;
          const scale = 1 + Math.sin(time * 1.5) * 0.15;
          meshRef.current.scale.setScalar(scale);
        }
      }
      animationFrame = requestAnimationFrame(animate);
    };

    animate();
    return () => cancelAnimationFrame(animationFrame);
  }, [node.status]);

  const getNodeColor = () => {
    if (isSelected) return '#00FF00';
    switch (node.status) {
      case 'online': return '#007AFF';
      case 'warning': return '#FF9F0A';
      case 'offline': return '#FF3B30';
      case 'maintenance': return '#AF52DE';
      default: return '#8E8E93';
    }
  };

  const getNodeSize = () => {
    switch (node.type) {
      case 'datacenter': return 0.8;
      case 'edge': return 0.5;
      case 'cdn': return 0.6;
      case 'gateway': return 0.4;
      case 'client': return 0.3;
      default: return 0.4;
    }
  };

  const nodeSize = getNodeSize();
  const color = getNodeColor();

  return (
    <group position={[node.position.x, node.position.y, node.position.z]}>
      {/* ✅ REAL 3D: Actual Box/Sphere geometry */}
      {node.type === 'datacenter' ? (
        <Box
          ref={meshRef}
          args={[nodeSize, nodeSize, nodeSize]}
          onClick={() => onSelect(node)}
          onPointerEnter={() => setHovered(true)}
          onPointerLeave={() => setHovered(false)}
        >
          <meshStandardMaterial 
            color={color} 
            emissive={color}
            emissiveIntensity={isSelected ? 0.5 : 0.2}
            transparent
            opacity={hovered ? 1.0 : 0.9}
            roughness={0.1}
            metalness={0.3}
          />
        </Box>
      ) : (
        <Sphere
          ref={meshRef}
          args={[nodeSize, 32, 32]}
          onClick={() => onSelect(node)}
          onPointerEnter={() => setHovered(true)}
          onPointerLeave={() => setHovered(false)}
        >
          <meshStandardMaterial 
            color={color} 
            emissive={color}
            emissiveIntensity={isSelected ? 0.5 : 0.2}
            transparent
            opacity={hovered ? 1.0 : 0.9}
            roughness={0.1}
            metalness={0.3}
          />
        </Sphere>
      )}
      
      {/* ✅ REAL 3D: Text labels floating in 3D space */}
      <Text
        position={[0, nodeSize + 0.6, 0]}
        fontSize={0.3}
        color={isSelected ? '#00FF00' : '#FFFFFF'}
        anchorX="center"
        anchorY="middle"
      >
        {node.name}
      </Text>
      
      {/* ✅ REAL 3D: Status indicator sphere */}
      <Sphere
        args={[0.1, 16, 16]}
        position={[nodeSize * 0.6, nodeSize * 0.6, nodeSize * 0.6]}
      >
        <meshBasicMaterial color={color} />
      </Sphere>
    </group>
  );
}

// ✅ REAL 3D: Connection lines in 3D space
function Connection3D({ connection, nodes }: { 
  connection: NetworkConnection; 
  nodes: NetworkNode[];
}) {
  const sourceNode = nodes.find(n => n.id === connection.source);
  const targetNode = nodes.find(n => n.id === connection.target);

  if (!sourceNode || !targetNode) return null;

  const getConnectionColor = () => {
    switch (connection.status) {
      case 'active': return '#007AFF';
      case 'congested': return '#FF9F0A';
      case 'failed': return '#FF3B30';
      default: return '#8E8E93';
    }
  };

  const points = [
    new THREE.Vector3(sourceNode.position.x, sourceNode.position.y, sourceNode.position.z),
    new THREE.Vector3(targetNode.position.x, targetNode.position.y, targetNode.position.z)
  ];

  return (
    <Line
      points={points}
      color={getConnectionColor()}
      lineWidth={Math.max(connection.utilization / 15, 4)}
      transparent
      opacity={0.8}
    />
  );
}

// ✅ REAL 3D: Animated data flow particles
function DataFlow3D({ dataFlow, nodes }: { 
  dataFlow: any; 
  nodes: NetworkNode[];
}) {
  const meshRef = useRef<THREE.Mesh>(null!);
  const sourceNode = nodes.find(n => n.id === dataFlow.source);
  const targetNode = nodes.find(n => n.id === dataFlow.target);

  useEffect(() => {
    let frameId: number;
    
    const animate = () => {
      if (meshRef.current && sourceNode && targetNode) {
        const time = Date.now() * 0.001;
        const progress = (Math.sin(time * 0.5) + 1) * 0.5;
        
        const x = sourceNode.position.x + (targetNode.position.x - sourceNode.position.x) * progress;
        const y = sourceNode.position.y + (targetNode.position.y - sourceNode.position.y) * progress;
        const z = sourceNode.position.z + (targetNode.position.z - sourceNode.position.z) * progress;
        
        meshRef.current.position.set(x, y, z);
        meshRef.current.rotation.x = time * 3;
        meshRef.current.rotation.y = time * 2;
      }
      frameId = requestAnimationFrame(animate);
    };

    animate();
    return () => cancelAnimationFrame(frameId);
  }, [dataFlow, sourceNode, targetNode]);

  if (!sourceNode || !targetNode) return null;

  const getFlowColor = () => {
    switch (dataFlow.priority) {
      case 'critical': return '#FF3B30';
      case 'high': return '#FF9F0A';
      case 'medium': return '#007AFF';
      case 'low': return '#30D158';
      default: return '#8E8E93';
    }
  };

  return (
    <Sphere
      ref={meshRef}
      args={[0.12, 16, 16]}
    >
      <meshBasicMaterial 
        color={getFlowColor()} 
        transparent 
        opacity={0.9}
      />
    </Sphere>
  );
}

// ✅ REAL 3D: Main scene with proper lighting
function NetworkScene({ 
  networkData, 
  selectedNode, 
  onNodeSelect 
}: { 
  networkData: any;
  selectedNode: NetworkNode | null;
  onNodeSelect: (node: NetworkNode) => void;
}) {
  return (
    <>
      {/* ✅ REAL 3D: Professional lighting setup */}
      <ambientLight intensity={0.6} />
      <directionalLight 
        position={[10, 10, 5]} 
        intensity={1.0} 
        castShadow 
        shadow-mapSize-width={2048}
        shadow-mapSize-height={2048}
      />
      <pointLight position={[-10, 10, -5]} color="#007AFF" intensity={0.4} />
      <pointLight position={[10, -10, 5]} color="#30D158" intensity={0.3} />
      
      {/* ✅ REAL 3D: Grid and reference plane */}
      <gridHelper args={[25, 25, '#333333', '#222222']} />
      
      {/* ✅ REAL 3D: Background sphere for depth */}
      <Sphere args={[50]} position={[0, 0, 0]}>
        <meshBasicMaterial 
          color="#000014" 
          transparent 
          opacity={0.1} 
          side={THREE.BackSide} 
        />
      </Sphere>
      
      {/* ✅ REAL 3D: Render all nodes */}
      {networkData.nodes.map((node: NetworkNode) => (
        <Node3D
          key={node.id}
          node={node}
          isSelected={selectedNode?.id === node.id}
          onSelect={onNodeSelect}
        />
      ))}
      
      {/* ✅ REAL 3D: Render connections */}
      {networkData.connections.map((connection: NetworkConnection) => (
        <Connection3D
          key={connection.id}
          connection={connection}
          nodes={networkData.nodes}
        />
      ))}
      
      {/* ✅ REAL 3D: Render data flows */}
      {networkData.dataFlows.map((flow: any) => (
        <DataFlow3D
          key={flow.id}
          dataFlow={flow}
          nodes={networkData.nodes}
        />
      ))}
      
      {/* ✅ REAL 3D: Interactive camera controls */}
      <OrbitControls
        enablePan={true}
        enableZoom={true}
        enableRotate={true}
        minDistance={8}
        maxDistance={35}
        autoRotate={true}
        autoRotateSpeed={0.5}
        dampingFactor={0.05}
        enableDamping={true}
      />
    </>
  );
}

// Status style functions (same as before)
const getStatusStyleClass = (status: NodeStatus): string => {
  const statusMap: Record<NodeStatus, string> = {
    'online': 'status-online',
    'warning': 'status-warning', 
    'offline': 'status-error',
    'maintenance': 'bg-purple-100 text-purple-700'
  };
  return statusMap[status];
};

const getThreatLevelStyleClass = (threatLevel: ThreatLevel): string => {
  return threatLevel === 'low' ? 'status-online' : 'status-warning';
};

const getEncryptionStyleClass = (encryptionStatus: EncryptionStatus): string => {
  return encryptionStatus === 'quantum-resistant' ? 'status-info' : 'bg-gray-100 text-gray-700';
};

// ✅ MAIN COMPONENT: Guaranteed 3D rendering
export default function NetworkTopology3D() {
  const [networkData, setNetworkData] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [networkStats, setNetworkStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadData = () => {
      const data = createMockNetworkData();
      setNetworkData(data);
      setNetworkStats({
        activeNodes: data.nodes.length,
        totalNodes: data.nodes.length,
        totalThroughput: data.nodes.reduce((sum, node) => sum + node.metrics.throughput, 0).toFixed(1),
        averageLatency: (data.nodes.reduce((sum, node) => sum + node.metrics.latency, 0) / data.nodes.length).toFixed(1),
        globalUptime: (data.nodes.reduce((sum, node) => sum + node.metrics.uptime, 0) / data.nodes.length).toFixed(2)
      });
      setIsLoading(false);
    };

    loadData();
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="apple-body text-gray-600">Loading 3D Network Topology...</p>
        </div>
      </div>
    );
  }

  if (!networkData) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <p className="apple-body text-gray-600">Failed to load network data</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Network Statistics */}
      <motion.div 
        className="enterprise-grid"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        {[
          { 
            label: 'Active Nodes', 
            value: `${networkStats?.activeNodes}/${networkStats?.totalNodes}`,
            color: 'blue',
            icon: '🌐'
          },
          { 
            label: 'Global Throughput', 
            value: `${networkStats?.totalThroughput} GB/s`,
            color: 'green',
            icon: '⚡'
          },
          { 
            label: 'Avg Latency', 
            value: `${networkStats?.averageLatency}ms`,
            color: 'orange',
            icon: '📡'
          },
          { 
            label: 'Global Uptime', 
            value: `${networkStats?.globalUptime}%`,
            color: 'purple',
            icon: '🛡️'
          }
        ].map((stat, index) => (
          <motion.div 
            key={stat.label}
            className="metric-card apple-fade-in-delay"
            style={{ animationDelay: `${index * 100}ms` }}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-2xl">{stat.icon}</span>
              <div className={`text-2xl font-bold text-${stat.color}-600`}>
                {stat.value}
              </div>
            </div>
            <div className="apple-footnote text-gray-600">{stat.label}</div>
          </motion.div>
        ))}
      </motion.div>

      {/* ✅ GUARANTEED 3D: Real Three.js Canvas */}
      <motion.div 
        className="apple-card overflow-hidden"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="apple-title-3">Real 3D Network Topology</h3>
              <p className="apple-subheadline">
                Interactive 3D visualization with WebGL rendering
              </p>
            </div>
            <div className="status-online px-3 py-1 rounded-full text-xs font-medium">
              3D WebGL Active
            </div>
          </div>
        </div>
        
        <div className="h-96 relative">
          {/* ✅ REAL 3D: Direct Canvas usage with no fallbacks */}
          <Canvas 
            camera={{ position: [15, 15, 15], fov: 60 }}
            style={{ 
              background: 'linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%)' 
            }}
          >
            <Suspense fallback={null}>
              <NetworkScene
                networkData={networkData}
                selectedNode={selectedNode}
                onNodeSelect={setSelectedNode}
              />
            </Suspense>
          </Canvas>
          
          <div className="absolute top-4 left-4 text-white text-sm bg-black/60 backdrop-blur-sm p-4 rounded-xl border border-white/20">
            <div className="apple-footnote space-y-2">
              <div className="font-semibold text-green-300">🎮 3D Controls:</div>
              <div>🖱️ Drag to rotate camera</div>
              <div>🔍 Scroll to zoom in/out</div>
              <div>👆 Click nodes for details</div>
              <div className="text-blue-300">📊 Real-time 3D monitoring</div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Node Details Panel */}
      {selectedNode && (
        <motion.div
          className="apple-card p-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ type: "spring", stiffness: 200 }}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="apple-title-2">{selectedNode.name}</h3>
              <p className="apple-subheadline">{selectedNode.region} • {selectedNode.country}</p>
            </div>
            <div className="flex items-center space-x-3">
              <div className={`status-indicator ${getStatusStyleClass(selectedNode.status)}`}>
                {selectedNode.status.toUpperCase()}
              </div>
              <button 
                onClick={() => setSelectedNode(null)}
                className="apple-button-small"
              >
                ✕
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Performance Metrics */}
            <div>
              <h4 className="apple-headline text-gray-900 mb-4">Performance</h4>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between apple-footnote mb-2">
                    <span>CPU Usage</span>
                    <span className="font-semibold">{selectedNode.metrics.cpu.toFixed(1)}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-blue-500"
                      style={{ width: `${selectedNode.metrics.cpu}%` }}
                    />
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between apple-footnote mb-2">
                    <span>Memory Usage</span>
                    <span className="font-semibold">{selectedNode.metrics.memory.toFixed(1)}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-purple-500"
                      style={{ width: `${selectedNode.metrics.memory}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 pt-2">
                  <div className="text-center p-3 bg-blue-50 rounded-lg">
                    <div className="metric-value">{selectedNode.metrics.latency.toFixed(1)}ms</div>
                    <div className="metric-label">Latency</div>
                  </div>
                  <div className="text-center p-3 bg-green-50 rounded-lg">
                    <div className="metric-value">{selectedNode.metrics.uptime}%</div>
                    <div className="metric-label">Uptime</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Network Metrics */}
            <div>
              <h4 className="apple-headline text-gray-900 mb-4">Network</h4>
              <div className="space-y-4">
                <div className="text-center p-4 bg-blue-50 rounded-xl">
                  <div className="text-2xl font-bold text-blue-600 mb-1">{selectedNode.metrics.throughput} GB/s</div>
                  <div className="apple-footnote text-gray-600">Throughput</div>
                </div>
                
                <div className="text-center p-4 bg-green-50 rounded-xl">
                  <div className="text-2xl font-bold text-green-600 mb-1">{selectedNode.metrics.connections.toLocaleString()}</div>
                  <div className="apple-footnote text-gray-600">Active Connections</div>
                </div>
                
                <div className="text-center p-4 bg-purple-50 rounded-xl">
                  <div className="text-2xl font-bold text-purple-600 mb-1">{(selectedNode.metrics.bandwidth / 1000).toFixed(0)}K</div>
                  <div className="apple-footnote text-gray-600">Bandwidth (Mbps)</div>
                </div>
              </div>
            </div>

            {/* Security Status */}
            <div>
              <h4 className="apple-headline text-gray-900 mb-4">Security</h4>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="apple-footnote text-gray-600">Threat Level</span>
                  <span className={`status-indicator ${getThreatLevelStyleClass(selectedNode.security.threatLevel)}`}>
                    {selectedNode.security.threatLevel.toUpperCase()}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="apple-footnote text-gray-600">Encryption</span>
                  <span className={`status-indicator ${getEncryptionStyleClass(selectedNode.security.encryptionStatus)}`}>
                    {selectedNode.security.encryptionStatus.replace('-', ' ').toUpperCase()}
                  </span>
                </div>
                
                <div>
                  <div className="flex justify-between apple-footnote mb-2">
                    <span>Compliance Level</span>
                    <span className="font-semibold">{selectedNode.security.complianceLevel}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-green-500"
                      style={{ width: `${selectedNode.security.complianceLevel}%` }}
                    />
                  </div>
                </div>

                <div className="compliance-badge">
                  SOC 2 Compliant
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
