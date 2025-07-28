'use client';

import { useRef, useEffect, useState, Suspense } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Text, Sphere, Box, Line } from '@react-three/drei';
import { motion } from 'framer-motion';
import * as THREE from 'three';
import { NetworkTopologyService, NetworkNode, NetworkConnection } from '../../lib/network/networkTopologyService';

// 3D Node Component
function Node3D({ node, isSelected, onSelect }: { 
  node: NetworkNode; 
  isSelected: boolean;
  onSelect: (node: NetworkNode) => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);

  useFrame((state) => {
    if (meshRef.current) {
      // Gentle rotation
      meshRef.current.rotation.y += 0.01;
      
      // Pulsing effect for active nodes
      if (node.status === 'online') {
        meshRef.current.scale.setScalar(
          1 + Math.sin(state.clock.elapsedTime * 2) * 0.1
        );
      }
    }
  });

  const getNodeColor = () => {
    if (isSelected) return '#00ff00';
    switch (node.status) {
      case 'online': return '#00d4ff';
      case 'warning': return '#ff9f0a';
      case 'offline': return '#ff3b30';
      case 'maintenance': return '#af52de';
      default: return '#8e8e93';
    }
  };

  const getNodeSize = () => {
    switch (node.type) {
      case 'datacenter': return 0.3;
      case 'edge': return 0.2;
      case 'cdn': return 0.15;
      case 'gateway': return 0.12;
      case 'client': return 0.1;
      default: return 0.15;
    }
  };

  return (
    <group position={[node.position.x, node.position.y, node.position.z]}>
      {node.type === 'datacenter' ? (
        <Box
          ref={meshRef}
          args={[getNodeSize(), getNodeSize(), getNodeSize()]}
          onClick={() => onSelect(node)}
          onPointerEnter={() => setHovered(true)}
          onPointerLeave={() => setHovered(false)}
        >
          <meshStandardMaterial 
            color={getNodeColor()} 
            emissive={getNodeColor()}
            emissiveIntensity={0.2}
            transparent
            opacity={hovered ? 0.9 : 0.7}
          />
        </Box>
      ) : (
        <Sphere
          ref={meshRef}
          args={[getNodeSize(), 32, 32]}
          onClick={() => onSelect(node)}
          onPointerEnter={() => setHovered(true)}
          onPointerLeave={() => setHovered(false)}
        >
          <meshStandardMaterial 
            color={getNodeColor()} 
            emissive={getNodeColor()}
            emissiveIntensity={0.3}
            transparent
            opacity={hovered ? 0.9 : 0.7}
          />
        </Sphere>
      )}
      
      {/* Node Label */}
      <Text
        position={[0, getNodeSize() + 0.2, 0]}
        fontSize={0.08}
        color={isSelected ? '#00ff00' : '#ffffff'}
        anchorX="center"
        anchorY="middle"
      >
        {node.name}
      </Text>
      
      {/* Status indicator */}
      <Sphere
        position={[getNodeSize() + 0.1, getNodeSize() + 0.1, 0]}
        args={[0.03, 16, 16]}
      >
        <meshBasicMaterial color={getNodeColor()} />
      </Sphere>
    </group>
  );
}

// 3D Connection Component
function Connection3D({ connection, nodes }: { 
  connection: NetworkConnection; 
  nodes: NetworkNode[];
}) {
  const sourceNode = nodes.find(n => n.id === connection.source);
  const targetNode = nodes.find(n => n.id === connection.target);

  if (!sourceNode || !targetNode) return null;

  const getConnectionColor = () => {
    switch (connection.status) {
      case 'active': return '#00d4ff';
      case 'congested': return '#ff9f0a';
      case 'failed': return '#ff3b30';
      default: return '#8e8e93';
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
      lineWidth={connection.utilization / 50} // Width based on utilization
      transparent
      opacity={0.6}
    />
  );
}

// Data Flow Visualization
function DataFlow3D({ dataFlow, nodes }: { 
  dataFlow: any; 
  nodes: NetworkNode[];
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const sourceNode = nodes.find(n => n.id === dataFlow.source);
  const targetNode = nodes.find(n => n.id === dataFlow.target);

  useFrame((state) => {
    if (meshRef.current && sourceNode && targetNode) {
      const progress = (dataFlow.progress || 0) / 100;
      const x = sourceNode.position.x + (targetNode.position.x - sourceNode.position.x) * progress;
      const y = sourceNode.position.y + (targetNode.position.y - sourceNode.position.y) * progress;
      const z = sourceNode.position.z + (targetNode.position.z - sourceNode.position.z) * progress;
      
      meshRef.current.position.set(x, y, z);
      meshRef.current.rotation.x += 0.1;
      meshRef.current.rotation.y += 0.1;
    }
  });

  if (!sourceNode || !targetNode) return null;

  const getFlowColor = () => {
    switch (dataFlow.priority) {
      case 'critical': return '#ff3b30';
      case 'high': return '#ff9f0a';
      case 'medium': return '#00d4ff';
      case 'low': return '#30d158';
      default: return '#8e8e93';
    }
  };

  return (
    <Sphere
      ref={meshRef}
      args={[0.05, 16, 16]}
    >
      <meshBasicMaterial 
        color={getFlowColor()} 
        transparent 
        opacity={0.8}
      />
    </Sphere>
  );
}

// Main 3D Scene
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
      {/* Lighting */}
      <ambientLight intensity={0.6} />
      <directionalLight position={[10, 10, 5]} intensity={1} />
      <pointLight position={[-10, -10, -5]} color="#00d4ff" intensity={0.5} />
      
      {/* Grid */}
      <gridHelper args={[20, 20, '#333333', '#333333']} />
      
      {/* Network Nodes */}
      {networkData.nodes.map((node: NetworkNode) => (
        <Node3D
          key={node.id}
          node={node}
          isSelected={selectedNode?.id === node.id}
          onSelect={onNodeSelect}
        />
      ))}
      
      {/* Network Connections */}
      {networkData.connections.map((connection: NetworkConnection) => (
        <Connection3D
          key={connection.id}
          connection={connection}
          nodes={networkData.nodes}
        />
      ))}
      
      {/* Data Flows */}
      {networkData.dataFlows.map((flow: any) => (
        <DataFlow3D
          key={flow.id}
          dataFlow={flow}
          nodes={networkData.nodes}
        />
      ))}
      
      {/* Controls */}
      <OrbitControls
        enablePan={true}
        enableZoom={true}
        enableRotate={true}
        minDistance={5}
        maxDistance={20}
      />
    </>
  );
}

// Main Component
export default function NetworkTopology3D() {
  const [networkService] = useState(() => NetworkTopologyService.getInstance());
  const [networkData, setNetworkData] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [networkStats, setNetworkStats] = useState<any>(null);
  const [securityOverview, setSecurityOverview] = useState<any>(null);

  useEffect(() => {
    const loadData = () => {
      setNetworkData(networkService.getNetworkTopology());
      setNetworkStats(networkService.getNetworkStats());
      setSecurityOverview(networkService.getSecurityOverview());
    };

    loadData();
    const interval = setInterval(loadData, 2000);

    return () => {
      clearInterval(interval);
      networkService.stopUpdates();
    };
  }, [networkService]);

  if (!networkData) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading 3D Network Topology...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Network Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="text-2xl font-bold text-blue-600 mb-1">
            {networkStats?.activeNodes}/{networkStats?.totalNodes}
          </div>
          <div className="text-sm text-gray-600">Active Nodes</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="text-2xl font-bold text-green-600 mb-1">
            {networkStats?.totalThroughput} GB/s
          </div>
          <div className="text-sm text-gray-600">Global Throughput</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="text-2xl font-bold text-orange-600 mb-1">
            {networkStats?.averageLatency}ms
          </div>
          <div className="text-sm text-gray-600">Avg Latency</div>
        </motion.div>

        <motion.div 
          className="apple-card p-6 text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <div className="text-2xl font-bold text-purple-600 mb-1">
            {networkStats?.globalUptime}%
          </div>
          <div className="text-sm text-gray-600">Global Uptime</div>
        </motion.div>
      </div>

      {/* 3D Visualization */}
      <div className="apple-card overflow-hidden">
        <div className="p-6 border-b border-gray-200">
          <h3 className="text-lg font-semibold">3D Global Network Topology</h3>
          <p className="text-gray-600 text-sm">Interactive visualization of worldwide DataVault infrastructure</p>
        </div>
        
        <div className="h-96 bg-black relative">
          <Canvas camera={{ position: [8, 8, 8], fov: 60 }}>
            <Suspense fallback={null}>
              <NetworkScene
                networkData={networkData}
                selectedNode={selectedNode}
                onNodeSelect={setSelectedNode}
              />
            </Suspense>
          </Canvas>
          
          {/* Controls Info */}
          <div className="absolute top-4 left-4 text-white text-xs bg-black/50 p-2 rounded">
            <div>🖱️ Drag to rotate</div>
            <div>🔍 Scroll to zoom</div>
            <div>👆 Click nodes for details</div>
          </div>
        </div>
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <motion.div
          className="apple-card p-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-semibold">{selectedNode.name}</h3>
              <p className="text-gray-600">{selectedNode.region} • {selectedNode.country}</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${{
              'online': 'bg-green-100 text-green-700',
              'warning': 'bg-orange-100 text-orange-700',
              'offline': 'bg-red-100 text-red-700',
              'maintenance': 'bg-purple-100 text-purple-700'
            }[selectedNode.status]}`}>
              {selectedNode.status.toUpperCase()}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {/* Performance Metrics */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-4">Performance</h4>
              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>CPU Usage</span>
                    <span>{selectedNode.metrics.cpu.toFixed(1)}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-blue-500"
                      style={{ width: `${selectedNode.metrics.cpu}%` }}
                    />
                  </div>
                </div>
                
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Memory Usage</span>
                    <span>{selectedNode.metrics.memory.toFixed(1)}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-purple-500"
                      style={{ width: `${selectedNode.metrics.memory}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 pt-2">
                  <div className="text-center">
                    <div className="text-lg font-bold text-gray-900">{selectedNode.metrics.latency.toFixed(1)}ms</div>
                    <div className="text-xs text-gray-600">Latency</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-gray-900">{selectedNode.metrics.uptime}%</div>
                    <div className="text-xs text-gray-600">Uptime</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Network Metrics */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-4">Network</h4>
              <div className="space-y-4">
                <div className="text-center p-3 bg-blue-50 rounded-lg">
                  <div className="text-xl font-bold text-blue-600">{selectedNode.metrics.throughput} GB/s</div>
                  <div className="text-xs text-gray-600">Throughput</div>
                </div>
                
                <div className="text-center p-3 bg-green-50 rounded-lg">
                  <div className="text-xl font-bold text-green-600">{selectedNode.metrics.connections}</div>
                  <div className="text-xs text-gray-600">Active Connections</div>
                </div>
                
                <div className="text-center p-3 bg-purple-50 rounded-lg">
                  <div className="text-xl font-bold text-purple-600">{selectedNode.metrics.bandwidth.toLocaleString()} Mbps</div>
                  <div className="text-xs text-gray-600">Bandwidth</div>
                </div>
              </div>
            </div>

            {/* Security Status */}
            <div>
              <h4 className="font-semibold text-gray-900 mb-4">Security</h4>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Threat Level</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${{
                    'low': 'bg-green-100 text-green-700',
                    'medium': 'bg-yellow-100 text-yellow-700',
                    'high': 'bg-orange-100 text-orange-700',
                    'critical': 'bg-red-100 text-red-700'
                  }[selectedNode.security.threatLevel]}`}>
                    {selectedNode.security.threatLevel.toUpperCase()}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Encryption</span>
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${{
                    'quantum-resistant': 'bg-blue-100 text-blue-700',
                    'standard': 'bg-gray-100 text-gray-700',
                    'legacy': 'bg-red-100 text-red-700'
                  }[selectedNode.security.encryptionStatus]}`}>
                    {selectedNode.security.encryptionStatus.replace('-', ' ').toUpperCase()}
                  </span>
                </div>
                
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Compliance Level</span>
                    <span>{selectedNode.security.complianceLevel}%</span>
                  </div>
                  <div className="apple-progress">
                    <div 
                      className="apple-progress-fill bg-green-500"
                      style={{ width: `${selectedNode.security.complianceLevel}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Security Overview */}
      {securityOverview && (
        <div className="apple-card p-6">
          <h3 className="text-lg font-semibold mb-4">Global Security Overview</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{securityOverview.quantumResistantNodes}</div>
              <div className="text-sm text-gray-600">Quantum-Resistant Nodes</div>
            </div>
            
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{securityOverview.encryptedConnections}</div>
              <div className="text-sm text-gray-600">Encrypted Connections</div>
            </div>
            
            <div className="text-center p-4 bg-purple-50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">{securityOverview.averageComplianceLevel}%</div>
              <div className="text-sm text-gray-600">Avg Compliance Level</div>
            </div>
            
            <div className="text-center p-4 bg-orange-50 rounded-lg">
              <div className="text-2xl font-bold text-orange-600">{securityOverview.highThreatNodes}</div>
              <div className="text-sm text-gray-600">High Threat Nodes</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
