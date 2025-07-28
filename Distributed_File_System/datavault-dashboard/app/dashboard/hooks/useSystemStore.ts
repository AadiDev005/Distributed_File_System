import { create } from 'zustand';
import { 
  SystemHealth, 
  BFTStatus, 
  QuantumStatus, 
  ShardingStatus, 
  ZeroTrustStatus,
  PerformanceMetrics 
} from '../types';

interface SystemStore {
  health: SystemHealth | null;
  bft: BFTStatus | null;
  quantum: QuantumStatus | null;
  sharding: ShardingStatus | null;
  zeroTrust: ZeroTrustStatus | null;
  performance: PerformanceMetrics;
  loading: boolean;
  error: string | null;
  lastUpdated: string | null;

  setHealth: (health: SystemHealth) => void;
  setBFT: (bft: BFTStatus) => void;
  setQuantum: (quantum: QuantumStatus) => void;
  setSharding: (sharding: ShardingStatus) => void;
  setZeroTrust: (zeroTrust: ZeroTrustStatus) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  updateLastUpdated: () => void;
}

export const useSystemStore = create<SystemStore>((set) => ({
  health: null,
  bft: null,
  quantum: null,
  sharding: null,
  zeroTrust: null,
  performance: {
    efficiency_improvement: 40,
    security_enhancement: 60,
    performance_boost: 35,
    audit_compliance: 100,
    availability: 99.9,
  },
  loading: false,
  error: null,
  lastUpdated: null,

  setHealth: (health) => set({ health }),
  setBFT: (bft) => set({ bft }),
  setQuantum: (quantum) => set({ quantum }),
  setSharding: (sharding) => set({ sharding }),
  setZeroTrust: (zeroTrust) => set({ zeroTrust }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  updateLastUpdated: () => set({ lastUpdated: new Date().toISOString() }),
}));
