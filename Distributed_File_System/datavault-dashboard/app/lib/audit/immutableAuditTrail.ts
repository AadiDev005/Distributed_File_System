import { AuditEvent } from '../../types/compliance';

interface AuditBlock {
  id: string;
  timestamp: Date;
  previousHash: string;
  events: AuditEvent[];
  hash: string;
  nonce: number;
  merkleRoot: string;
}

interface AuditChain {
  blocks: AuditBlock[];
  pendingEvents: AuditEvent[];
  difficulty: number;
}

export class ImmutableAuditTrail {
  private static instance: ImmutableAuditTrail;
  private chain: AuditChain;
  private readonly BLOCK_SIZE = 10; // Events per block
  private readonly MINING_REWARD = 0; // No mining reward for audit blocks

  private constructor() {
    this.chain = {
      blocks: [this.createGenesisBlock()],
      pendingEvents: [],
      difficulty: 2 // Proof-of-work difficulty
    };
  }

  static getInstance(): ImmutableAuditTrail {
    if (!ImmutableAuditTrail.instance) {
      ImmutableAuditTrail.instance = new ImmutableAuditTrail();
    }
    return ImmutableAuditTrail.instance;
  }

  // Add audit event to pending events
  addAuditEvent(event: AuditEvent): string {
    // Add immutability metadata
    const immutableEvent: AuditEvent = {
      ...event,
      id: event.id || this.generateEventId(),
      timestamp: new Date(),
      metadata: {
        ...event.metadata,
        blockchainHash: this.calculateEventHash(event),
        immutable: true,
        systemVersion: '1.0.0'
      }
    };

    this.chain.pendingEvents.push(immutableEvent);

    // Mine new block if we have enough events
    if (this.chain.pendingEvents.length >= this.BLOCK_SIZE) {
      this.mineBlock();
    }

    console.log('🔍 Audit Event Added:', immutableEvent);
    return immutableEvent.id;
  }

  // Create genesis block
  private createGenesisBlock(): AuditBlock {
    const genesisEvent: AuditEvent = {
      id: 'genesis',
      timestamp: new Date(),
      userId: 'system',
      action: 'create',
      resourceId: 'audit-chain',
      resourceType: 'system',
      metadata: { genesis: true },
      complianceFlags: ['system-initialization'],
      ipAddress: '127.0.0.1',
      userAgent: 'DataVault-System'
    };

    const block: AuditBlock = {
      id: 'block_0',
      timestamp: new Date(),
      previousHash: '0',
      events: [genesisEvent],
      hash: '',
      nonce: 0,
      merkleRoot: this.calculateMerkleRoot([genesisEvent])
    };

    block.hash = this.calculateBlockHash(block);
    return block;
  }

  // Mine new block with proof-of-work
  private mineBlock(): AuditBlock {
    const blockIndex = this.chain.blocks.length;
    const previousBlock = this.chain.blocks[blockIndex - 1];
    
    const newBlock: AuditBlock = {
      id: `block_${blockIndex}`,
      timestamp: new Date(),
      previousHash: previousBlock.hash,
      events: [...this.chain.pendingEvents],
      hash: '',
      nonce: 0,
      merkleRoot: this.calculateMerkleRoot(this.chain.pendingEvents)
    };

    // Proof-of-work mining
    console.log('⛏️ Mining audit block...');
    const startTime = Date.now();
    
    while (newBlock.hash.substring(0, this.chain.difficulty) !== Array(this.chain.difficulty + 1).join('0')) {
      newBlock.nonce++;
      newBlock.hash = this.calculateBlockHash(newBlock);
    }

    const miningTime = Date.now() - startTime;
    console.log(`✅ Block mined in ${miningTime}ms with nonce ${newBlock.nonce}`);

    this.chain.blocks.push(newBlock);
    this.chain.pendingEvents = [];

    return newBlock;
  }

  // Verify chain integrity
  verifyChainIntegrity(): {
    isValid: boolean;
    errors: string[];
    blockCount: number;
    eventCount: number;
  } {
    const errors: string[] = [];
    let eventCount = 0;

    for (let i = 1; i < this.chain.blocks.length; i++) {
      const currentBlock = this.chain.blocks[i];
      const previousBlock = this.chain.blocks[i - 1];

      eventCount += currentBlock.events.length;

      // Verify block hash
      if (currentBlock.hash !== this.calculateBlockHash(currentBlock)) {
        errors.push(`Block ${i} has invalid hash`);
      }

      // Verify previous hash link
      if (currentBlock.previousHash !== previousBlock.hash) {
        errors.push(`Block ${i} has invalid previous hash link`);
      }

      // Verify Merkle root
      if (currentBlock.merkleRoot !== this.calculateMerkleRoot(currentBlock.events)) {
        errors.push(`Block ${i} has invalid Merkle root`);
      }

      // Verify proof-of-work
      if (currentBlock.hash.substring(0, this.chain.difficulty) !== Array(this.chain.difficulty + 1).join('0')) {
        errors.push(`Block ${i} doesn't meet proof-of-work difficulty`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      blockCount: this.chain.blocks.length,
      eventCount
    };
  }

  // Query audit events with cryptographic proof
  queryEvents(filter: {
    userId?: string;
    action?: string;
    resourceType?: string;
    startDate?: Date;
    endDate?: Date;
  }): {
    events: AuditEvent[];
    proof: {
      blockHashes: string[];
      merkleProofs: string[];
      verified: boolean;
    };
  } {
    const matchingEvents: AuditEvent[] = [];
    const blockHashes: string[] = [];
    const merkleProofs: string[] = [];

    this.chain.blocks.forEach(block => {
      const filteredEvents = block.events.filter(event => {
        if (filter.userId && event.userId !== filter.userId) return false;
        if (filter.action && event.action !== filter.action) return false;
        if (filter.resourceType && event.resourceType !== filter.resourceType) return false;
        if (filter.startDate && event.timestamp < filter.startDate) return false;
        if (filter.endDate && event.timestamp > filter.endDate) return false;
        return true;
      });

      if (filteredEvents.length > 0) {
        matchingEvents.push(...filteredEvents);
        blockHashes.push(block.hash);
        merkleProofs.push(block.merkleRoot);
      }
    });

    return {
      events: matchingEvents,
      proof: {
        blockHashes,
        merkleProofs,
        verified: this.verifyChainIntegrity().isValid
      }
    };
  }

  // Export audit trail for legal/compliance purposes
  exportAuditTrail(format: 'json' | 'csv' | 'pdf' = 'json'): {
    data: any;
    integrity: any;
    exportMetadata: any;
  } {
    const integrity = this.verifyChainIntegrity();
    const exportMetadata = {
      exportDate: new Date(),
      totalBlocks: this.chain.blocks.length,
      totalEvents: integrity.eventCount,
      chainIntegrity: integrity.isValid,
      exportFormat: format,
      systemVersion: '1.0.0'
    };

    if (format === 'json') {
      return {
        data: {
          chain: this.chain,
          events: this.getAllEvents()
        },
        integrity,
        exportMetadata
      };
    }

    // For CSV/PDF, would implement specific formatters
    return {
      data: this.chain,
      integrity,
      exportMetadata
    };
  }

  // Private helper methods
  private calculateBlockHash(block: AuditBlock): string {
    const blockData = `${block.id}${block.timestamp}${block.previousHash}${block.merkleRoot}${block.nonce}`;
    return this.sha256(blockData);
  }

  private calculateEventHash(event: AuditEvent): string {
    const eventData = `${event.userId}${event.action}${event.resourceId}${event.timestamp}`;
    return this.sha256(eventData);
  }

  private calculateMerkleRoot(events: AuditEvent[]): string {
    if (events.length === 0) return this.sha256('empty');
    if (events.length === 1) return this.calculateEventHash(events[0]);

    const hashes = events.map(event => this.calculateEventHash(event));
    return this.buildMerkleTree(hashes);
  }

  private buildMerkleTree(hashes: string[]): string {
    if (hashes.length === 1) return hashes[0];

    const newLevel: string[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i];
      const right = i + 1 < hashes.length ? hashes[i + 1] : left;
      newLevel.push(this.sha256(left + right));
    }

    return this.buildMerkleTree(newLevel);
  }

  private sha256(data: string): string {
    // Simplified hash function for demo - in production would use crypto.subtle
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  private generateEventId(): string {
    return 'evt_' + Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
  }

  private getAllEvents(): AuditEvent[] {
    return this.chain.blocks.flatMap(block => block.events);
  }

  // Public getters
  getChainStats() {
    const integrity = this.verifyChainIntegrity();
    return {
      totalBlocks: this.chain.blocks.length,
      totalEvents: integrity.eventCount,
      pendingEvents: this.chain.pendingEvents.length,
      chainIntegrity: integrity.isValid,
      lastBlockHash: this.chain.blocks[this.chain.blocks.length - 1]?.hash,
      difficulty: this.chain.difficulty
    };
  }

  getLatestBlocks(count: number = 5): AuditBlock[] {
    return this.chain.blocks.slice(-count);
  }
}
