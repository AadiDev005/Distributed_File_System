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

  // ✅ ENHANCED: Add audit event to pending events with better validation
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

  // ✅ FIXED: Create genesis block with proper resourceType
  private createGenesisBlock(): AuditBlock {
    const genesisEvent: AuditEvent = {
      id: 'genesis',
      timestamp: new Date(),
      userId: 'system',
      action: 'create',
      resourceId: 'audit-chain',
      resourceType: 'system', // ✅ FIXED: Now properly typed
      metadata: { 
        genesis: true,
        chainInitialization: true,
        blockchainVersion: '1.0.0'
      },
      complianceFlags: ['system-initialization', 'blockchain-genesis'],
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

  // ✅ ENHANCED: Mine new block with improved proof-of-work and logging
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

    // Proof-of-work mining with enhanced logging
    console.log(`⛏️ Mining audit block ${blockIndex} with ${newBlock.events.length} events...`);
    const startTime = Date.now();
    
    const target = Array(this.chain.difficulty + 1).join('0');
    while (newBlock.hash.substring(0, this.chain.difficulty) !== target) {
      newBlock.nonce++;
      newBlock.hash = this.calculateBlockHash(newBlock);
      
      // Progress logging for long mining operations
      if (newBlock.nonce % 10000 === 0) {
        console.log(`⛏️ Mining progress: ${newBlock.nonce} attempts...`);
      }
    }

    const miningTime = Date.now() - startTime;
    console.log(`✅ Block ${blockIndex} mined in ${miningTime}ms with nonce ${newBlock.nonce}`);
    console.log(`📦 Block hash: ${newBlock.hash}`);
    console.log(`🔗 Merkle root: ${newBlock.merkleRoot}`);

    this.chain.blocks.push(newBlock);
    this.chain.pendingEvents = [];

    return newBlock;
  }

  // ✅ ENHANCED: Comprehensive chain integrity verification
  verifyChainIntegrity(): {
    isValid: boolean;
    errors: string[];
    blockCount: number;
    eventCount: number;
    verificationTimestamp: Date;
  } {
    const errors: string[] = [];
    let eventCount = 0;
    const verificationStart = Date.now();

    console.log('🔍 Starting blockchain integrity verification...');

    for (let i = 1; i < this.chain.blocks.length; i++) {
      const currentBlock = this.chain.blocks[i];
      const previousBlock = this.chain.blocks[i - 1];

      eventCount += currentBlock.events.length;

      // Verify block hash
      const recalculatedHash = this.calculateBlockHash(currentBlock);
      if (currentBlock.hash !== recalculatedHash) {
        errors.push(`Block ${i} has invalid hash. Expected: ${recalculatedHash}, Got: ${currentBlock.hash}`);
      }

      // Verify previous hash link
      if (currentBlock.previousHash !== previousBlock.hash) {
        errors.push(`Block ${i} has invalid previous hash link. Expected: ${previousBlock.hash}, Got: ${currentBlock.previousHash}`);
      }

      // Verify Merkle root
      const recalculatedMerkleRoot = this.calculateMerkleRoot(currentBlock.events);
      if (currentBlock.merkleRoot !== recalculatedMerkleRoot) {
        errors.push(`Block ${i} has invalid Merkle root. Expected: ${recalculatedMerkleRoot}, Got: ${currentBlock.merkleRoot}`);
      }

      // Verify proof-of-work
      const target = Array(this.chain.difficulty + 1).join('0');
      if (currentBlock.hash.substring(0, this.chain.difficulty) !== target) {
        errors.push(`Block ${i} doesn't meet proof-of-work difficulty ${this.chain.difficulty}`);
      }
    }

    const verificationTime = Date.now() - verificationStart;
    const isValid = errors.length === 0;

    console.log(`${isValid ? '✅' : '❌'} Blockchain verification completed in ${verificationTime}ms`);
    console.log(`📊 Verified ${this.chain.blocks.length} blocks with ${eventCount} events`);
    
    if (!isValid) {
      console.log('❌ Integrity errors found:', errors);
    }

    return {
      isValid,
      errors,
      blockCount: this.chain.blocks.length,
      eventCount,
      verificationTimestamp: new Date()
    };
  }

  // ✅ ENHANCED: Query audit events with comprehensive cryptographic proof
  queryEvents(filter: {
    userId?: string;
    action?: string;
    resourceType?: string;
    startDate?: Date;
    endDate?: Date;
    complianceFlags?: string[];
  }): {
    events: AuditEvent[];
    proof: {
      blockHashes: string[];
      merkleProofs: string[];
      verified: boolean;
      queryTimestamp: Date;
      totalBlocks: number;
      matchingBlocks: number;
    };
  } {
    const matchingEvents: AuditEvent[] = [];
    const blockHashes: string[] = [];
    const merkleProofs: string[] = [];
    let matchingBlocks = 0;

    console.log('🔍 Querying audit events with filter:', filter);

    this.chain.blocks.forEach((block, index) => {
      const filteredEvents = block.events.filter(event => {
        if (filter.userId && event.userId !== filter.userId) return false;
        if (filter.action && event.action !== filter.action) return false;
        if (filter.resourceType && event.resourceType !== filter.resourceType) return false;
        if (filter.startDate && event.timestamp < filter.startDate) return false;
        if (filter.endDate && event.timestamp > filter.endDate) return false;
        if (filter.complianceFlags && !filter.complianceFlags.some(flag => 
          event.complianceFlags?.includes(flag))) return false;
        return true;
      });

      if (filteredEvents.length > 0) {
        matchingEvents.push(...filteredEvents);
        blockHashes.push(block.hash);
        merkleProofs.push(block.merkleRoot);
        matchingBlocks++;
      }
    });

    const verification = this.verifyChainIntegrity();

    console.log(`📊 Query found ${matchingEvents.length} events in ${matchingBlocks} blocks`);

    return {
      events: matchingEvents,
      proof: {
        blockHashes,
        merkleProofs,
        verified: verification.isValid,
        queryTimestamp: new Date(),
        totalBlocks: this.chain.blocks.length,
        matchingBlocks
      }
    };
  }

  // ✅ ENHANCED: Export audit trail with comprehensive metadata
  exportAuditTrail(format: 'json' | 'csv' | 'pdf' = 'json'): {
    data: any;
    integrity: any;
    exportMetadata: any;
  } {
    console.log(`📤 Exporting audit trail in ${format} format...`);
    
    const integrity = this.verifyChainIntegrity();
    const chainStats = this.getChainStats();
    
    const exportMetadata = {
      exportDate: new Date(),
      totalBlocks: this.chain.blocks.length,
      totalEvents: integrity.eventCount,
      chainIntegrity: integrity.isValid,
      exportFormat: format,
      systemVersion: '1.0.0',
      blockchainVersion: '1.0.0',
      difficulty: this.chain.difficulty,
      pendingEvents: this.chain.pendingEvents.length,
      lastBlockHash: chainStats.lastBlockHash,
      exportId: this.generateEventId()
    };

    if (format === 'json') {
      return {
        data: {
          chain: this.chain,
          events: this.getAllEvents(),
          statistics: chainStats
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

  // ✅ ENHANCED: Private helper methods with improved crypto simulation
  private calculateBlockHash(block: AuditBlock): string {
    const blockData = `${block.id}${block.timestamp.toISOString()}${block.previousHash}${block.merkleRoot}${block.nonce}`;
    return this.sha256(blockData);
  }

  private calculateEventHash(event: AuditEvent): string {
    const eventData = `${event.userId}${event.action}${event.resourceId}${event.timestamp.toISOString()}${JSON.stringify(event.metadata || {})}`;
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

  // ✅ ENHANCED: Improved hash function with better distribution
  private sha256(data: string): string {
    // Enhanced hash function for better distribution (still simplified for demo)
    let hash = 0;
    let secondaryHash = 0;
    
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
      
      // Secondary hash for better distribution
      secondaryHash = ((secondaryHash << 3) - secondaryHash) + char;
      secondaryHash = secondaryHash & secondaryHash;
    }
    
    const combinedHash = Math.abs(hash) ^ Math.abs(secondaryHash);
    return combinedHash.toString(16).padStart(8, '0');
  }

  private generateEventId(): string {
    return 'evt_' + Date.now().toString() + '_' + Math.random().toString(36).substr(2, 9);
  }

  private getAllEvents(): AuditEvent[] {
    return this.chain.blocks.flatMap(block => block.events);
  }

  // ✅ ENHANCED: Public getters with comprehensive stats
  getChainStats() {
    const integrity = this.verifyChainIntegrity();
    const latestBlock = this.chain.blocks[this.chain.blocks.length - 1];
    
    return {
      totalBlocks: this.chain.blocks.length,
      totalEvents: integrity.eventCount,
      pendingEvents: this.chain.pendingEvents.length,
      chainIntegrity: integrity.isValid,
      lastBlockHash: latestBlock?.hash,
      lastBlockTimestamp: latestBlock?.timestamp,
      difficulty: this.chain.difficulty,
      blockSize: this.BLOCK_SIZE,
      averageEventsPerBlock: integrity.eventCount / this.chain.blocks.length,
      integrityErrors: integrity.errors.length,
      systemVersion: '1.0.0'
    };
  }

  getLatestBlocks(count: number = 5): AuditBlock[] {
    return this.chain.blocks.slice(-count);
  }

  // ✅ NEW: Additional utility methods
  getBlockByIndex(index: number): AuditBlock | null {
    return this.chain.blocks[index] || null;
  }

  getEventsByUserId(userId: string): AuditEvent[] {
    return this.queryEvents({ userId }).events;
  }

  getEventsByResourceType(resourceType: string): AuditEvent[] {
    return this.queryEvents({ resourceType }).events;
  }

  getPendingEventsCount(): number {
    return this.chain.pendingEvents.length;
  }

  forceMineBlock(): AuditBlock | null {
    if (this.chain.pendingEvents.length === 0) {
      console.log('⚠️ No pending events to mine');
      return null;
    }
    return this.mineBlock();
  }
}
