import { ethers } from 'ethers';
import { z } from 'zod';
import { ComplianceVerifier__factory } from '../typechain-types/index.js';
import { zkProofService } from './zkProofService.js';
import { auth0Service } from './auth0Service.js';

const AGENT_ACTION_SCHEMA = z.object({
  action: z.enum(['transfer', 'withdraw', 'deposit', 'execute', 'query']),
  target: z.string().min(1).max(256),
  amount: z.string().min(1).max(77),
  timestamp: z.number().int().positive(),
  compliance_proof: z.object({
    proof: z.array(z.string()),
    publicInputs: z.array(z.string())
  }),
  agent_id: z.string().min(1).max(256),
  nonce: z.string().min(1).max(64)
});

const COMPLIANCE_TIER = {
  NONE: 0,
  BASIC: 1,
  STANDARD: 2,
  PREMIUM: 3,
  INSTITUTIONAL: 4
};

const ACTION_TIER_REQUIREMENTS = {
  transfer: COMPLIANCE_TIER.PREMIUM,
  withdraw: COMPLIANCE_TIER.PREMIUM,
  deposit: COMPLIANCE_TIER.STANDARD,
  execute: COMPLIANCE_TIER.BASIC,
  query: COMPLIANCE_TIER.NONE
};

class AgentMiddleware {
  constructor({ provider, contractAddress, agentRegistryAddress }) {
    this.provider = provider;
    this.contractAddress = contractAddress;
    this.agentRegistryAddress = agentRegistryAddress;
    this.complianceVerifier = ComplianceVerifier__factory.connect(contractAddress, provider);
    this.agentRegistry = null;
    this.requestCache = new Map();
    this.maxCacheSize = 10000;
    this.cacheTTL = 300000;
    this.replayWindow = 60000;
    this.complianceCache = new Map();
    this.complianceCacheTTL = 60000;
  }

  async initialize() {
    try {
      const registryABI = [
        'function getAgentComplianceTier(address agent) view returns (uint8)',
        'function isAgentRegistered(address agent) view returns (bool)'
      ];
      this.agentRegistry = new ethers.Contract(this.agentRegistryAddress, registryABI, this.provider);
    } catch (error) {
      console.error('Agent registry initialization failed:', error.message);
    }
  }

  async interceptRequest(request) {
    try {
      const validated = AGENT_ACTION_SCHEMA.parse(request);
      const agentId = validated.agent_id;
      const action = validated.action;
      const proof = validated.compliance_proof;
      const nonce = validated.nonce;

      await this.validateAgentIdentity(agentId);
      await this.validateProofIntegrity(proof, validated.timestamp);
      await this.verifyComplianceOnChain(agentId, proof, nonce);
      await this.checkComplianceTier(action, agentId, proof.publicInputs);
      await this.recordAgentAction(agentId, action, validated.timestamp);

      return {
        status: 'APPROVED',
        agentId,
        action,
        complianceTier: await this.getAgentComplianceTier(agentId),
        proofHash: proof.publicInputs[0]
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return { status: 'REJECTED', reason: 'INVALID_REQUEST_SCHEMA', details: error.errors };
      }
      if (error.code === 'REPLAY_ATTACK') {
        return { status: 'REJECTED', reason: 'REPLAY_PROOF_DETECTED', details: error.message };
      }
      if (error.code === 'COMPLIANCE_TIER_MISMATCH') {
        return { status: 'REJECTED', reason: 'INSUFFICIENT_COMPLIANCE_TIER', details: error.message };
      }
      if (error.code === 'PROOF_VERIFICATION_FAILED') {
        return { status: 'REJECTED', reason: 'INVALID_ZK_PROOF', details: error.message };
      }
      return { status: 'REJECTED', reason: 'MIDDLEWARE_ERROR', details: error.message };
    }
  }

  async validateAgentIdentity(agentId) {
    const cached = this.requestCache.get(agentId);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return;
    }

    const authResult = await auth0Service.verifyAgentToken(agentId);
    if (!authResult.valid) {
      throw new Error('INVALID_AGENT_IDENTITY');
    }

    this.requestCache.set(agentId, {
      timestamp: Date.now(),
      agentId
    });

    if (this.requestCache.size > this.maxCacheSize) {
      const oldestKey = this.requestCache.keys().next().value;
      this.requestCache.delete(oldestKey);
    }
  }

  async validateProofIntegrity(proof, timestamp) {
    const proofHash = proof.publicInputs[0];
    const cachedProof = this.complianceCache.get(proofHash);

    if (cachedProof && Date.now() - cachedProof.timestamp < this.complianceCacheTTL) {
      return;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const validityStart = parseInt(proof.publicInputs[2]);
    const validityEnd = parseInt(proof.publicInputs[3]);

    if (currentTime < validityStart || currentTime > validityEnd) {
      throw new Error('PROOF_EXPIRED');
    }

    const nonce = proof.publicInputs[4];
    const nonceHash = ethers.keccak256(ethers.toUtf8Bytes(nonce));
    const cachedNonce = this.complianceCache.get(nonceHash);

    if (cachedNonce) {
      throw new Error('REPLAY_PROOF_DETECTED');
    }

    this.complianceCache.set(proofHash, {
      timestamp: Date.now(),
      proofHash,
      validityEnd
    });

    this.complianceCache.set(nonceHash, {
      timestamp: Date.now(),
      nonceHash
    });

    if (this.complianceCache.size > this.maxCacheSize) {
      const oldestKey = this.complianceCache.keys().next().value;
      this.complianceCache.delete(oldestKey);
    }
  }

  async verifyComplianceOnChain(agentId, proof, nonce) {
    const proofData = proof.proof.map(p => ethers.toBeHex(p, 32));
    const publicInputs = proof.publicInputs.map(p => ethers.toBeHex(p, 32));

    try {
      const isValid = await this.complianceVerifier.verifyProof(
        proofData,
        publicInputs
      );

      if (!isValid) {
        throw new Error('PROOF_VERIFICATION_FAILED');
      }

      const complianceHash = publicInputs[0];
      const nonceChain = publicInputs[4];

      const isNonceValid = await this.complianceVerifier.isNonceValid(
        agentId,
        nonceChain
      );

      if (!isNonceValid) {
        throw new Error('REPLAY_PROOF_DETECTED');
      }

      const complianceTier = parseInt(publicInputs[5]);
      const proofExpiry = parseInt(publicInputs[6]);

      this.complianceCache.set(complianceHash, {
        timestamp: Date.now(),
        complianceTier,
        proofExpiry
      });

    } catch (error) {
      if (error.code === 'PROOF_VERIFICATION_FAILED') {
        throw error;
      }
      throw new Error('PROOF_VERIFICATION_FAILED');
    }
  }

  async checkComplianceTier(action, agentId, publicInputs) {
    const requiredTier = ACTION_TIER_REQUIREMENTS[action];
    const complianceTier = parseInt(publicInputs[5]);

    if (complianceTier < requiredTier) {
      throw new Error('COMPLIANCE_TIER_MISMATCH');
    }

    const agentTier = await this.getAgentComplianceTier(agentId);
    if (agentTier < complianceTier) {
      throw new Error('AGENT_TIER_INSUFFICIENT');
    }
  }

  async recordAgentAction(agentId, action, timestamp) {
    const actionRecord = {
      agentId,
      action,
      timestamp,
      blockNumber: await this.provider.getBlockNumber()
    };

    const actionHash = ethers.keccak256(
      ethers.toUtf8Bytes(JSON.stringify(actionRecord))
    );

    const cachedAction = this.requestCache.get(actionHash);
    if (cachedAction) {
      throw new Error('DUPLICATE_ACTION_DETECTED');
    }

    this.requestCache.set(actionHash, {
      timestamp: Date.now(),
      actionRecord
    });

    if (this.requestCache.size > this.maxCacheSize) {
      const oldestKey = this.requestCache.keys().next().value;
      this.requestCache.delete(oldestKey);
    }
  }

  async getAgentComplianceTier(agentId) {
    try {
      if (this.agentRegistry) {
        const tier = await this.agentRegistry.getAgentComplianceTier(agentId);
        return parseInt(tier);
      }

      const cached = this.complianceCache.get(agentId);
      if (cached && Date.now() - cached.timestamp < this.complianceCacheTTL) {
        return cached.complianceTier;
      }

      return COMPLIANCE_TIER.NONE;
    } catch (error) {
      return COMPLIANCE_TIER.NONE;
    }
  }

  async getComplianceStatus(agentId) {
    try {
      const tier = await this.getAgentComplianceTier(agentId);
      const cached = this.complianceCache.get(agentId);

      return {
        agentId,
        complianceTier: tier,
        isCompliant: tier > COMPLIANCE_TIER.NONE,
        cachedAt: cached ? cached.timestamp : null,
        allowedActions: Object.entries(ACTION_TIER_REQUIREMENTS)
          .filter(([_, requiredTier]) => tier >= requiredTier)
          .map(([action]) => action)
      };
    } catch (error) {
      return {
        agentId,
        complianceTier: COMPLIANCE_TIER.NONE,
        isCompliant: false,
        allowedActions: []
      };
    }
  }

  async revokeCompliance(agentId) {
    try {
      const tx = await this.complianceVerifier.revokeCompliance(agentId);
      await tx.wait();
      this.complianceCache.delete(agentId);
      return { success: true, txHash: tx.hash };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async batchVerify(proofs) {
    const results = [];
    for (const proof of proofs) {
      try {
        const result = await this.interceptRequest(proof);
        results.push(result);
      } catch (error) {
        results.push({
          status: 'REJECTED',
          reason: 'BATCH_VERIFICATION_FAILED',
          details: error.message
        });
      }
    }
    return results;
  }

  async getComplianceMetrics() {
    const totalRequests = this.requestCache.size;
    const cachedCompliance = this.complianceCache.size;
    const approvedRequests = Array.from(this.requestCache.values())
      .filter(record => record.actionRecord?.status === 'APPROVED').length;

    return {
      totalRequests,
      cachedCompliance,
      approvedRequests,
      rejectionRate: totalRequests > 0 ? (totalRequests - approvedRequests) / totalRequests : 0,
      cacheHitRate: cachedCompliance / (totalRequests || 1)
    };
  }
}

const agentMiddleware = new AgentMiddleware({
  provider: null,
  contractAddress: null,
  agentRegistryAddress: null
});

export { agentMiddleware, COMPLIANCE_TIER, ACTION_TIER_REQUIREMENTS };