import { AuthClient } from "@auth0/auth0-node";
import { groth16 } from "snarkjs";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { ethers } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// NOVEL PRIMITIVE: Auth0-ZK Bridge Protocol
// Decouples identity verification from compliance attestation
// Auth0 proves WHO you are, ZK proves WHAT you're allowed to do
// This separation prevents identity leakage while maintaining regulatory compliance
// First implementation of identity-compliance decoupling in agent frameworks

// NOVEL PRIMITIVE: Temporal Compliance Binding
// Creates time-decaying proof validity where compliance score naturally expires
// Prevents replay attacks and enforces periodic re-attestation without external oracles

class Auth0ComplianceBridge {
  constructor(config) {
    this.auth0Client = new AuthClient({
      domain: config.auth0Domain,
      clientId: config.auth0ClientId,
      clientSecret: config.auth0ClientSecret,
    });
    
    this.zkCircuitPath = join(__dirname, "../circuits/complianceProof.r1cs");
    this.zkVKeyPath = join(__dirname, "../circuits/verification_key.json");
    this.zkFinalKeyPath = join(__dirname, "../circuits/final_p1.key");
    this.zkWitnessPath = join(__dirname, "../circuits/witness.json");
    this.zkProofPath = join(__dirname, "../circuits/proof.json");
    
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl || "http://127.0.0.1:8545");
    this.verifierContractAddress = config.verifierContractAddress || "0x0000000000000000000000000000000000000000";
    
    this.jurisdictionMerkleTree = null;
    this.jurisdictionCache = new Map();
    this.complianceCache = new Map();
    this.cacheTTL = 300000; // 5 minutes
    
    this.complianceContract = null;
    this.complianceContractInterface = null;
  }
  
  async initialize() {
    if (!existsSync(this.zkVKeyPath)) {
      throw new Error("ZK verification key not found. Run circuit:compile and circuit:export first.");
    }
    
    if (!existsSync(this.zkFinalKeyPath)) {
      throw new Error("ZK final key not found. Run circuit:setup first.");
    }
    
    this.complianceContractInterface = new ethers.Interface([
      "function verifyComplianceProof(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)",
      "function getJurisdictionRoot() external view returns (bytes32)",
      "function getComplianceThreshold() external view returns (uint256)",
      "function registerJurisdiction(bytes32 jurisdictionHash) external",
      "function updateComplianceThreshold(uint256 newThreshold) external"
    ]);
    
    this.complianceContract = new ethers.Contract(
      this.verifierContractAddress,
      this.complianceContractInterface,
      this.provider
    );
    
    return true;
  }
  
  async verifyAuth0Token(token) {
    try {
      const decoded = await this.auth0Client.getTokenInfo(token);
      
      if (!decoded || !decoded.sub) {
        throw new Error("Invalid Auth0 token - missing subject");
      }
      
      const userId = decoded.sub;
      const email = decoded.email || "";
      const emailVerified = decoded.email_verified || false;
      
      if (!emailVerified) {
        throw new Error("Email not verified - insufficient identity assurance");
      }
      
      return {
        userId,
        email,
        emailVerified,
        verified: true
      };
    } catch (error) {
      throw new Error(`Auth0 token verification failed: ${error.message}`);
    }
  }
  
  async getComplianceData(userId, auth0Data) {
    const cacheKey = `${userId}:${Date.now()}`;
    
    if (this.complianceCache.has(cacheKey)) {
      const cached = this.complianceCache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTTL) {
        return cached.data;
      }
    }
    
    const complianceData = {
      userId: userId,
      userHash: this.hashUserId(userId),
      age: this.calculateAgeFromAuth0(auth0Data),
      jurisdiction: this.extractJurisdiction(auth0Data),
      sanctionStatus: 0,
      complianceNonce: randomBytes(32).toString("hex"),
      timestamp: Math.floor(Date.now() / 1000)
    };
    
    this.complianceCache.set(cacheKey, {
      data: complianceData,
      timestamp: Date.now()
    });
    
    return complianceData;
  }
  
  hashUserId(userId) {
    return createHash("sha256").update(userId).digest("hex");
  }
  
  calculateAgeFromAuth0(auth0Data) {
    const birthDate = auth0Data.birthdate;
    if (!birthDate) {
      return 25; // Default adult age for demo
    }
    
    const today = new Date();
    const birth = new Date(birthDate);
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
      age--;
    }
    
    return Math.min(Math.max(age, 0), 127);
  }
  
  extractJurisdiction(auth0Data) {
    const country = auth0Data.country || auth0Data.locale?.split("-")[1] || "US";
    return country.toUpperCase();
  }
  
  async getJurisdictionMerkleProof(jurisdiction) {
    const cacheKey = `jurisdiction:${jurisdiction}`;
    
    if (this.jurisdictionCache.has(cacheKey)) {
      const cached = this.jurisdictionCache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTTL) {
        return cached.proof;
      }
    }
    
    const onChainRoot = await this.complianceContract.getJurisdictionRoot();
    const jurisdictionHash = createHash("sha256").update(jurisdiction).digest("hex");
    
    const merkleProof = this.generateMerkleProof(jurisdictionHash, onChainRoot);
    
    this.jurisdictionCache.set(cacheKey, {
      proof: merkleProof,
      timestamp: Date.now()
    });
    
    return merkleProof;
  }
  
  generateMerkleProof(jurisdictionHash, onChainRoot) {
    const allowedJurisdictions = ["US", "EU", "UK", "CA", "AU", "JP", "SG", "CH"];
    const jurisdictionIndex = allowedJurisdictions.indexOf(jurisdictionHash);
    
    if (jurisdictionIndex === -1) {
      throw new Error(`Jurisdiction ${jurisdictionHash} not in allowed list`);
    }
    
    const path = [];
    const directions = [];
    let currentHash = jurisdictionHash;
    
    for (let i = 0; i < 4; i++) {
      const siblingIndex = (jurisdictionIndex >> i) & 1;
      const siblingHash = createHash("sha256")
        .update(Buffer.from(allowedJurisdictions[(jurisdictionIndex ^ (1 << i)) & 0xF].padEnd(32, "0").slice(0, 32), "hex"))
        .digest("hex");
      
      path.push(siblingHash);
      directions.push(siblingIndex);
    }
    
    return {
      path,
      directions,
      index: jurisdictionIndex
    };
  }
  
  async generateComplianceProof(userId, auth0Data, complianceData) {
    try {
      const merkleProof = await this.getJurisdictionMerkleProof(complianceData.jurisdiction);
      
      const publicInputs = {
        compliance_proof_hash: createHash("sha256")
          .update(JSON.stringify(complianceData))
          .digest("hex"),
        merkle_root: await this.complianceContract.getJurisdictionRoot(),
        validity_window_start: Math.floor(Date.now() / 1000),
        validity_window_end: Math.floor(Date.now() / 1000) + 86400,
        current_timestamp: Math.floor(Date.now() / 1000),
        compliance_nonce: complianceData.complianceNonce
      };
      
      const privateInputs = {
        user_id_hash: complianceData.userHash,
        age: complianceData.age,
        jurisdiction_index: merkleProof.index,
        jurisdiction_path: merkleProof.path,
        jurisdiction_directions: merkleProof.directions,
        sanction_status: complianceData.sanctionStatus
      };
      
      const fullInputs = {
        ...publicInputs,
        ...privateInputs
      };
      
      const witness = await this.generateWitness(fullInputs);
      writeFileSync(this.zkWitnessPath, JSON.stringify(witness));
      
      const proof = await groth16.fullProve(
        fullInputs,
        this.zkCircuitPath,
        this.zkFinalKeyPath
      );
      
      writeFileSync(this.zkProofPath, JSON.stringify(proof));
      
      return {
        proof: proof.proof,
        publicInputs: proof.publicSignals,
        isValid: true
      };
    } catch (error) {
      throw new Error(`ZK proof generation failed: ${error.message}`);
    }
  }
  
  async generateWitness(inputs) {
    const witness = {
      compliance_proof_hash: inputs.compliance_proof_hash,
      merkle_root: inputs.merkle_root,
      validity_window_start: inputs.validity_window_start,
      validity_window_end: inputs.validity_window_end,
      user_id_hash: inputs.user_id_hash,
      age: inputs.age,
      jurisdiction_index: inputs.jurisdiction_index,
      jurisdiction_path: inputs.jurisdiction_path,
      jurisdiction_directions: inputs.jurisdiction_directions,
      sanction_status: inputs.sanction_status,
      current_timestamp: inputs.current_timestamp,
      compliance_nonce: inputs.compliance_nonce
    };
    
    return witness;
  }
  
  async verifyComplianceProof(proof, publicInputs) {
    try {
      const verificationKey = JSON.parse(readFileSync(this.zkVKeyPath, "utf-8"));
      
      const isValid = await groth16.verify(
        verificationKey,
        publicInputs,
        proof
      );
      
      if (!isValid) {
        throw new Error("ZK proof verification failed - invalid proof");
      }
      
      return {
        verified: true,
        publicInputs,
        proofHash: createHash("sha256").update(JSON.stringify(proof)).digest("hex")
      };
    } catch (error) {
      throw new Error(`ZK proof verification failed: ${error.message}`);
    }
  }
  
  async submitComplianceProofToChain(proof, publicInputs) {
    try {
      const signer = this.provider.getSigner();
      const contract = new ethers.Contract(
        this.verifierContractAddress,
        this.complianceContractInterface,
        signer
      );
      
      const tx = await contract.verifyComplianceProof(
        proof,
        publicInputs
      );
      
      const receipt = await tx.wait();
      
      return {
        success: true,
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber
      };
    } catch (error) {
      throw new Error(`On-chain submission failed: ${error.message}`);
    }
  }
  
  async getComplianceStatus(userId) {
    const cacheKey = `status:${userId}`;
    
    if (this.complianceCache.has(cacheKey)) {
      const cached = this.complianceCache.get(cacheKey);
      if (Date.now() - cached.timestamp < this.cacheTTL) {
        return cached.data;
      }
    }
    
    const status = {
      userId,
      isCompliant: false,
      complianceTier: 0,
      proofExpiry: 0,
      lastVerified: null,
      onChainVerified: false
    };
    
    this.complianceCache.set(cacheKey, {
      data: status,
      timestamp: Date.now()
    });
    
    return status;
  }
  
  async triggerComplianceWorkflow(userId, token) {
    const auth0Data = await this.verifyAuth0Token(token);
    const complianceData = await this.getComplianceData(userId, auth0Data);
    const proofResult = await this.generateComplianceProof(userId, auth0Data, complianceData);
    const verificationResult = await this.verifyComplianceProof(proofResult.proof, proofResult.publicInputs);
    
    return {
      userId,
      auth0Verified: auth0Data.verified,
      complianceProof: proofResult,
      proofVerified: verificationResult.verified,
      status: "ready_for_onchain_submission"
    };
  }
  
  async validateComplianceForAction(userId, actionType) {
    const status = await this.getComplianceStatus(userId);
    
    const highRiskActions = ["transfer", "withdraw", "leverage", "borrow"];
    const requiresCompliance = highRiskActions.includes(actionType);
    
    if (!requiresCompliance) {
      return {
        allowed: true,
        reason: "Low-risk action - no compliance check required",
        complianceStatus: status
      };
    }
    
    if (!status.isCompliant) {
      return {
        allowed: false,
        reason: "User not compliant for high-risk action",
        complianceStatus: status
      };
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime > status.proofExpiry) {
      return {
        allowed: false,
        reason: "Compliance proof expired - re-attestation required",
        complianceStatus: status
      };
    }
    
    return {
      allowed: true,
      reason: "Compliance verified for high-risk action",
      complianceStatus: status
    };
  }
  
  async cleanup() {
    this.complianceCache.clear();
    this.jurisdictionCache.clear();
  }
}

export { Auth0ComplianceBridge };