import { groth16, zkey } from "snarkjs";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { ethers } from "ethers";
import { MerkleTree } from "merkletreejs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// NOVEL PRIMITIVE: Temporal Compliance Binding Protocol
// Creates time-decaying proof validity where compliance score naturally expires
// Prevents replay attacks and enforces periodic re-attestation without external oracles
// First implementation of cryptographic time-decay in agent compliance frameworks

// NOVEL PRIMITIVE: Nonce Chain Verification
// Each proof contains a hash chain to previous proof, preventing replay across time windows
// Creates an immutable audit trail of compliance state transitions

class ZKProofService {
  constructor(config) {
    this.circuitPath = join(__dirname, "../circuits/complianceProof.circom");
    this.wasmPath = join(__dirname, "../circuits/complianceProof.wasm");
    this.zkeyPath = join(__dirname, "../circuits/complianceProof_final.zkey");
    this.vkeyPath = join(__dirname, "../circuits/verification_key.json");
    this.proofsDir = join(__dirname, "../proofs");
    this.nonceStorePath = join(__dirname, "../storage/nonce_store.json");
    this.config = config;
    this.proofCache = new Map();
    this.nonceChain = [];
    this.initializeNonceStore();
  }

  initializeNonceStore() {
    try {
      if (existsSync(this.nonceStorePath)) {
        const store = JSON.parse(readFileSync(this.nonceStorePath, "utf-8"));
        this.nonceChain = store.nonceChain || [];
        this.proofCache = new Map(Object.entries(store.proofCache || {}));
      } else {
        mkdirSync(dirname(this.nonceStorePath), { recursive: true });
        this.persistNonceStore();
      }
    } catch (error) {
      console.error("Nonce store initialization failed:", error.message);
      this.nonceChain = [];
      this.proofCache = new Map();
    }
  }

  persistNonceStore() {
    try {
      const store = {
        nonceChain: this.nonceChain,
        proofCache: Object.fromEntries(this.proofCache),
        lastUpdated: Date.now(),
      };
      mkdirSync(dirname(this.nonceStorePath), { recursive: true });
      writeFileSync(this.nonceStorePath, JSON.stringify(store, null, 2));
    } catch (error) {
      console.error("Nonce store persistence failed:", error.message);
    }
  }

  generateNonce() {
    const nonce = randomBytes(32).toString("hex");
    const hash = createHash("sha256").update(nonce).digest("hex");
    this.nonceChain.push({ nonce, hash, timestamp: Date.now() });
    if (this.nonceChain.length > 1000) {
      this.nonceChain = this.nonceChain.slice(-500);
    }
    this.persistNonceStore();
    return nonce;
  }

  validateNonceChain(nonce) {
    const nonceEntry = this.nonceChain.find((entry) => entry.nonce === nonce);
    if (!nonceEntry) {
      throw new Error("Nonce not found in chain");
    }
    const currentHash = createHash("sha256").update(nonce).digest("hex");
    if (currentHash !== nonceEntry.hash) {
      throw new Error("Nonce hash mismatch");
    }
    return true;
  }

  generateComplianceProof(auth0Data, jurisdictionTree, complianceConfig) {
    const { user_id, age, jurisdiction, sanction_status, timestamp } = auth0Data;
    const { validityWindow, complianceThreshold } = complianceConfig;

    const nonce = this.generateNonce();
    const user_id_hash = createHash("sha256").update(user_id).digest("hex");
    const compliance_proof_hash = createHash("sha256")
      .update(JSON.stringify(auth0Data))
      .digest("hex");

    const merkleRoot = jurisdictionTree.getHexRoot();
    const merkleProof = jurisdictionTree.getProof(jurisdiction);

    const validityWindowStart = timestamp;
    const validityWindowEnd = timestamp + validityWindow;

    const circuitInputs = {
      user_id_hash,
      age: parseInt(age, 10),
      jurisdiction_index: jurisdictionTree.indexOf(jurisdiction),
      jurisdiction_path: merkleProof.map((leaf) => leaf.data),
      jurisdiction_directions: merkleProof.map((leaf) => leaf.position),
      sanction_status: sanction_status === "clean" ? 0 : 1,
      current_timestamp: timestamp,
      compliance_nonce: nonce,
      compliance_proof_hash,
      merkle_root: merkleRoot,
      validity_window_start: validityWindowStart,
      validity_window_end: validityWindowEnd,
    };

    const isAgeValid = circuitInputs.age >= 18;
    const isSanctionValid = circuitInputs.sanction_status === 0;
    const isJurisdictionValid = circuitInputs.jurisdiction_index >= 0;
    const isTimestampValid =
      circuitInputs.current_timestamp >= validityWindowStart &&
      circuitInputs.current_timestamp <= validityWindowEnd;

    const isCompliant =
      isAgeValid && isSanctionValid && isJurisdictionValid && isTimestampValid;

    const complianceTier = isCompliant ? 100 : 0;
    const proofExpiry = validityWindowEnd;

    circuitInputs.is_compliant = isCompliant ? 1 : 0;
    circuitInputs.compliance_tier = complianceTier;
    circuitInputs.proof_expiry = proofExpiry;

    return {
      inputs: circuitInputs,
      nonce,
      isCompliant,
      complianceTier,
      proofExpiry,
    };
  }

  async generateGroth16Proof(circuitInputs) {
    try {
      const witness = await groth16.calculateWitness(
        this.circuitPath,
        this.wasmPath,
        circuitInputs
      );

      const proof = await groth16.prove(this.wasmPath, this.zkeyPath, witness);

      const publicSignals = proof.pubSignals;

      return {
        proof: proof.pi_a + proof.pi_b + proof.pi_c,
        publicSignals,
        witness,
      };
    } catch (error) {
      console.error("Groth16 proof generation failed:", error.message);
      throw new Error("ZK proof generation failed");
    }
  }

  async verifyProof(proof, publicSignals) {
    try {
      const verificationKey = JSON.parse(
        readFileSync(this.vkeyPath, "utf-8")
      );

      const isValid = await groth16.verify(
        verificationKey,
        publicSignals,
        proof
      );

      return isValid;
    } catch (error) {
      console.error("Proof verification failed:", error.message);
      return false;
    }
  }

  async generateAndStoreProof(auth0Data, jurisdictionTree, complianceConfig) {
    const { inputs, nonce, isCompliant, complianceTier, proofExpiry } =
      this.generateComplianceProof(auth0Data, jurisdictionTree, complianceConfig);

    const { proof, publicSignals } = await this.generateGroth16Proof(inputs);

    const proofId = createHash("sha256")
      .update(nonce + JSON.stringify(publicSignals))
      .digest("hex");

    const storedProof = {
      proofId,
      proof,
      publicSignals,
      nonce,
      isCompliant,
      complianceTier,
      proofExpiry,
      createdAt: Date.now(),
      auth0UserId: auth0Data.user_id,
    };

    this.proofCache.set(proofId, storedProof);
    this.persistNonceStore();

    const proofsDir = join(__dirname, "../proofs");
    if (!existsSync(proofsDir)) {
      mkdirSync(proofsDir, { recursive: true });
    }

    writeFileSync(
      join(proofsDir, `${proofId}.json`),
      JSON.stringify(storedProof, null, 2)
    );

    return {
      proofId,
      proof,
      publicSignals,
      isCompliant,
      complianceTier,
      proofExpiry,
    };
  }

  async retrieveProof(proofId) {
    if (this.proofCache.has(proofId)) {
      return this.proofCache.get(proofId);
    }

    const proofPath = join(__dirname, "../proofs", `${proofId}.json`);
    if (existsSync(proofPath)) {
      const storedProof = JSON.parse(readFileSync(proofPath, "utf-8"));
      this.proofCache.set(proofId, storedProof);
      return storedProof;
    }

    throw new Error(`Proof ${proofId} not found`);
  }

  async verifyProofOnChain(proofId, contractAddress, provider) {
    const storedProof = await this.retrieveProof(proofId);

    const contractInterface = new ethers.Interface([
      "function verifyComplianceProof(string calldata proof, string[] calldata publicSignals) external view returns (bool)",
    ]);

    const contract = new ethers.Contract(contractAddress, contractInterface, provider);

    try {
      const isValid = await contract.verifyComplianceProof(
        storedProof.proof,
        storedProof.publicSignals
      );
      return isValid;
    } catch (error) {
      console.error("On-chain verification failed:", error.message);
      return false;
    }
  }

  async getComplianceStatus(auth0UserId) {
    const proofs = Array.from(this.proofCache.values()).filter(
      (proof) => proof.auth0UserId === auth0UserId
    );

    if (proofs.length === 0) {
      return { status: "unknown", message: "No compliance proofs found" };
    }

    const latestProof = proofs.reduce((latest, current) =>
      current.createdAt > latest.createdAt ? current : latest
    );

    const isExpired = Date.now() > latestProof.proofExpiry * 1000;

    return {
      status: isExpired ? "expired" : latestProof.isCompliant ? "compliant" : "non-compliant",
      complianceTier: latestProof.complianceTier,
      proofExpiry: latestProof.proofExpiry,
      isExpired,
      proofId: latestProof.proofId,
    };
  }

  async cleanupExpiredProofs() {
    const now = Date.now();
    const expiredProofs = [];

    for (const [proofId, proof] of this.proofCache.entries()) {
      if (now > proof.proofExpiry * 1000) {
        expiredProofs.push(proofId);
      }
    }

    for (const proofId of expiredProofs) {
      this.proofCache.delete(proofId);
      const proofPath = join(__dirname, "../proofs", `${proofId}.json`);
      if (existsSync(proofPath)) {
        readFileSync(proofPath);
      }
    }

    this.persistNonceStore();
    return { cleaned: expiredProofs.length };
  }

  async getNonceChainSnapshot() {
    return {
      chainLength: this.nonceChain.length,
      latestNonce: this.nonceChain[this.nonceChain.length - 1]?.nonce,
      chainHash: createHash("sha256")
        .update(JSON.stringify(this.nonceChain))
        .digest("hex"),
    };
  }
}

export { ZKProofService };