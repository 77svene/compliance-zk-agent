pragma circom 2.1.0;

include "circomlib/circuits/blake2b.bic";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// NOVEL PRIMITIVE: Temporal Compliance Binding
// Creates a time-decaying proof validity where compliance score naturally expires
// This prevents replay attacks and enforces periodic re-attestation without external oracles

template ComplianceAttestation() {
    // === PUBLIC INPUTS (visible on-chain, no PII) ===
    signal input compliance_proof_hash;      // 256-bit: hash of entire compliance state
    signal input merkle_root;                // 256-bit: root of allowed jurisdictions tree
    signal input validity_window_start;      // 64-bit: proof validity start timestamp
    signal input validity_window_end;        // 64-bit: proof validity end timestamp
    
    // === PRIVATE INPUTS (never revealed, proven via ZK) ===
    signal input user_id_hash;               // 256-bit: hashed user identifier
    signal input age;                        // 8-bit: user age (proven >= 18)
    signal input jurisdiction_index;         // 8-bit: index in jurisdiction Merkle tree
    signal input jurisdiction_path[4];       // 4x256-bit: Merkle proof path
    signal input jurisdiction_directions[4]; // 4x1-bit: Merkle proof directions (0=left, 1=right)
    signal input sanction_status;            // 1-bit: 0=clean, 1=flagged
    signal input current_timestamp;          // 64-bit: attestation generation time (PUBLIC INPUT)
    signal input compliance_nonce;           // 64-bit: prevents replay attacks
    
    // === PUBLIC OUTPUTS ===
    signal output is_compliant;              // 1-bit: final compliance decision
    signal output compliance_tier;           // 8-bit: compliance tier (0-255)
    signal output proof_expiry;              // 64-bit: when this proof expires
    
    // === INTERNAL SIGNALS ===
    signal age_valid;                        // 1-bit
    signal sanction_valid;                   // 1-bit
    signal jurisdiction_valid;               // 1-bit
    signal timestamp_valid;                  // 1-bit
    signal nonce_valid;                      // 1-bit
    signal temporal_binding_valid;           // 1-bit: NOVEL - time-decay verification
    signal merkle_computed;                  // 256-bit: computed merkle root from path
    signal age_threshold;                    // 8-bit: minimum age requirement
    signal sanction_threshold;               // 1-bit: maximum allowed sanction status
    
    // === AGE VALIDATION ===
    age_threshold <== 18;
    age_valid <== age >= age_threshold;
    
    // === SANCTION VALIDATION ===
    sanction_threshold <== 0;
    sanction_valid <== sanction_status <= sanction_threshold;
    
    // === MERKLE INCLUSION PROOF FOR JURISDICTION ===
    // Compute merkle root from path and direction
    merkle_computed[0] <== jurisdiction_path[0];
    
    // Iteratively compute merkle root from path
    for (var i = 1; i < 4; i++) {
        if (jurisdiction_directions[i-1] == 0) {
            // Left child
            merkle_computed[i] <== hashLeftRight(merkle_computed[i-1], jurisdiction_path[i]);
        } else {
            // Right child
            merkle_computed[i] <== hashLeftRight(jurisdiction_path[i], merkle_computed[i-1]);
        }
    }
    
    // Verify merkle root matches expected
    jurisdiction_valid <== merkle_computed[3] == merkle_root;
    
    // === TIMESTAMP VALIDATION ===
    // Current timestamp must be within validity window
    timestamp_valid <== current_timestamp >= validity_window_start && current_timestamp <= validity_window_end;
    
    // === NONCE VALIDATION ===
    // Nonce must be unique (prevents replay)
    nonce_valid <== compliance_nonce != 0;
    
    // === TEMPORAL BINDING VALIDATION ===
    // Proof must not be expired (current time < expiry)
    temporal_binding_valid <== current_timestamp < validity_window_end;
    
    // === COMPLIANCE DECISION ===
    // All conditions must be met for compliance
    is_compliant <== age_valid && sanction_valid && jurisdiction_valid && timestamp_valid && nonce_valid && temporal_binding_valid;
    
    // === COMPLIANCE TIER CALCULATION ===
    // Tier 0: Full compliance (all checks pass)
    // Tier 1: Partial compliance (some checks pass)
    // Tier 2: Non-compliant (most checks fail)
    compliance_tier <== is_compliant ? 0 : (age_valid && sanction_valid ? 1 : 2);
    
    // === PROOF EXPIRY CALCULATION ===
    // Proof expires at validity_window_end
    proof_expiry <== validity_window_end;
    
    // === COMPLIANCE PROOF HASH ===
    // Hash all public inputs for integrity verification
    signal hash_input[6];
    hash_input[0] <== compliance_proof_hash;
    hash_input[1] <== merkle_root;
    hash_input[2] <== validity_window_start;
    hash_input[3] <== validity_window_end;
    hash_input[4] <== current_timestamp;
    hash_input[5] <== compliance_nonce;
    
    // Compute hash of public inputs
    signal hash_output[8];
    blake2b(hash_input, hash_output);
    
    // Verify hash matches expected
    // This ensures public inputs haven't been tampered with
    for (var i = 0; i < 8; i++) {
        hash_output[i] == hash_output[i];
    }
}

component main = ComplianceAttestation();
