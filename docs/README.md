# ComplianceZK: ZK-Verified Agent Regulatory Adherence

## Overview

ComplianceZK is a privacy-preserving middleware layer that enables autonomous agents to execute regulated actions while maintaining zero-knowledge compliance verification. Unlike existing ZK identity solutions (Polygon ID, Worldcoin, Semaphore), ComplianceZK introduces **agent-specific regulatory attestation** — proving compliance status without exposing PII to the agent itself.

### Key Differentiators

| Feature | Existing ZK Identity | ComplianceZK |
|---------|---------------------|--------------|
| Target | Human identity verification | Agent regulatory compliance |
| PII Exposure | Minimal (on-chain) | Zero (agent never sees PII) |
| Compliance Scope | KYC/AML only | KYC/AML + jurisdiction + sanctions + age |
| Agent Integration | Manual verification | Automated ZK proof verification |
| Privacy Model | Pseudonymous | Agent-decoupled identity |

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              COMPLIANCEZK ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────┐   │
│  │   Auth0      │───▶│  ZK Proof        │───▶│  Compliance              │   │
│  │  Identity    │    │  Generation      │    │  Verifier (On-Chain)     │   │
│  │  Provider    │    │  (Circom)        │    │  (Solidity)              │   │
│  └──────────────┘    └──────────────────┘    └──────────────────────────┘   │
│         │                    │                         │                     │
│         │                    ▼                         ▼                     │
│         │           ┌──────────────────┐    ┌──────────────────────────┐   │
│         │           │  Compliance      │    │  Agent                   │   │
│         │           │  Status          │    │  Action Execution        │   │
│         │           │  (ZK Proof)      │    │  (Only receives proof)   │   │
│         │           └──────────────────┘    └──────────────────────────┘   │
│         │                    │                         │                     │
│         ▼                    ▼                         ▼                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    COMPLIANCE MIDDLEWARE LAYER                          ││
│  │  - Auth0 Integration (Identity)                                         ││
│  │  - ZK Circuit Generation (Privacy)                                      ││
│  │  - On-Chain Verification (Trustless)                                    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Note on Centralization**: The Node.js middleware layer is a trust-minimized component that generates ZK proofs. While the middleware is centralized, the **verification is fully on-chain and trustless**. The middleware cannot forge proofs without the private key, and any forged proof will fail on-chain verification. For production deployments, consider running the middleware in a multi-signature configuration or using a decentralized prover network.

---

## Quick Start

### Prerequisites

- Node.js 18+ (LTS)
- npm or yarn
- Hardhat (for contract compilation)
- Circom 2.1.0+ (for circuit compilation)
- Auth0 account with Custom Actions enabled

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/compliancezk.git
cd compliancezk

# Install dependencies
npm install

# Compile Circom circuits
npm run circuit:compile

# Compile Solidity contracts
npx hardhat compile

# Generate verification key
npm run circuit:generate-key

# Set environment variables
cp .env.example .env
# Edit .env with your configuration (see Security section)

# Deploy contracts
npx hardhat run scripts/deploy.js --network <your-network>

# Start API server
npm start
```

### Environment Configuration

```env
# Auth0 Configuration
AUTH0_DOMAIN=your-auth0-domain.auth0.com
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_CLIENT_SECRET=your-auth0-client-secret

# Blockchain Configuration
# ⚠️ SECURITY WARNING: Never commit PRIVATE_KEY to version control
# Use environment variables or secret management (HashiCorp Vault, AWS Secrets Manager)
PRIVATE_KEY=your-deployer-private-key
RPC_URL=https://your-rpc-provider.com
DEPLOYMENT_NETWORK=sepolia

# Circuit Configuration
CIRCUIT_PATH=./circuits/complianceProof.circom
VERIFICATION_KEY_PATH=./circuits/verification_key.json

# API Configuration
API_PORT=3000
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100

# Compliance Configuration
COMPLIANCE_TIER_THRESHOLD=50
JURISDICTION_WHITELIST_PATH=./config/jurisdictions.json
```

---

## Circuit Explanation

### ComplianceAttestation Circuit

The core ZK circuit (`circuits/complianceProof.circom`) implements temporal compliance binding with the following structure:

#### Public Inputs (Visible On-Chain)

| Input | Type | Description |
|-------|------|-------------|
| `compliance_proof_hash` | 256-bit | Hash of entire compliance state |
| `merkle_root` | 256-bit | Root of allowed jurisdictions tree |
| `validity_window_start` | 64-bit | Proof validity start timestamp |
| `validity_window_end` | 64-bit | Proof validity end timestamp |

#### Private Inputs (Never Revealed)

| Input | Type | Description |
|-------|------|-------------|
| `user_id_hash` | 256-bit | Hashed user identifier (never reveals PII) |
| `age` | 8-bit | User age (proven >= 18) |
| `jurisdiction_index` | 8-bit | Index in jurisdiction Merkle tree |
| `jurisdiction_path` | 4x256-bit | Merkle proof path |
| `jurisdiction_directions` | 4x1-bit | Merkle proof directions |
| `sanction_status` | 1-bit | 0=clean, 1=flagged |
| `compliance_nonce` | 64-bit | Prevents replay attacks |

#### Novel Primitive: Temporal Compliance Binding

The circuit implements time-decaying proof validity:

```circom
// Temporal binding ensures proofs expire naturally
// This prevents replay attacks without external oracles
signal input current_timestamp;
signal input validity_window_start;
signal input validity_window_end;

// Age verification (proven >= 18 without revealing exact age)
age >= 18;

// Timestamp validation
current_timestamp >= validity_window_start;
current_timestamp <= validity_window_end;

// Nonce chain verification
compliance_nonce > previous_nonce;
```

#### Circuit Compilation

```bash
# Compile circuit
npm run circuit:compile

# Generate proving key
npm run circuit:generate-key

# Output files:
# - circuits/build/complianceProof_js/
# - circuits/build/complianceProof.wasm
# - circuits/verification_key.json
```

---

## API Documentation

### Base URL

```
http://localhost:3000/api/v1
```

### Authentication

All endpoints require an Auth0 Bearer token in the `Authorization` header:

```
Authorization: Bearer <auth0-token>
```

### Endpoints

#### 1. Generate Compliance Proof

**POST** `/compliance/generate-proof`

Generates a ZK proof attesting to user compliance status.

**Request Body:**
```json
{
  "user_id": "auth0|123456789",
  "age": 25,
  "jurisdiction": "US",
  "sanction_status": 0,
  "nonce": "random-uuid"
}
```

**Response:**
```json
{
  "success": true,
  "proof": {
    "public_inputs": [
      "0x1234...",
      "0x5678...",
      "1704067200",
      "1706745600"
    ],
    "proof": [
      "0xabc...",
      "0xdef...",
      "0x123..."
    ]
  },
  "proof_hash": "0x9876543210abcdef",
  "expires_at": "2024-02-01T00:00:00Z"
}
```

#### 2. Verify Compliance Proof

**POST** `/compliance/verify-proof`

Verifies a ZK proof against the on-chain verifier contract.

**Request Body:**
```json
{
  "public_inputs": ["0x1234...", "0x5678...", "1704067200", "1706745600"],
  "proof": ["0xabc...", "0xdef...", "0x123..."]
}
```

**Response:**
```json
{
  "success": true,
  "verified": true,
  "compliance_tier": 75,
  "valid_until": "2024-02-01T00:00:00Z",
  "on_chain_tx": "0xabcdef123456"
}
```

#### 3. Agent Action Authorization

**POST** `/agent/authorize`

Authorizes an agent to execute a high-risk action based on compliance proof.

**Request Body:**
```json
{
  "agent_id": "agent-123",
  "action_type": "transfer",
  "amount": "1000",
  "proof_hash": "0x9876543210abcdef",
  "nonce": "agent-nonce-456"
}
```

**Response:**
```json
{
  "success": true,
  "authorized": true,
  "compliance_tier": 75,
  "action_hash": "0xaction123",
  "rate_limit_remaining": 99
}
```

#### 4. Compliance Status Dashboard

**GET** `/compliance/status/:user_id`

Returns compliance status for a user (for dashboard visualization).

**Response:**
```json
{
  "user_id": "auth0|123456789",
  "compliance_tier": 75,
  "proof_valid": true,
  "proof_expires_at": "2024-02-01T00:00:00Z",
  "jurisdiction": "US",
  "sanction_status": "clean",
  "last_verified": "2024-01-01T12:00:00Z"
}
```

#### 5. Rate Limit Check

**GET** `/compliance/rate-limit/:client_id`

Checks rate limit status for a client (on-chain enforced).

**Response:**
```json
{
  "client_id": "client-123",
  "requests_remaining": 99,
  "window_reset_at": "2024-01-01T12:01:00Z",
  "on_chain_state": "verified"
}
```

---

## Security Audit Notes

### Critical Security Considerations

#### 1. Private Key Management

**⚠️ CRITICAL**: Never store `PRIVATE_KEY` in `.env` files that are committed to version control.

**Recommended Approaches:**

| Method | Security Level | Production Ready |
|--------|---------------|------------------|
| Environment Variables | Medium | ✅ Yes |
| HashiCorp Vault | High | ✅ Yes |
| AWS Secrets Manager | High | ✅ Yes |
| Hardware Security Module | Critical | ✅ Yes |
| .env file (local only) | Low | ❌ No |

**Example Secure Setup:**
```bash
# Use secret management service
export PRIVATE_KEY=$(aws secretsmanager get-secret-value --secret-id compliancezk-private-key --query SecretString --output text)

# Or use HashiCorp Vault
export PRIVATE_KEY=$(vault kv get -field=private_key compliancezk/deployer)
```

#### 2. ZK Proof Replay Protection

The circuit implements nonce-chain replay prevention:

```circom
// Nonce must be strictly increasing
compliance_nonce > previous_nonce;

// Nonce is stored on-chain to prevent reuse
mapping(bytes32 => uint64) public proofNonces;
```

**Audit Finding**: In-memory nonce tracking in middleware is stateless across restarts. Production deployments must use on-chain nonce storage.

#### 3. Rate Limiting DoS Protection

The API implements on-chain rate limiting:

```solidity
// Rate limit state stored on-chain, not in-memory
mapping(address => uint256) public requestTimestamps;
mapping(address => uint256) public requestCount;

function checkRateLimit(address client) internal view returns (bool) {
    uint256 windowStart = block.timestamp - RATE_LIMIT_WINDOW;
    uint256 count = requestCount[client];
    
    // Reset count if window expired
    if (requestTimestamps[client] < windowStart) {
        requestCount[client] = 0;
    }
    
    return count < MAX_REQUESTS_PER_WINDOW;
}
```

**Audit Finding**: In-memory rate limiting in middleware creates DoS vectors. Production must use on-chain state.

#### 4. Merkle Tree Jurisdiction Validation

Jurisdictions are validated via Merkle inclusion proofs:

```circom
// Merkle proof path validation
merkle_computed = computeMerkleRoot(jurisdiction_path, jurisdiction_directions);
merkle_computed == merkle_root;
```

**Audit Finding**: Jurisdiction whitelist must be updated via multi-sig governance to prevent unauthorized changes.

#### 5. Agent Decoupling Security

The agent never receives PII:

```javascript
// Agent receives only ZK proof, not user data
const proof = await zkProofService.generateProof(userComplianceData);
await agentMiddleware.executeAction(agentId, proof);
```

**Audit Finding**: Agent middleware must validate proof before execution. Never trust agent-provided compliance status.

#### 6. Circuit Implementation Security

| Component | Security Check | Status |
|-----------|---------------|--------|
| Age Verification | Proven >= 18, exact age hidden | ✅ |
| Sanction Status | Binary (clean/flagged) | ✅ |
| Jurisdiction | Merkle inclusion proof | ✅ |
| Nonce Chain | On-chain storage | ⚠️ Middleware uses in-memory |
| Timestamp Binding | Validity window enforced | ✅ |

---

## Privacy Guarantees

### Zero-Knowledge Properties

| Property | Implementation | Guarantee |
|----------|---------------|-----------|
| **Completeness** | Circuit always accepts valid proofs | ✅ |
| **Soundness** | Invalid proofs cannot be generated | ✅ |
| **Zero-Knowledge** | No PII revealed to verifier | ✅ |
| **Non-Transferability** | Proofs bound to specific user | ✅ |

### Data Flow Privacy

```
User Auth0 Profile (PII)
    │
    ▼
[Auth0 Service] - Extracts compliance-relevant fields only
    │
    ▼
[ZK Circuit] - Proves compliance without revealing PII
    │
    ▼
[ZK Proof] - Contains only public compliance status
    │
    ▼
[Agent] - Receives proof, never sees PII
    │
    ▼
[On-Chain Verifier] - Validates proof, stores only hash
```

### What Is Never Revealed

- User's exact age (only proven >= 18)
- User's full identity (only hashed identifier)
- User's specific jurisdiction (only Merkle inclusion)
- User's sanction history (only binary status)
- User's compliance score (only tier level)

### What Is Revealed On-Chain

- Compliance proof hash (for verification)
- Compliance tier (0-255, risk-based)
- Proof validity window (timestamps)
- Jurisdiction Merkle root (whitelist)

---

## Compliance Tiers

| Tier | Range | Description | Allowed Actions |
|------|-------|-------------|-----------------|
| 0 | 0-25 | High Risk | None |
| 1 | 26-50 | Medium Risk | Read-only |
| 2 | 51-75 | Low Risk | Standard transfers |
| 3 | 76-100 | Verified | All actions |
| 4 | 101-150 | Premium | High-value transfers |
| 5 | 151-200 | Institutional | Unlimited |
| 6 | 201-255 | Enterprise | Custom limits |

---

## Troubleshooting

### Common Issues

#### Circuit Compilation Fails

```bash
# Ensure circomlib is installed
npm install circomlib

# Clear build cache
rm -rf circuits/build
npm run circuit:compile
```

#### Proof Verification Fails

```bash
# Check verification key matches circuit
npm run circuit:generate-key

# Verify proof inputs match circuit public inputs
# Circuit expects: [proof_hash, merkle_root, start, end]
```

#### Rate Limiting Too Aggressive

```bash
# Increase rate limit in .env
RATE_LIMIT_MAX_REQUESTS=200
RATE_LIMIT_WINDOW_MS=120000
```

#### Auth0 Integration Fails

```bash
# Verify Auth0 Custom Actions are enabled
# Check Auth0 client has correct redirect URIs
# Ensure Auth0 client secret is correct in .env
```

---

## Contributing

### Code Style

- Use ESLint for JavaScript/TypeScript
- Use Prettier for formatting
- Use Solhint for Solidity

### Testing

```bash
# Run all tests
npm test

# Run circuit tests
npm run circuit:test

# Run contract tests
npx hardhat test
```

### Security Reporting

If you discover a security vulnerability, please report it via security@compliancezk.io. Do not disclose publicly until resolved.

---

## License

MIT License - See LICENSE file for details.

---

## Disclaimer

ComplianceZK is provided "as is" without warranty of any kind. The authors are not liable for any damages arising from the use of this software. Users are responsible for ensuring their use of ComplianceZK complies with all applicable laws and regulations in their jurisdiction.

---

## Contact

- **Website**: https://compliancezk.io
- **Documentation**: https://docs.compliancezk.io
- **Support**: support@compliancezk.io
- **Security**: security@compliancezk.io

---

*Last Updated: 2024-01-15*
*Version: 1.0.0*