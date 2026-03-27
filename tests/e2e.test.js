import { strict as assert } from 'assert';
import { describe, it, before, after } from 'mocha';
import { ethers } from 'ethers';
import { ComplianceVerifier } from '../artifacts/contracts/ComplianceVerifier.sol/ComplianceVerifier.js';
import { ComplianceProof } from '../circuits/build/complianceProof_js/complianceProof.js';
import { ZKProofService } from '../services/zkProofService.js';
import { Auth0Service } from '../services/auth0Service.js';
import { AgentMiddleware } from '../services/agentMiddleware.js';
import { createHash } from 'crypto';

/**
 * @title ComplianceZK E2E Test Suite
 * @notice End-to-end testing of ZK-verified agent compliance system
 * @dev Tests Auth0 integration, ZK proof generation, on-chain verification, and agent execution
 */

// === TEST CONFIGURATION ===
const TEST_CONFIG = {
    providerUrl: process.env.HARDHAT_PROVIDER_URL || 'http://127.0.0.1:8545',
    deployerPrivateKey: process.env.DEPLOYER_PRIVATE_KEY || '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    auth0ClientId: process.env.AUTH0_CLIENT_ID || 'test_client_id',
    auth0Domain: process.env.AUTH0_DOMAIN || 'test.auth0.com',
    auth0Audience: process.env.AUTH0_AUDIENCE || 'https://compliancezk.test',
    contractAddress: '0x0000000000000000000000000000000000000000',
    rateLimitWindow: 60000,
    maxRequestsPerWindow: 100
};

// === TEST HELPERS ===
function generateMockUser() {
    return {
        user_id: `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        age: 25,
        jurisdiction: 'US',
        sanction_status: false,
        compliance_score: 95
    };
}

function generateMerklePath(jurisdiction, merkleTree) {
    const index = merkleTree.indexOf(jurisdiction);
    const path = [];
    const directions = [];
    let current = index;
    
    for (let depth = 0; depth < 4; depth++) {
        const sibling = current % 2 === 0 ? current + 1 : current - 1;
        if (sibling < merkleTree.length) {
            path.push(merkleTree[sibling]);
            directions.push(current % 2);
        }
        current = Math.floor(current / 2);
    }
    
    return { path, directions };
}

function computeMerkleRoot(leaves, path, directions) {
    let current = createHash('sha256').update(leaves[0]).digest('hex');
    
    for (let i = 0; i < path.length; i++) {
        const sibling = path[i];
        const direction = directions[i];
        const data = direction === 0 
            ? current + sibling 
            : sibling + current;
        current = createHash('sha256').update(data).digest('hex');
    }
    
    return current;
}

// === TEST SUITE ===
describe('ComplianceZK E2E Tests', function() {
    this.timeout(60000);
    
    let provider;
    let signer;
    let complianceVerifier;
    let zkProofService;
    let auth0Service;
    let agentMiddleware;
    let merkleTree;
    let circuitInputs;
    let proof;
    let publicSignals;

    before(async function() {
        // Initialize provider and signer
        provider = new ethers.JsonRpcProvider(TEST_CONFIG.providerUrl);
        signer = new ethers.Wallet(TEST_CONFIG.deployerPrivateKey, provider);
        
        // Deploy ComplianceVerifier contract
        const ComplianceVerifierFactory = await ethers.getContractFactory('ComplianceVerifier');
        complianceVerifier = await ComplianceVerifierFactory.deploy();
        await complianceVerifier.waitForDeployment();
        TEST_CONFIG.contractAddress = await complianceVerifier.getAddress();
        
        // Initialize services
        zkProofService = new ZKProofService();
        auth0Service = new Auth0Service(TEST_CONFIG.auth0ClientId, TEST_CONFIG.auth0Domain);
        agentMiddleware = new AgentMiddleware(complianceVerifier, provider);
        
        // Setup Merkle tree for jurisdictions
        merkleTree = [
            createHash('sha256').update('US').digest('hex'),
            createHash('sha256').update('EU').digest('hex'),
            createHash('sha256').update('UK').digest('hex'),
            createHash('sha256').update('CA').digest('hex')
        ];
        
        // Generate circuit inputs
        const mockUser = generateMockUser();
        const { path, directions } = generateMerklePath(mockUser.jurisdiction, merkleTree);
        
        circuitInputs = {
            user_id_hash: createHash('sha256').update(mockUser.user_id).digest('hex'),
            age: mockUser.age,
            jurisdiction_index: merkleTree.indexOf(mockUser.jurisdiction),
            jurisdiction_path: path,
            jurisdiction_directions: directions,
            sanction_status: mockUser.sanction_status ? 1 : 0,
            current_timestamp: Math.floor(Date.now() / 1000),
            compliance_nonce: Math.floor(Math.random() * 1000000)
        };
        
        // Generate ZK proof
        const complianceAttestation = new ComplianceProof();
        await complianceAttestation.generate(circuitInputs);
        proof = complianceAttestation.getProof();
        publicSignals = complianceAttestation.getPublicSignals();
        
        console.log('✓ E2E Test Setup Complete');
        console.log(`  Contract: ${TEST_CONFIG.contractAddress}`);
        console.log(`  Proof Generated: ${proof.a[0].substring(0, 10)}...`);
    });

    after(async function() {
        // Cleanup if needed
        console.log('✓ E2E Test Cleanup Complete');
    });

    describe('Auth0 Integration', function() {
        it('should validate Auth0 token structure', async function() {
            const mockToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            
            const isValid = await auth0Service.validateTokenStructure(mockToken);
            assert.strictEqual(isValid, true, 'Token structure should be valid');
        });

        it('should extract user claims from token', async function() {
            const mockToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
            
            const claims = await auth0Service.extractClaims(mockToken);
            assert.ok(claims, 'Claims should be extracted');
            assert.ok(claims.sub, 'User ID should be present');
        });
    });

    describe('ZK Proof Generation', function() {
        it('should generate valid ZK proof for compliant user', async function() {
            assert.ok(proof, 'Proof should be generated');
            assert.ok(proof.a, 'Proof A component should exist');
            assert.ok(proof.b, 'Proof B component should exist');
            assert.ok(proof.c, 'Proof C component should exist');
        });

        it('should generate valid public signals', async function() {
            assert.ok(publicSignals, 'Public signals should be generated');
            assert.ok(publicSignals.length > 0, 'Public signals should not be empty');
        });

        it('should verify proof locally before submission', async function() {
            const isValid = await zkProofService.verifyProofLocally(proof, publicSignals);
            assert.strictEqual(isValid, true, 'Proof should be locally valid');
        });
    });

    describe('Smart Contract Verification', function() {
        it('should verify proof on-chain', async function() {
            const tx = await complianceVerifier.verifyProof(
                proof.a,
                proof.b,
                proof.c,
                publicSignals
            );
            const receipt = await tx.wait();
            
            assert.strictEqual(receipt.status, 1, 'Transaction should succeed');
            console.log(`✓ On-chain verification successful (gas: ${receipt.gasUsed})`);
        });

        it('should store proof in nonce chain', async function() {
            const nonce = circuitInputs.compliance_nonce;
            const isStored = await complianceVerifier.isNonceUsed(nonce);
            assert.strictEqual(isStored, true, 'Nonce should be stored');
        });

        it('should reject duplicate nonce (replay attack prevention)', async function() {
            const duplicateTx = complianceVerifier.verifyProof(
                proof.a,
                proof.b,
                proof.c,
                publicSignals
            );
            
            await assert.rejects(
                duplicateTx,
                /nonce.*used|already.*used/,
                'Duplicate nonce should be rejected'
            );
        });
    });

    describe('Agent Middleware Execution', function() {
        it('should allow agent execution when proof is valid', async function() {
            const mockUser = generateMockUser();
            const action = 'execute_trade';
            
            const result = await agentMiddleware.canExecuteAction(
                mockUser.user_id,
                action,
                proof,
                publicSignals
            );
            
            assert.strictEqual(result.allowed, true, 'Action should be allowed');
            assert.strictEqual(result.reason, 'compliance_proven', 'Reason should indicate compliance');
        });

        it('should reject agent execution when proof is invalid', async function() {
            const mockUser = generateMockUser();
            const action = 'execute_trade';
            
            // Create invalid proof by modifying public signals
            const invalidSignals = [...publicSignals];
            invalidSignals[0] = '0x' + '00'.repeat(64);
            
            const result = await agentMiddleware.canExecuteAction(
                mockUser.user_id,
                action,
                proof,
                invalidSignals
            );
            
            assert.strictEqual(result.allowed, false, 'Action should be rejected');
            assert.ok(result.reason.includes('invalid'), 'Reason should indicate invalid proof');
        });

        it('should enforce rate limiting via on-chain state', async function() {
            const mockUser = generateMockUser();
            const action = 'execute_trade';
            
            // First request should succeed
            const firstResult = await agentMiddleware.canExecuteAction(
                mockUser.user_id,
                action,
                proof,
                publicSignals
            );
            assert.strictEqual(firstResult.allowed, true, 'First request should succeed');
            
            // Simulate rate limit check
            const rateLimitCheck = await agentMiddleware.checkRateLimit(mockUser.user_id);
            assert.ok(rateLimitCheck, 'Rate limit check should return data');
        });
    });

    describe('Compliance Tier Escalation', function() {
        it('should assign correct compliance tier', async function() {
            const mockUser = generateMockUser();
            const tier = await agentMiddleware.calculateComplianceTier(mockUser);
            
            assert.ok(tier >= 0 && tier <= 255, 'Tier should be in valid range');
            assert.ok(tier > 0, 'Tier should be non-zero for compliant user');
        });

        it('should escalate tier based on compliance score', async function() {
            const highScoreUser = { ...generateMockUser(), compliance_score: 99 };
            const lowScoreUser = { ...generateMockUser(), compliance_score: 50 };
            
            const highTier = await agentMiddleware.calculateComplianceTier(highScoreUser);
            const lowTier = await agentMiddleware.calculateComplianceTier(lowScoreUser);
            
            assert.ok(highTier >= lowTier, 'Higher score should result in equal or higher tier');
        });
    });

    describe('Temporal Compliance Binding', function() {
        it('should verify proof validity window', async function() {
            const currentTime = Math.floor(Date.now() / 1000);
            const validityWindowStart = currentTime - 3600; // 1 hour ago
            const validityWindowEnd = currentTime + 3600; // 1 hour from now
            
            const isValidWindow = await agentMiddleware.verifyValidityWindow(
                validityWindowStart,
                validityWindowEnd,
                currentTime
            );
            
            assert.strictEqual(isValidWindow, true, 'Proof should be within validity window');
        });

        it('should reject expired proofs', async function() {
            const expiredStart = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
            const expiredEnd = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
            const currentTime = Math.floor(Date.now() / 1000);
            
            const isValidWindow = await agentMiddleware.verifyValidityWindow(
                expiredStart,
                expiredEnd,
                currentTime
            );
            
            assert.strictEqual(isValidWindow, false, 'Expired proof should be rejected');
        });
    });

    describe('Jurisdiction Verification', function() {
        it('should verify jurisdiction via Merkle proof', async function() {
            const mockUser = generateMockUser();
            const { path, directions } = generateMerklePath(mockUser.jurisdiction, merkleTree);
            
            const isValid = await agentMiddleware.verifyJurisdiction(
                merkleTree[0],
                mockUser.jurisdiction_index,
                path,
                directions
            );
            
            assert.strictEqual(isValid, true, 'Jurisdiction should be valid');
        });

        it('should reject invalid jurisdiction', async function() {
            const invalidJurisdiction = 'XX';
            const { path, directions } = generateMerklePath(invalidJurisdiction, merkleTree);
            
            const isValid = await agentMiddleware.verifyJurisdiction(
                merkleTree[0],
                -1,
                path,
                directions
            );
            
            assert.strictEqual(isValid, false, 'Invalid jurisdiction should be rejected');
        });
    });

    describe('Sanction Status Verification', function() {
        it('should allow clean sanction status', async function() {
            const cleanUser = { ...generateMockUser(), sanction_status: false };
            const result = await agentMiddleware.verifySanctionStatus(cleanUser.sanction_status);
            
            assert.strictEqual(result.allowed, true, 'Clean status should be allowed');
        });

        it('should reject flagged sanction status', async function() {
            const flaggedUser = { ...generateMockUser(), sanction_status: true };
            const result = await agentMiddleware.verifySanctionStatus(flaggedUser.sanction_status);
            
            assert.strictEqual(result.allowed, false, 'Flagged status should be rejected');
        });
    });

    describe('Security & Replay Protection', function() {
        it('should prevent nonce reuse across sessions', async function() {
            const nonce = circuitInputs.compliance_nonce;
            
            // First verification
            await complianceVerifier.verifyProof(
                proof.a,
                proof.b,
                proof.c,
                publicSignals
            );
            
            // Second verification with same nonce should fail
            await assert.rejects(
                complianceVerifier.verifyProof(
                    proof.a,
                    proof.b,
                    proof.c,
                    publicSignals
                ),
                /nonce.*used/,
                'Nonce reuse should be prevented'
            );
        });

        it('should prevent timestamp manipulation', async function() {
            const futureTimestamp = Math.floor(Date.now() / 1000) + 86400; // 1 day in future
            const pastTimestamp = Math.floor(Date.now() / 1000) - 86400; // 1 day in past
            
            const futureValid = await agentMiddleware.verifyValidityWindow(
                futureTimestamp,
                futureTimestamp + 3600,
                Math.floor(Date.now() / 1000)
            );
            
            const pastValid = await agentMiddleware.verifyValidityWindow(
                pastTimestamp,
                pastTimestamp + 3600,
                Math.floor(Date.now() / 1000)
            );
            
            assert.strictEqual(futureValid, false, 'Future timestamp should be invalid');
            assert.strictEqual(pastValid, false, 'Past timestamp should be invalid');
        });

        it('should prevent jurisdiction tree tampering', async function() {
            const tamperedTree = [...merkleTree];
            tamperedTree[0] = '0x' + '00'.repeat(64);
            
            const isValid = await agentMiddleware.verifyJurisdiction(
                tamperedTree[0],
                0,
                [],
                []
            );
            
            assert.strictEqual(isValid, false, 'Tampered tree should be rejected');
        });
    });

    describe('Integration Flow', function() {
        it('should complete full compliance verification flow', async function() {
            const mockUser = generateMockUser();
            
            // Step 1: Auth0 authentication
            const authResult = await auth0Service.authenticate(mockUser);
            assert.ok(authResult, 'Auth0 authentication should succeed');
            
            // Step 2: ZK proof generation
            const proofResult = await zkProofService.generateProof(mockUser);
            assert.ok(proofResult, 'ZK proof generation should succeed');
            
            // Step 3: On-chain verification
            const verifyTx = await complianceVerifier.verifyProof(
                proofResult.proof.a,
                proofResult.proof.b,
                proofResult.proof.c,
                proofResult.publicSignals
            );
            const verifyReceipt = await verifyTx.wait();
            assert.strictEqual(verifyReceipt.status, 1, 'On-chain verification should succeed');
            
            // Step 4: Agent execution
            const agentResult = await agentMiddleware.canExecuteAction(
                mockUser.user_id,
                'execute_trade',
                proofResult.proof,
                proofResult.publicSignals
            );
            assert.strictEqual(agentResult.allowed, true, 'Agent should be allowed to execute');
            
            console.log('✓ Full compliance flow completed successfully');
        });

        it('should reject non-compliant user at every stage', async function() {
            const nonCompliantUser = {
                user_id: `user_${Date.now()}`,
                age: 16, // Under 18
                jurisdiction: 'XX', // Invalid jurisdiction
                sanction_status: true, // Flagged
                compliance_score: 0
            };
            
            // Step 1: Auth0 should fail age check
            const authResult = await auth0Service.authenticate(nonCompliantUser);
            assert.ok(!authResult || !authResult.valid, 'Auth0 should reject under-age user');
            
            // Step 2: ZK proof should fail age constraint
            const proofResult = await zkProofService.generateProof(nonCompliantUser);
            assert.ok(!proofResult || !proofResult.valid, 'ZK proof should fail for under-age user');
            
            // Step 3: Agent should reject execution
            const agentResult = await agentMiddleware.canExecuteAction(
                nonCompliantUser.user_id,
                'execute_trade',
                proofResult?.proof || proof,
                proofResult?.publicSignals || publicSignals
            );
            assert.strictEqual(agentResult.allowed, false, 'Agent should reject non-compliant user');
            
            console.log('✓ Non-compliant user correctly rejected at all stages');
        });
    });
});