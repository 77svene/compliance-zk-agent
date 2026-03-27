# **🛡️ ComplianceZK: ZK-Verified Agent Regulatory Adherence**

**Privacy-preserving middleware enabling autonomous agents to prove KYC/AML compliance via Zero-Knowledge Proofs without exposing PII.**

[![Hackathon](https://img.shields.io/badge/Hackathon-Auth0%20for%20AI%20Agents-blue)](https://github.com/77svene/compliance-zk-agent)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8+-orange.svg)](https://docs.soliditylang.org/)
[![Circom](https://img.shields.io/badge/Circom-ZK-blue.svg)](https://github.com/iden3/circom)

---

## 🏆 Hackathon Challenge
**Authorized to Act: Auth0 for AI Agents**  
**Prize:** $10,000  
**Deadline:** Mar 02 - Apr 07, 2026  
**Repo:** [https://github.com/77svene/compliance-zk-agent](https://github.com/77svene/compliance-zk-agent)

---

## 🚀 Problem
Autonomous AI agents operating in regulated industries (DeFi, Healthcare, Finance) face a critical bottleneck: **Identity vs. Privacy**. To execute high-risk actions, agents traditionally require access to user PII (Personally Identifiable Information) for KYC/AML checks. This creates three major risks:
1.  **Data Exposure:** PII is stored or transmitted to the agent, increasing attack surface.
2.  **Regulatory Friction:** Agents cannot legally act without verifiable compliance, but sharing data violates GDPR/CCPA.
3.  **Trust Deficit:** Users are unwilling to grant agents full identity access for simple compliance checks.

## 💡 Solution
**ComplianceZK** introduces a privacy-preserving middleware layer between Auth0 and autonomous agents. It decouples identity from action using Zero-Knowledge Proofs (ZKPs).

1.  **Auth0 Integration:** Users authenticate via Auth0.
2.  **ZK Proof Generation:** The system generates a Circom-based proof attesting to specific criteria (Age > 18, Sanction-Free, Jurisdiction Valid) without revealing the underlying data.
3.  **Agent Verification:** The agent receives only the proof. A Solidity smart contract verifies the proof before allowing action.
4.  **Privacy First:** The agent never sees the PII; the public ledger never sees the PII.

---

## 🏗️ Architecture

```text
+----------+       +----------------+       +-------------------+       +----------------+
|   User   |       |   Auth0        |       | ComplianceZK      |       |   Agent        |
|          |       |                |       | Middleware        |       |                |
+----+-----+       +-------+--------+       +---------+---------+       +-------+--------+
     |                     |                          |                       |
     | 1. Authenticate      |                          |                       |
     +-------------------->|                          |                       |
     |                     |                          |                       |
     |                     | 2. Extract Claims        |                       |
     |                     +-------------------------->                       |
     |                     |                          |                       |
     |                     |                          | 3. Generate ZK Proof  |
     |                     |                          |    (Circom)           |
     |                     |                          +----------------------->|
     |                     |                          |                       |
     |                     |                          | 4. Submit Proof       |
     |                     |                          |    to Contract        |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          | 5. Verify Proof       |
     |                     |                          |    (Solidity)         |
     |                     |                          +----------------------->|
     |                     |                          |                       |
     |                     |                          | 6. Compliance Status  |
     |                     |                          |    (True/False)       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |......<think>......|                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
......<think>......|                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |                     |                          |                       |
     |......