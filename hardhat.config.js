import { task, config } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import dotenv from "dotenv";

dotenv.config();

const PRIVATE_KEY = process.env.PRIVATE_KEY || "";
const ALCHEMY_URL = process.env.ALCHEMY_URL || "";
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

config.env = {
  ...config.env,
  PRIVATE_KEY,
  ALCHEMY_URL,
  ETHERSCAN_API_KEY,
};

config.solidity = {
  version: "0.8.24",
  settings: {
    optimizer: {
      enabled: true,
      runs: 200,
    },
    evmVersion: "paris",
    viaIR: true,
    metadata: {
      bytecodeHash: "none",
    },
  },
};

config.networks = {
  localhost: {
    url: "http://127.0.0.1:8545",
    accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
    timeout: 60000,
    gas: 30000000,
    gasPrice: 20000000000,
  },
  hardhat: {
    forking: {
      url: ALCHEMY_URL || "https://eth-mainnet.g.alchemy.com/v2/demo",
      blockNumber: 18000000,
    },
  },
  sepolia: {
    url: ALCHEMY_URL || "https://eth-sepolia.g.alchemy.com/v2/demo",
    accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
    chainId: 11155111,
  },
  mainnet: {
    url: ALCHEMY_URL || "https://eth-mainnet.g.alchemy.com/v2/demo",
    accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
    chainId: 1,
  },
};

task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();
  for (const account of accounts) {
    console.log(account.address);
  }
});

task("verify-proof", "Verify a ZK proof on-chain")
  .addParam("proof", "The proof to verify")
  .addParam("publicSignals", "The public signals")
  .setAction(async (taskArgs, hre) => {
    const { ComplianceVerifier } = await hre.artifacts.readArtifact("ComplianceVerifier");
    const verifier = await hre.ethers.getContractFactory("ComplianceVerifier");
    const instance = await verifier.attach(taskArgs.contractAddress);
    const isValid = await instance.verifyProof(
      taskArgs.proof,
      taskArgs.publicSignals
    );
    console.log("Proof valid:", isValid);
  });

export default config;