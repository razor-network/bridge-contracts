import fs from "fs";
import "@nomiclabs/hardhat-waffle";
import "@typechain/hardhat";
import "hardhat-preprocessor";
import "hardhat-deploy";
import { HardhatUserConfig } from "hardhat/config";
import "dotenv/config";
import "solidity-coverage";
import "hardhat-abi-exporter";
import "hardhat-ethernal";

function getRemappings() {
  return fs
    .readFileSync("remappings.txt", "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.trim().split("="));
}

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.15",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  paths: {
    sources: "./src", // Use ./src rather than ./contracts as Hardhat expects
    cache: "./hh-cache",
    artifacts: "./artifacts",
  },
  // This fully resolves paths for imports in the ./lib directory for Hardhat
  preprocess: {
    eachLine: (hre) => ({
      transform: (line: string) => {
        if (line.match(/^\s*import /i)) {
          getRemappings().forEach(([find, replace]) => {
            if (line.match(find)) {
              line = line.replace(find, replace);
            }
          });
        }
        return line;
      },
    }),
  },
  namedAccounts: {
    deployer: 0,
    simpleERC20Beneficiary: 1,
  },
  networks: {
    local: {
      url: `http://${process.env.PROVIDER_HOST}:${process.env.PROVIDER_PORT}`,
      chainId: 31337,
    },
    hardhat: {
      mining: {
        auto: false,
        interval: 10000,
      },
    },
    skale: {
      url: process.env.RPC_URL || "",
      accounts: { mnemonic: process.env.MNEMONIC || "test test test test test test test test test test test test" },
      chainId: 1517929550,
      timeout: 300000,
    },
  },
  abiExporter: {
    path: "./data/abi",
    runOnCompile: true,
    clear: true,
    flat: true,
    spacing: 2,
    pretty: true,
  },
  ethernal: {
    disableSync: false, // If set to true, plugin will not sync blocks & txs
    disableTrace: false, // If set to true, plugin won't trace transaction
    workspace: undefined, // Set the workspace to use, will default to the default workspace (latest one used in the dashboard). It is also possible to set it through the ETHERNAL_WORKSPACE env variable
    uploadAst: true, // If set to true, plugin will upload AST, and you'll be able to use the storage feature (longer sync time though)
    disabled: false, // If set to true, the plugin will be disabled, nothing will be synced, ethernal.push won't do anything either
    resetOnStart: "WorkspaceName", // Pass a workspace name to reset it automatically when restarting the node, note that if the workspace doesn't exist it won't throw an error
    serverSync: false, // If set to true, blocks & txs will be synced by the server. For this to work, your chain needs to be accessible from the internet. Also, trace won't be synced for now when this is enabled.
    skipFirstBlock: false, // If set to true, the first block will be skipped. This is mostly useful to avoid having the first block synced with its tx when starting a mainnet fork
  },
};

export default config;
