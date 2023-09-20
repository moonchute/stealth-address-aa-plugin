import "@nomicfoundation/hardhat-foundry";
import "@nomicfoundation/hardhat-toolbox";
import "@nomiclabs/hardhat-ethers";
import "@typechain/hardhat";
import * as dotenv from "dotenv";
import fs from "fs";
import "hardhat-deploy";
import "hardhat-preprocessor";
import { HardhatUserConfig } from "hardhat/config";
dotenv.config();

function getAccounts(): string[] | { mnemonic: string } {
  const accs = [];
  if (process.env.DEPLOYER_PRIVATE_KEY !== undefined) {
    accs.push(process.env.DEPLOYER_PRIVATE_KEY);
  }
  if (process.env.PAYMASTER_OWNER_PRIVATE_KEY !== undefined) {
    accs.push(process.env.PAYMASTER_OWNER_PRIVATE_KEY);
  }
  return accs;
}

function getRemappings() {
  return fs
    .readFileSync("remappings.txt", "utf8")
    .split("\n")
    .filter(Boolean) // remove empty lines
    .map((line) => line.trim().split("="));
}

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000000,
      },
      metadata: {
        bytecodeHash: "none",
      },
      viaIR: true,
    },
  },
  networks: {
    mumbai: {
      url: `https://polygon-mumbai.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    polygon: {
      url: `https://polygon-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    goerli: {
      url: `https://goerli.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    ethereum: {
      url: `https://mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    avalanche: {
      url: `https://avalanche-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    fuji: {
      url: `https://avalanche-fuji.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    arbitrum: {
      url: `https://arbitrum-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    arbitrumGoerli: {
      url: `https://arbitrum-goerli.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    optimism: {
      url: `https://optimism-mainnet.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    optimismGoerli: {
      url: `https://optimism-goerli.infura.io/v3/${process.env.INFURA_ID}`,
      accounts: getAccounts(),
    },
    bscTestnet: {
      url: `https://sly-indulgent-paper.bsc-testnet.discover.quiknode.pro/ab7e00c229f5967334160958e40fd6a4d893fb93`,
      accounts: getAccounts(),
    },
    bsc: {
      url: `https://wandering-quaint-reel.bsc.quiknode.pro/508c3d245c14adb8689ed4073d29aa5795dfa24e`,
      accounts: getAccounts(),
    },
    baseGoerli: {
      url: `https://icy-long-mountain.base-goerli.quiknode.pro/5b80d93e97cc9412a63c10a30841869abbef9596`,
      accounts: getAccounts(),
    },
  },
  preprocess: {
    eachLine: (hre) => ({
      transform: (line: string, sourceInfo: { absolutePath: string }) => {
        // console.log(sourceInfo.absolutePath);
        if (line.match(/^\s*import /i)) {
          const libIndex = sourceInfo.absolutePath.indexOf("lib");
          const srcIndex = sourceInfo.absolutePath.indexOf("src");
          if (libIndex !== -1 && srcIndex !== -1) {
            const libPath = sourceInfo.absolutePath.slice(
              libIndex,
              srcIndex - 1
            );
            return line.replace("src", libPath + "/src");
          }

          for (const [from, to] of getRemappings()) {
            if (line.includes(from)) {
              line = line.replace(from, to);
              break;
            }
          }
        }
        return line;
      },
    }),
  },
  paths: {
    sources: "./src",
    cache: "./cache_hardhat",
  },
};

export default config;
