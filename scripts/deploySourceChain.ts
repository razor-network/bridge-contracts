import { readFile, writeFile } from "fs/promises";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import * as hre from "hardhat";
const DEPLOYMENT_JSON = `${__dirname}/../.deployment.tmp.json`;

async function append(deploymentFileDir: any, data: any) {
    let deploymentFile = {};

    try {
      deploymentFile = await readFile(deploymentFileDir);
    }
    catch (e) {
      console.log("generating file")
    }
    await writeFile(deploymentFileDir, { ...deploymentFile, ...data});
}

async function main(hre: HardhatRuntimeEnvironment) {
  await hre.run("compile");
  console.log("started");
  console.log("Accounts Fetched");

  const SourceChain = await hre.ethers.getContractFactory("SourceChain");
  const sourceChain = await SourceChain.deploy();
  await sourceChain.deployed();

  await append(DEPLOYMENT_JSON, {["SourceChain"]: sourceChain.address});
}

main(hre)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });