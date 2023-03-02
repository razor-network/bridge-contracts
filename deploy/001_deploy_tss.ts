import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { readFile, writeFile } from "fs/promises";
import { BigNumber } from "ethers";
import "hardhat-ethernal";

const DEPLOYMENT_FILE = `${__dirname}/../.contract-deployment.tmp.json`;
const { NETWORK_TYPE, SEED_AMOUNT, STAKER_ADDRESSES, DAEMON_ADDRESS } = process.env;

const DEVNET_NUM_REQUESTS = 20;

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, getNamedAccounts, ethers } = hre;
  const { deploy, get } = deployments;
  const { deployer } = await getNamedAccounts();
  const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000";
  const STAKE_MODIFIER_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("STAKE_MODIFIER_ROLE"));
  const JAILER_ROLE = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("JAILER_ROLE"));

  console.log("Deploying BridgeToken");
  await deploy("BridgeToken", {
    from: deployer,
    log: true,
    autoMine: true, // speed up deployment on local network (ganache, hardhat), no effect on live networks
  });

  console.log("Deploying Bridge");
  await deploy("Bridge", {
    from: deployer,
    log: true,
    autoMine: true,
  });

  console.log("Deploying SourceChain");
  await deploy("SourceChain", {
    from: deployer,
    log: true,
    autoMine: true, // speed up deployment on local network (ganache, hardhat), no effect on live networks
  });

  console.log("Deploying MockSource");
  const MockSourceDeployment = await deploy("MockSource", {
    from: deployer,
    log: true,
    autoMine: true, // speed up deployment on local network (ganache, hardhat), no effect on live networks
  });

  const bridgeTokenContract = await get("BridgeToken");
  const bridgeContract = await get("Bridge");

  await hre.ethernal.push({
    name: "BridgeToken",
    address: bridgeTokenContract.address,
  });
  await hre.ethernal.push({
    name: "Bridge",
    address: bridgeContract.address,
  });
  const bridge = await ethers.getContractAt(bridgeContract.abi, bridgeContract.address);
  const bridgeToken = await ethers.getContractAt(bridgeTokenContract.abi, bridgeTokenContract.address);
  const firstDynastyCreation = await bridge.firstDynastyCreation();

  console.log("Deploying StakeManager");
  await deploy("StakeManager", {
    from: deployer,
    log: true,
    autoMine: true,
    args: [firstDynastyCreation],
  });

  console.log("Deploying BlameManager");
  await deploy("BlameManager", {
    from: deployer,
    log: true,
    autoMine: true,
    args: [firstDynastyCreation],
  });
  const stakeManagerContract = await get("StakeManager");
  const blameManagerContract = await get("BlameManager");
  const sourceChainContract = await get("SourceChain");
  const stakeManager = await ethers.getContractAt(stakeManagerContract.abi, stakeManagerContract.address);
  const blameManager = await ethers.getContractAt(blameManagerContract.abi, blameManagerContract.address);

  //Initialize contracts
  const tx1 = await bridge.initialize(stakeManagerContract.address);
  console.log("Initialize Bridge with StakeManager address", tx1.hash);
  await tx1.wait();

  const tx2 = await stakeManager.initialize(bridgeTokenContract.address, bridgeContract.address);
  console.log("Initialize StakeManager with BridgeToken and Bridge", tx2.hash);
  await tx2.wait();

  const tx3 = await blameManager.initialize(bridgeContract.address, stakeManagerContract.address);
  console.log("Initialize BlameManager with Bridge and StakeManager", tx3.hash);
  await tx3.wait();

  const tx4 = await stakeManager.grantRole(STAKE_MODIFIER_ROLE, bridgeContract.address);
  console.log("Grant Bridge stakeManager role STAKE_MODIFIER", tx4.hash);
  await tx4.wait();

  const tx5 = await stakeManager.grantRole(JAILER_ROLE, bridgeContract.address);
  console.log("Grant Bridge stakeManager role JAILER_ROLE", tx5.hash);
  await tx5.wait();
  //Write contract address to deployment file
  console.log("Write contract address to deployment file");
  await writeFile(
    DEPLOYMENT_FILE,
    `{"Bridge" : "${bridgeContract.address}", "BridgeToken" : "${bridgeTokenContract.address}", "StakeManager" : "${stakeManagerContract.address}", "BlameManager" : "${blameManagerContract.address}", "SourceChain" : "${sourceChainContract.address}"}`
  );

  //set result of MockSourceContract
  const mock = await ethers.getContractAt(MockSourceDeployment.abi, MockSourceDeployment.address);
  const txMock = await mock.setResult();
  console.log("Setting Result of MockSource");
  txMock.wait();

  console.log(
    `{"Bridge" : "${bridgeContract.address}", "BridgeToken" : "${bridgeTokenContract.address}", "MockSourceContract" : "${MockSourceDeployment.address}", "StakeManager" : "${stakeManagerContract.address}", "BlameManager" : "${blameManagerContract.address}", "SourceChain" : "${sourceChainContract.address}"}`
  );

  // Only transfer tokens in testnets
  if (NETWORK_TYPE === "TESTNET" && STAKER_ADDRESSES !== "") {
    // Add new instance of StakeManager contract & Deployer address as Minter
    const stakerAddressList = STAKER_ADDRESSES!.split(",");
    for (let i = 0; i < stakerAddressList.length; i++) {
      await bridgeToken.transfer(stakerAddressList[i], SEED_AMOUNT);
    }
    //Grant DEFAULT_ADMIN_ROLE to the Bridge Daemon Address
    //Required so that the daemon can createRequest
    const tx = await bridge.grantRole(DEFAULT_ADMIN_ROLE, DAEMON_ADDRESS);
    tx.wait();
    console.log("DEFAULT_ADMIN_ROLE granted to the Bridge Daemon tx:", tx.hash);

    //Fund the StakeManager with 1M tokens
    const supply = BigNumber.from(10).pow(BigNumber.from(23)).mul(BigNumber.from(10));
    await bridgeToken.transfer(stakeManagerContract.address, supply);
    console.log("Supply StakeManager: ", stakeManagerContract.address, "with: ", supply, "Bridge Tokens");
  }

  if (NETWORK_TYPE === "DEVNET") {
    const signers = await ethers.getSigners();
    // Add new instance of StakeManager contract & Deployer address as Minter
    for (let i = 0; i < 10; i++) {
      console.log("Sending seed amount to devnet address: ", signers[i].address);
      await bridgeToken.transfer(signers[i].address, SEED_AMOUNT);
    }

    const MockSourceContract = await get("MockSource");
    const { chainId } = await ethers.provider.getNetwork();

    //set the supported chainId for devnet
    console.log("setting supported chainId");
    await bridge.setSupportedChainId(chainId, true);

    console.log("creating requests...");
    try {
      for (let index = 0; index < DEVNET_NUM_REQUESTS; index++) {
        const tx = await bridge.createRequest(
          deployer,
          chainId,
          MockSourceContract.address,
          ethers.utils.hexlify(ethers.utils.toUtf8Bytes("getResult()")),
          chainId
        );
        await tx.wait();
        console.log("Created request with TX: ", tx.hash);
      }
    } catch (error) {
      console.log(error);
    }
  }
};
export default func;
func.tags = ["Bridge"];
