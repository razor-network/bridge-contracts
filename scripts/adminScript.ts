import { HardhatRuntimeEnvironment } from "hardhat/types";
import BRIDGE_ABI from "../out/Bridge.sol/Bridge.abi.json";
import * as hre from "hardhat";
import { concat } from "ethers/lib/utils";
import Elliptic from "elliptic";
const PROVIDER = process.env.PROVIDER_URL || "http://localhost:8545/";
const BRIDGE_ADDRESS: string = process.env.BRIDGE_ADDRESS || "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const PRIVATE_KEY: string = process.env.DEPLOYER_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const { NETWORK_TYPE } = process.env;
// Create a wallet to sign the message with

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(hre: HardhatRuntimeEnvironment) {
  const EC_secp256k1 = new Elliptic.ec("secp256k1");
  const keyPair = EC_secp256k1.keyFromPrivate(hre.ethers.utils.arrayify(PRIVATE_KEY));
  const provider = new hre.ethers.providers.JsonRpcProvider(PROVIDER);
  let signer;
  if (NETWORK_TYPE === "DEVNET") {
    signer = provider.getSigner();
  } else if (NETWORK_TYPE === "TESTNET") {
    signer = hre.ethers.provider.getSigner();
  }
  const accounts = await provider.listAccounts();
  const bridgeContract = new hre.ethers.Contract(BRIDGE_ADDRESS, BRIDGE_ABI, signer);
  const dynasty = await bridgeContract.getDynasty();
  console.log(dynasty);
  await hre.run("compile");
  console.log("started");

  let attested = false;
  let epoch = 0;
  let attestedSignerAddress;

  // wait till first attested signer address is created
  while (!attested) {
    const dynasty = await bridgeContract.getDynasty();
    const activeSet = await bridgeContract.getActiveSetPerDynasty(dynasty);
    console.log(dynasty, activeSet);
    epoch = await bridgeContract.getEpoch();

    attestedSignerAddress = await bridgeContract.attestedSignerAddress(dynasty, epoch);
    console.log("Attested signer address: ", attestedSignerAddress);
    console.log("Epoch: ", Number(epoch));
    console.log("Dynasty: ", dynasty);

    if (attestedSignerAddress !== "0x0000000000000000000000000000000000000000") {
      attested = true;
    } else {
      console.log("waiting...");
      await delay(1000);
    }
  }

  // in the 1st dynasty admin needs to call confirmSigner since there is no previous signerAddress to confirm.
  console.log("Admin confirming signer...");
  console.log("Admin", accounts[0]);
  console.log("Attested Signer Address", attestedSignerAddress);
  epoch = await bridgeContract.getEpoch();
  const messageHash = hre.ethers.utils.solidityKeccak256(["uint256", "address"], [epoch, attestedSignerAddress]);
  const signature = keyPair.sign(hre.ethers.utils.arrayify(messageHash), { canonical: true });
  const splitSignature = hre.ethers.utils.splitSignature({
    recoveryParam: signature.recoveryParam || 0,
    r: hre.ethers.utils.hexZeroPad("0x" + signature.r.toString(16), 32),
    s: hre.ethers.utils.hexZeroPad("0x" + signature.s.toString(16), 32),
  });
  const formattedSignature = hre.ethers.utils.hexlify(
    concat([splitSignature.r, splitSignature.s, signature.recoveryParam ? "0x1c" : "0x1b"])
  );
  console.log(formattedSignature);
  const tx = await bridgeContract.confirmSigner(formattedSignature);
  await tx.wait();
  console.log("ConfirmSigner", tx.hash);
}

main(hre)
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
