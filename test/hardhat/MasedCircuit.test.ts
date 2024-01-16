import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import crypto from "crypto";
import { Wallet, utils } from "ethers";
import { ethers } from "hardhat";
import path from "path";
import {
  bigintSubMod,
  bytes2bnArr,
  getStealthAddress,
} from "./utils/StealthAddressUtil";

const wasm_tester = require("circom_tester").wasm;

describe("Masked ZK", function () {
  let ecdsaVerifier: any;
  let owner: Wallet;
  let hashSharedSecret: any;
  let stealthAddress: any;
  this.beforeAll(async function () {
    ({ ecdsaVerifier, owner, hashSharedSecret, stealthAddress } =
      await loadFixture(deployOneYearLockFixture));
  });
  async function deployOneYearLockFixture() {
    const privateKey = Wallet.createRandom().privateKey;
    const owner = new Wallet(privateKey);

    const { stealthAddress, hashSharedSecret } = getStealthAddress(owner);

    const ECDSAVerifier = await ethers.getContractFactory("MaskVerifier");
    const ecdsaVerifier = await ECDSAVerifier.deploy();

    return { ecdsaVerifier, owner, hashSharedSecret, stealthAddress };
  }

  it("circuit", async () => {
    const { hashSharedSecret } = await loadFixture(deployOneYearLockFixture);
    const P =
      115792089237316195423570985008687907852837564279074904382605163141518161494337n;

    const cir = await wasm_tester(
      path.join(__dirname, "..", "..", "circuits", "masked.circom")
    );
    const message = utils.sha256("0x0102030405060708090a");

    /// mock sig r
    const r = utils.sha256("0x1234");
    const rPrivate =
      "0x" +
      (((BigInt(r) % P) * (BigInt(hashSharedSecret) % P)) % P)
        .toString(16)
        .padStart(64, "0");

    const privateBytes = utils.arrayify(hashSharedSecret);
    const messageBytes = utils.arrayify(message);
    const concatBytes = utils.arrayify(
      utils.concat([privateBytes, messageBytes])
    );
    const rBytes = utils.arrayify(r);

    const hash =
      "0x" +
      crypto
        .createHash("sha256")
        .update(concatBytes)
        .digest("hex")
        .padStart(64, "0");

    /// stealthMessage = message - r * private - hash(private, message)
    const masked = bigintSubMod(BigInt(message), BigInt(rPrivate), P);
    const stealthMessage = bigintSubMod(BigInt(masked), BigInt(hash), P);
    const stealthMessageBytes = utils.arrayify(stealthMessage);

    const privateIn = bytes2bnArr(privateBytes);
    const messageIn = bytes2bnArr(messageBytes);
    const rIn = bytes2bnArr(rBytes);
    const finalMessageIn = bytes2bnArr(stealthMessageBytes);

    const witness = await cir.calculateWitness(
      {
        privkey: privateIn,
        message: messageIn,
        maskedMessage: finalMessageIn,
        r: rIn,
      },
      true
    );
    await cir.checkConstraints(witness);
  });
