import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { assert } from "chai";
import { ethers } from "hardhat";
import { getAggregateSig, getStealthAddress } from "./utils/StealthAddressUtil";

describe("Stealth AA", function () {
  async function deployStealthFixture() {
    const [factoryOwner, beneficiary] = await ethers.getSigners();

    const owner = ethers.Wallet.createRandom();
    await factoryOwner.provider.send("hardhat_setBalance", [
      owner.address,
      ethers.utils.parseEther("0.0001").toHexString(),
    ]);

    const stealthAggregateFactory = await ethers.getContractFactory(
      "StealthAggreagteSignature"
    );
    const stealthAggregate = await stealthAggregateFactory.deploy();

    return { stealthAggregate, owner };
  }

  describe("should pass stealthAggregate validation", function () {
    it("Should pass validation from StealthAggregateSignature", async function () {
      const { stealthAggregate, owner } = await loadFixture(
        deployStealthFixture
      );

      const message = ethers.utils.keccak256(
        ethers.utils.arrayify("0x0102030405060708090a")
      );

      const {
        stealthAddress,
        stealthPub,
        dhkey,
        stealthPrefix,
        dhkeyPrefix,
        hashSharedSecret,
      } = getStealthAddress(owner);

      const sig = getAggregateSig(owner, hashSharedSecret, message);

      const res = await stealthAggregate.validateAggregatedSignature(
        stealthPub,
        dhkey,
        stealthPrefix,
        dhkeyPrefix,
        message,
        sig
      );
      assert.equal(res, true);
    });
  });
});
