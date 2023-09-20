import BN from "bn.js";
import { ec } from "elliptic";
import { BigNumber, Wallet, utils } from "ethers";

const abiCoder = new utils.AbiCoder();
const EC = new ec("secp256k1");

export const getStealthAddress = (owner: Wallet) => {
  const ownerPub = EC.keyFromPrivate(owner.privateKey).getPublic();

  const ephemeralKey = EC.genKeyPair();
  const ephemeralPriv = ephemeralKey.getPrivate();

  const sharedSecret = ownerPub.mul(ephemeralPriv);
  const hashSharedSecret = utils.keccak256(
    abiCoder.encode(
      ["uint256", "uint256"],
      [sharedSecret.getX().toString(), sharedSecret.getY().toString()]
    )
  );

  const sharedPub = EC.keyFromPrivate(hashSharedSecret).getPublic();
  const stealthPub = sharedPub.add(ownerPub);
  const stealthAddress = utils.computeAddress(
    utils.concat([
      Number(stealthPub.getY().toString()[0]) % 2 === 0 ? "0x02" : "0x03",
      BigNumber.from(stealthPub.getX().toString()).toHexString(),
    ])
  );
  const dhkey = ownerPub.mul(EC.keyFromPrivate(hashSharedSecret).getPrivate());

  return {
    stealthAddress,
    stealthPub: stealthPub.getX().toString(),
    dhkey: dhkey.getX().toString(),
    stealthPrefix: stealthPub.getY().isEven() ? "0x02" : "0x03",
    dhkeyPrefix: dhkey.getY().isEven() ? "0x02" : "0x03",
    hashSharedSecret,
  };
};

export const getAggregateSig = (
  owner: Wallet,
  sharedSecret: string,
  message: string
) => {
  const ownerSigner = EC.keyFromPrivate(owner.privateKey);
  const sharedKey = EC.keyFromPrivate(sharedSecret);
  var signature = ownerSigner.sign(utils.arrayify(message));

  const aggs = signature.s
    .mul(
      sharedKey
        .getPrivate()
        .mul(signature.r)
        .add(new BN(utils.arrayify(message), 16))
    )
    .umod(EC.g.curve.n);

  return utils.concat([
    "0x" + signature.r.toString(16),
    "0x" + aggs.toString(16),
  ]);
};
