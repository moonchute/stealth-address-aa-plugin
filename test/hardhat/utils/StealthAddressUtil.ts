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
  const stealthPrivate = EC.keyFromPrivate(hashSharedSecret)
    .getPrivate()
    .add(ephemeralPriv)
    .mod(EC.g.curve.n);

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
    stealthPrivate: "0x" + stealthPrivate.toString("hex"),
    stealthAddress,
    stealthPub: stealthPub.getX().toString(),
    dhkey: dhkey.getX().toString(),
    stealthPrefix: stealthPub.getY().isEven() ? "0x02" : "0x03",
    dhkeyPrefix: dhkey.getY().isEven() ? "0x02" : "0x03",
    hashSharedSecret,
  };
};

export const getAggregateSig = async (
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

export const getZKMessage = (
  sharedSecret: string,
  message: string,
  signature: string
) => {
  const r = signature.slice(2, 66);
  const s = signature.slice(66, 130);
  const N = EC.g.curve.n;
  console.log("N:", N.toString());

  // bn
  const bnMessage = new BN(utils.arrayify(message), 16);
  const bnR = new BN(r, "hex");

  const secret = EC.keyFromPrivate(sharedSecret);
  const ecSharedSecret = secret.getPrivate();

  const aggH = bnMessage.sub(bnR.mul(ecSharedSecret).umod(N)).umod(N);

  return "0x" + aggH.toString(16, 64);
};

// bytes to 8 bytes array
export const bytes2bnArr = (bytes: Uint8Array) => {
  const arr = [];
  for (let i = bytes.length / 8 - 1; i >= 0; i--) {
    const rBN = BigInt(utils.hexlify(bytes.slice(i * 8, (i + 1) * 8)));
    arr.push(rBN);
  }
  return arr;
};

export const bigintSubMod = (a: bigint, b: bigint, N: bigint) => {
  const sub = (a - b) % N;
  const subString =
    "0x" + (sub > 0 ? sub : sub + N).toString(16).padStart(64, "0");

  return subString;
};
