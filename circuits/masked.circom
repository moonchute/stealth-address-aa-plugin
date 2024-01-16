pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "./bigint.circom";

template Masked() {
  signal input privkey[4];
  signal input message[4];
  signal input maskedMessage[4];
  signal input r[4];

  component sha256 = Sha256(512);
  component rPrivate = BigMultModP(64, 4);

  // secp256k1 order
  var order[4];
  order[0] = 13822214165235122497;
  order[1] = 13451932020343611451;
  order[2] = 18446744073709551614;
  order[3] = 18446744073709551615;
  component maskedSub1 = BigSubModP(64, 4);
  component maskedSub2 = BigSubModP(64, 4);
  component sha256Num[4];

  // compute Hash(priv,message)
  for (var i = 0; i < 4; i++) {
    for (var j = 0; j < 64; j++) {
      sha256.in[i * 64 + j] <-- (privkey[(3 - i)] >> (63 - j)) & 1;
    }
  }
  for (var i = 0; i < 4; i++) {
    for (var j = 0; j < 64; j++) {
      sha256.in[256 + i * 64 + j] <-- (message[(3 - i)] >> (63 - j)) & 1;
    }
  }
  for (var i = 0; i < 4; i++) {
    sha256Num[i] = Bits2Num(64);
    for (var j = 0; j < 8; j++) {
      for (var k = 0; k < 8; k++) {
        sha256Num[i].in[8 * j + k] <== sha256.out[(3 - i) * 64 + (7 -j) * 8 + (7 -k)];
      }
    }
  }

  // masked = message - Hash(priv,message) - r * privkey
  for (var i = 0; i < 4; i++) {
    rPrivate.a[i] <== privkey[i];
    rPrivate.b[i] <== r[i];
    rPrivate.p[i] <== order[i];
  }

  for (var i = 0; i < 4; i++) {
    maskedSub1.a[i] <== message[i];
    maskedSub1.b[i] <== rPrivate.out[i];
    maskedSub1.p[i] <== order[i];
  }

  for (var i = 0; i < 4; i++) {
    maskedSub2.a[i] <== maskedSub1.out[i];
    maskedSub2.b[i] <== sha256Num[i].out;
    maskedSub2.p[i] <== order[i];
  }

  for (var i = 0; i < 4; i++) {
    maskedMessage[i] === maskedSub2.out[i];
  }
}

component main {public [message, maskedMessage, r]} = Masked();