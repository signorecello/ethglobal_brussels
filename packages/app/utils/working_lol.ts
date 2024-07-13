import {IMT} from '@zk-kit/imt';
import {BarretenbergSync, Fr} from '@aztec/bb.js';
import {p256, secp256r1} from '@noble/curves/p256';
import crypto from 'crypto';

import {Hex, bytesToHex, hexToBytes, sha256} from 'viem';
import {generatePrivateKey} from 'viem/accounts';

async function main() {
  const bb = await BarretenbergSync.new();

  const hash = (childNodes: string[]) =>
    bb.poseidon2Hash(childNodes.map(c => new Fr(BigInt(c)))).toString();

  const tree = new IMT(hash, 3, BigInt('0x00'));

  let privateKey = secp256r1.utils.randomPrivateKey();
  let publicKey = p256.getPublicKey(privateKey, false);
  let x = publicKey.slice(1).slice(0, 32);
  let y = publicKey.slice(1).slice(32);
  console.log('x', x);
  console.log('y', y);

  let msgHash = sha256(publicKey);
  console.log('message hash', hexToBytes(msgHash));
  let signature = p256.sign(msgHash.slice(2), privateKey);

  console.log(signature.toCompactRawBytes());
  //   console.log('recover');
  //   tree.insert(BigInt('0x' + publicKey) % Fr.MODULUS);

  // privateKey = secp256r1.utils.randomPrivateKey();
  // publicKey = privKeyToPubKeyDER(privateKey);
  // tree.insert(BigInt('0x' + publicKey) % Fr.MODULUS);

  // privateKey = secp256r1.utils.randomPrivateKey();
  // publicKey = privKeyToPubKeyDER(privateKey);
  // tree.insert(BigInt('0x' + publicKey) % Fr.MODULUS);

  // console.log(tree.createProof(0));
}

// const derPrefix = '0x3059301306072a8648ce3d020106082a8648ce3d03010703420004';

export function contractFriendlyKeyToDER(
  accountPubkey: readonly [Hex, Hex],
): Hex {
  return (accountPubkey[0].substring(2) + accountPubkey[1].substring(2)) as Hex;
}

function privKeyToPubKeyDER(privKey: Uint8Array): Hex {
  const publicKeyBytes = p256.getPublicKey(privKey, false);
  const x = bytesToHex(publicKeyBytes.subarray(1, 33), {size: 32});
  const y = bytesToHex(publicKeyBytes.subarray(33, 65), {size: 32});
  return contractFriendlyKeyToDER([x, y]);
}

main();
// genKey();
