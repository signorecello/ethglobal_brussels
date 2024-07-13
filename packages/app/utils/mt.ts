import {IMT} from '@zk-kit/imt';
import {BarretenbergSync, Fr} from '@aztec/bb.js';
import {p256, secp256r1} from '@noble/curves/p256';
import crypto from 'crypto';

import {ByteArray, Hex, bytesToHex, hexToBytes, sha256} from 'viem';
import {generatePrivateKey} from 'viem/accounts';
import json2toml from 'json2toml';
import {writeFileSync} from 'fs';
import {resolve} from 'path';
import {execSync} from 'child_process

/*
0x31c8ade75ea71860119fba204d14fde72f10ca0232e8d252a79d43a66e7febe4
0x3d136a9cf7aedd66e0b639b0f0b6b7fb402b1976c0b06693e07cfd58deb8c7f0
0xcecd2246f98d9cfa45c3dd32c8697945c833b5dce0b37d270abbf07f62ead2a6
*/

const privateKeys: Uint8Array[] = [
  new Uint8Array([
    50, 194, 13, 104, 255, 160, 58, 79, 28, 157, 100, 23, 82, 92, 84, 106, 142,
    76, 231, 85, 67, 68, 18, 110, 92, 229, 41, 182, 130, 171, 22, 173,
  ]),
  new Uint8Array([
    117, 35, 123, 26, 211, 211, 133, 161, 0, 223, 173, 178, 203, 6, 63, 51, 90,
    57, 214, 180, 239, 227, 187, 85, 185, 221, 76, 241, 11, 57, 57, 123,
  ]),
  new Uint8Array([
    61, 198, 24, 52, 125, 60, 144, 66, 247, 86, 215, 26, 28, 84, 40, 196, 17,
    25, 252, 245, 246, 187, 102, 96, 24, 132, 145, 241, 170, 46, 172, 238,
  ]),
];

const getSigner = (index: number) => {
  let privateKey = secp256r1.utils.randomPrivateKey();
  // let privateKey = privateKeys[index];
  let publicKey = p256.getPublicKey(privateKey, false);
  let x = publicKey.slice(1).slice(0, 32);
  let y = publicKey.slice(1).slice(32);
  let msgHash = sha256(publicKey);
  let signature = p256.sign(msgHash.slice(2), privateKey);
  return {
    x: [...x],
    y: [...y],
    msgHash: [...hexToBytes(msgHash)],
    signature: [...signature.toCompactRawBytes()],
    // recover: p256.verify(signature, msgHash.slice(2), publicKey),
  };
};

async function main() {
  const bb = await BarretenbergSync.new();

  const hash = (childNodes: string[]) =>
    bb.poseidon2Hash(childNodes.map(c => new Fr(BigInt(c)))).toString();

  const tree = new IMT(hash, 3, BigInt('0x00'));
  const signer = getSigner(0);
  const toml = json2toml(signer);

  writeFileSync(resolve('circuit/Prover.toml'), toml);
  // execSync("cd circuit && nargo prove");
  // console.log(signer);
  // console.log(sha256(signer.publicKey.slice(1)));
  // tree.insert(BigInt('0x' + signer.publicKey) % Fr.MODULUS);
}

main();
// genKey();
