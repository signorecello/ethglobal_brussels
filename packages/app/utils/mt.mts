import {IMT} from '@zk-kit/imt';
import {BarretenbergSync, Fr} from '@aztec/bb.js';
import {p256, secp256r1} from '@noble/curves/p256';
import crypto from 'crypto';

import {ByteArray, Hex, bytesToHex, hexToBytes, sha256, pad} from 'viem';
import {generatePrivateKey} from 'viem/accounts';
import json2toml from 'json2toml';
import {writeFileSync} from 'fs';
import {resolve} from 'path';
import {execSync} from 'child_process';

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

export function bytesToBigInt(bytes: number[]): bigint {
  return BigInt(
    `0x${bytes.map(b => b.toString(16).padStart(2, '0')).join('')}`,
  );
}

export function bigIntToBytes(int: bigint): number[] {
  const hex = int.toString(16);
  return hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || [];
}

const getSigner = (index: number) => {
  // let privateKey = secp256r1.utils.randomPrivateKey();
  let privateKey = privateKeys[index];
  let publicKey = p256.getPublicKey(privateKey, false);
  let x = publicKey.slice(1).slice(0, 32);
  let y = publicKey.slice(1).slice(32);
  let msgHash = sha256(publicKey);
  let malleableSignature = p256.sign(msgHash.slice(2), privateKey);

  const bSig = hexToBytes(`0x${malleableSignature.toCompactHex()}`);
  if (bSig.length !== 64) {
    throw new Error('Invalid signature length');
  }
  const bR = bSig.slice(0, 32);
  const bS = bSig.slice(32);

  // Avoid malleability. Ensure low S (<= N/2 where N is the curve order)
  const r = bytesToBigInt(Array.from(bR));
  let s = bytesToBigInt(Array.from(bS));
  const n = BigInt(
    '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
  );
  if (s > n / 2n) {
    s = n - s;
  }

  const signature = p256.Signature.fromCompact(
    Uint8Array.from([...bigIntToBytes(r), ...bigIntToBytes(s)]),
  );
  return {
    toml: {
      x: [...x],
      y: [...y],
      msgHash: [...hexToBytes(msgHash)],
      signature: [...signature.toCompactRawBytes()],
    },
    recover: p256.verify(signature, msgHash.slice(2), publicKey),
    nullifier: sha256(publicKey.slice(1)),
  };
};

const hash = (childNodes: bigint[]) => {
  const arr: `0x${string}` = pad(
    `0x${childNodes.map(c => c.toString(16).replace('0x', '')).join('')}`,
    {dir: 'right', size: 64},
  );
  return sha256(arr);
};

const tree = new IMT(hash, 3, BigInt('0x00'));

async function main(user: number) {
  const {toml, nullifier} = getSigner(user);
  tree.insert(nullifier);
  const mtProof = tree.createProof(user);
  console.log(mtProof);
  let indices = user;
  let root = [...hexToBytes(mtProof.root)];
  let paths = mtProof.siblings.map(sibling => [
    ...pad(hexToBytes(`0x${BigInt(sibling).toString(16)}`)),
  ]);
  const tomlToWrite = json2toml({...toml, indices, root, paths});

  writeFileSync(resolve('circuit/Prover.toml'), tomlToWrite);

  console.log(tomlToWrite);
  console.log('Wrote Prover.toml');
  console.log('Proving');
  execSync('cd circuit && nargo prove');
}

await main(0);
await main(1);
await main(2);
