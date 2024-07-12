import {IMT} from '@zk-kit/imt';
import {BarretenbergSync, Fr} from '@aztec/bb.js';

async function main() {
  const bb = await BarretenbergSync.new();

  const hash = (childNodes: string[]) =>
    bb.poseidon2Hash(childNodes.map(c => new Fr(BigInt(c)))).toString();

  const tree = new IMT(hash, 3, BigInt('0x00'));

  tree.insert(BigInt('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'));
  tree.insert(BigInt('0x70997970C51812dc3A010C7d01b50e0d17dc79C8'));
  tree.insert(BigInt('0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'));
  console.log(tree.createProof(0));
}

main();
