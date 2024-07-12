use dep::std::ecdsa_secp256r1::verify_signature_slice;
use dep::std::hash::poseidon2::Poseidon2::hash;

global TREE_SIZE: u64 = 3;

// owners:
// a is h(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
// b is h(0x70997970C51812dc3A010C7d01b50e0d17dc79C8)
// c is h(0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC)

struct MerkleTree {
    root: Field,
    hasher: fn([Field; 2]) -> Field,
}

impl MerkleTree {
    fn default(root: Field, hasher: fn([Field; 2]) -> Field) -> Self {
        Self { root, hasher }
    }

    fn root(self, leaf: Field, indices: Field, siblings: ([Field; TREE_SIZE])) -> Field {
        let index_bits = indices.to_le_bits(TREE_SIZE as u32);
        let mut node = leaf;
        for i in 0..siblings.len() {
            let sibling = siblings[i];
            if sibling != 0 {
                let mut left = sibling;
                let mut right = node;
                if index_bits[i] == 0 {
                    left = node;
                    right = sibling;
                }
                node = (self.hasher)([left, right]);
            }
        }
        node
    }
}

// root is 0x21167ecd7bf6a886e76fcc0a4a160250dee259b6252f2972e5bca57e85e74f84

fn hasher(leaves: [Field; 2]) -> Field {
    hash([leaves[0], leaves[1]], 2)
}

fn main(paths: [Field; TREE_SIZE], indices: Field, entry: Field, root: Field) {
    let mut mt = MerkleTree::default(root, hasher);

    let siblings = paths;
    assert(root == mt.root(entry, indices, siblings));
}

#[test]
fn some_test() {
    let root = 0x2a102514e4d1bd10f58d0744001e6c415b9c3082b6ccfe6b64b4b129f5a28a4f;
    let entry = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
    let paths = [
        0x70997970c51812dc3a010c7d01b50e0d17dc79c8,
        0x24f0ac648ded87a26e87444e6bf113fb6c1951fddeb573eab915ff71fc616b10,
        0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290
    ];
    let indices = 0;
    main(paths, indices, entry, root);
}
