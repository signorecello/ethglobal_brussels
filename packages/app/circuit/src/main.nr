use dep::std::ecdsa_secp256r1::verify_signature;
use dep::std::hash::poseidon2::Poseidon2::hash;
use dep::std::hash::sha256;

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

fn main(
    x: [u8; 32],
    y: [u8; 32],
    msgHash: pub [u8; 32],
    signature: [u8; 64] // paths: [Field; TREE_SIZE],
    // indices: Field,
    // root: pub Field
) {
    // let mut mt = MerkleTree::default(root, hasher);

    let valid_signature = verify_signature(x, y, signature, msgHash);
    assert(valid_signature);
    // let pubkey_slice = pub_key_x.as_slice().append(pub_key_y.as_slice());
    // let pubkey_array : [u8; 64] = pubkey_slice.as_array();
    // println(pubkey_array);
    // let leaf_array = sha256(pubkey_array);
    // let mut leaf : Field = 0;
    // for i in 0..32 {
    //     leaf = (leaf * 256) + (leaf_array[i] as Field);
    // }
    // println(leaf);
    // let siblings = paths;
    // assert(root == mt.root(leaf, indices, siblings));
}

#[test]
fn test_leaf_0() {
    let x = [
        240, 243, 75, 130, 121, 227, 193, 42,
        154, 70, 197, 169, 202, 73, 57, 251,
        83, 83, 74, 37, 8, 89, 161, 103,
        137, 240, 128, 226, 12, 103, 245, 36
    ];
    let y = [
        191, 16, 166, 111, 133, 146, 220,
        59, 186, 73, 214, 29, 230, 26,
        198, 239, 128, 124, 12, 226, 155,
        238, 84, 85, 108, 15, 140, 234,
        106, 15, 134, 182
    ];
    let hashed = [
        228, 118, 141, 99, 237, 121, 215,
        125, 70, 236, 226, 80, 150, 121,
        98, 228, 237, 147, 205, 151, 92,
        108, 253, 45, 230, 27, 126, 100,
        157, 226, 44, 123
    ];
    let signature = [
        106, 155, 194, 151, 145, 94, 49, 171, 126, 32, 160,
        89, 75, 21, 172, 0, 255, 164, 232, 167, 180, 97,
        240, 238, 100, 55, 48, 85, 83, 33, 127, 224, 194,
        215, 197, 162, 196, 132, 147, 243, 68, 86, 224, 112,
        131, 122, 133, 54, 144, 213, 210, 144, 163, 253, 135,
        2, 181, 5, 188, 214, 179, 241, 16, 236
    ];
    // let root = 0x1a0962962735cfb8bd29eefda168aeb30253848b548c70bef32a06437ed39a50;
    // let paths = [
    //     0x1b7fdccd18c5db0507b95cdeef0c0bf13cc6f7af1c5b325dad189359d4b674af,
    //     0x071e1136e70ef083e239518fabd6a4a8b13e161a5055ade98fcc612c2c7014a5,
    //     0x0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290
    // ];
    // let indices = 0;
    main(x, y, hashed, signature);
}
