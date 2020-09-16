// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};
use threshold_crypto as bls;

/// Proof that a quorum of the section elders has agreed on something.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Proof {
    /// The BLS public key.
    pub public_key: bls::PublicKey,
    /// The BLS signature corresponding to the public key.
    pub signature: bls::Signature,
}

impl Proof {
    /// Verifies this proof against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key.verify(&self.signature, payload)
    }
}

/// Single share of `Proof`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProofShare {
    /// BLS public key set.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the node that created this proof share.
    pub index: usize,
    /// BLS signature share corresponding to the `index`-th public key share of the public key set.
    pub signature_share: bls::SignatureShare,
}

impl ProofShare {
    /// Creates new proof share.
    pub fn new(
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
        payload: &[u8],
    ) -> Self {
        Self {
            public_key_set,
            index,
            signature_share: secret_key_share.sign(payload),
        }
    }

    /// Verifies this proof share against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key_set
            .public_key_share(self.index)
            .verify(&self.signature_share, payload)
    }
}

impl Debug for ProofShare {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "ProofShare {{ public_key: {:?}, index: {}, .. }}",
            self.public_key_set.public_key(),
            self.index
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::Proof;
    use threshold_crypto::SecretKey;

    #[test]
    fn verify_proof() {
        let sk = SecretKey::random();
        let public_key = sk.public_key();
        let data = "hello".to_string();
        let signature = sk.sign(&data);
        let proof = Proof {
            public_key,
            signature,
        };
        assert!(proof.verify(&data.as_bytes()));
    }
}
