use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use sha2::{Digest as _, Sha256};

pub struct OnionPacket;
pub struct Error;

/// Derives the ephemeral key for the next hop.
///
/// Assume that the current hop is $n_{i-1}$, and the next hop is $n_i$.
///
/// The parameters are:
///
/// - `ephemeral_key`: the ephemeral key of the current node $n_{i-1}$, which is x times the blinding factors so far: $x b_0 b_1 \cdots b_{i-2}$
/// - `shared_secret`: the shared secret of the current node $s_{i-1}$
///
/// Returns the ephemeral key for the mix node $n_i$, which is $x b_0 b_1 \cdots b_{i-1}$.
pub fn derive_next_hop_ephemeral_key<C: Signing>(
    ephemeral_key: SecretKey,
    shared_secret: &[u8],
    secp_ctx: &Secp256k1<C>,
) -> SecretKey {
    let alpha = ephemeral_key.public_key(secp_ctx);
    let blinding_factor: [u8; 32] = {
        let mut sha = Sha256::new();
        sha.update(&alpha.serialize()[..]);
        sha.update(shared_secret.as_ref());
        sha.finalize().into()
    };

    ephemeral_key
        .mul_tweak(&Scalar::from_be_bytes(blinding_factor).expect("valid scalar"))
        .expect("valid mul tweak")
}

pub fn new_onion_packet(
    _payment_path: Vec<PublicKey>,
    _session_key: SecretKey,
    _hops_data: Vec<Vec<u8>>,
    _assoc_data: Vec<u8>,
) -> Result<OnionPacket, Error> {
    Ok(OnionPacket)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use secp256k1::{ecdh::SharedSecret, Secp256k1};

    use super::*;

    #[test]
    fn it_works() {
        let packet = new_onion_packet(
            vec![],
            SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order"),
            vec![],
            vec![],
        );
        assert!(packet.is_ok());
    }

    #[test]
    fn test_deriving_next_hop_ephemeral_keys() {
        // From https://github.com/lightning/bolts/blob/master/04-onion-routing.md#test-vector

        let secp_ctx = Secp256k1::new();
        let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");

        let mut ephemeral_key = session_key.clone();

        {
            let pk = PublicKey::from_slice(
                &hex!("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")[..],
            )
            .expect("33 bytes, valid pubkey");
            let shared_secret = SharedSecret::new(&pk, &ephemeral_key);

            assert_eq!(
                base16::encode_lower(&shared_secret),
                "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
            );

            // Derive ephemeral public key from private key.
            ephemeral_key =
                derive_next_hop_ephemeral_key(ephemeral_key, shared_secret.as_ref(), &secp_ctx);
        }

        {
            let pk = PublicKey::from_slice(
                &hex!("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c")[..],
            )
            .expect("33 bytes, valid pubkey");
            let shared_secret = SharedSecret::new(&pk, &ephemeral_key);

            assert_eq!(
                base16::encode_lower(&shared_secret),
                "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae"
            );
        }
    }
}
