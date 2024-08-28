use secp256k1::{ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey, Signing};
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

/// Derives the shared secrets for all hops in the payment path.
///
/// - `payment_path`: the list of public keys of the nodes in the payment path.
/// - `session_key`: the random generated ephemeral key, which is $x$ in the paper.
pub fn derive_hop_shared_secrets<C: Signing>(
    payment_path: &Vec<PublicKey>,
    session_key: SecretKey,
    secp_ctx: &Secp256k1<C>,
) -> Vec<Vec<u8>> {
    payment_path
        .iter()
        .scan(session_key, |ephemeral_key, pk| {
            let shared_secret = SharedSecret::new(pk, ephemeral_key);
            *ephemeral_key =
                derive_next_hop_ephemeral_key(*ephemeral_key, shared_secret.as_ref(), secp_ctx);
            Some(shared_secret.as_ref().to_vec())
        })
        .collect()
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
    fn test_derive_hop_shared_secrets() {
        let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
        let payment_path = vec![
            hex!("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
            hex!("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"),
            hex!("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"),
            hex!("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"),
            hex!("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145"),
        ]
        .into_iter()
        .map(|pk| PublicKey::from_slice(&pk).expect("33 bytes, valid pubkey"))
        .collect();

        let shared_secrets =
            derive_hop_shared_secrets(&payment_path, session_key, &Secp256k1::new())
                .into_iter()
                .map(|ss| base16::encode_lower(ss.as_slice()))
                .collect::<Vec<_>>();

        let expected_shared_secrets = vec![
            "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
            "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae",
            "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc",
            "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d",
            "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328",
        ];
        assert_eq!(shared_secrets.len(), expected_shared_secrets.len());
        for (ss, expected_ss) in shared_secrets.iter().zip(expected_shared_secrets.iter()) {
            assert_eq!(ss, expected_ss);
        }
    }
}
