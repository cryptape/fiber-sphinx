use hmac::{Hmac, Mac as _};
use secp256k1::{ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub struct OnionPacket;

#[derive(Error, Debug)]
pub enum SphinxError {
    #[error("unknown sphinx error")]
    Unknown,
}

/// Derives the ephemeral secret key for the next hop.
///
/// Assume that the current hop is $n_{i-1}$, and the next hop is $n_i$.
///
/// The parameters are:
///
/// - `ephemeral_secret_key`: the ephemeral secret key of the current node $n_{i-1}$,
///     which is x times the blinding factors so far: $x b_0 b_1 \cdots b_{i-2}$
/// - `ephemeral_public_key`: the corresponding public key of `ephemeral_secret_key`
/// - `shared_secret`: the shared secret of the current node $s_{i-1}$
///
/// Returns the ephemeral secret key for the mix node $n_i$, which is $x b_0 b_1 \cdots b_{i-1}$.
fn derive_next_hop_ephemeral_secret_key(
    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: &PublicKey,
    shared_secret: &[u8],
) -> SecretKey {
    let blinding_factor: [u8; 32] = {
        let mut sha = Sha256::new();
        sha.update(&ephemeral_public_key.serialize()[..]);
        sha.update(shared_secret.as_ref());
        sha.finalize().into()
    };

    ephemeral_secret_key
        .mul_tweak(&Scalar::from_be_bytes(blinding_factor).expect("valid scalar"))
        .expect("valid mul tweak")
}

const HMAC_KEY_RHO: &[u8] = b"rho";
const HMAC_KEY_MU: &[u8] = b"mu";

// Keys manager for each hop
pub struct HopKeys {
    pub ephemeral_public_key: PublicKey,
    pub rho: [u8; 32],
    pub mu: [u8; 32],
}

pub fn derive_hop_keys<C: Signing>(
    payment_path: &Vec<PublicKey>,
    session_key: SecretKey,
    secp_ctx: &Secp256k1<C>,
) -> Vec<HopKeys> {
    payment_path
        .iter()
        .scan(session_key, |ephemeral_secret_key, pk| {
            let ephemeral_public_key = ephemeral_secret_key.public_key(secp_ctx);

            let shared_secret = SharedSecret::new(pk, ephemeral_secret_key);
            let rho = derive_key(HMAC_KEY_RHO, shared_secret.as_ref());
            let mu = derive_key(HMAC_KEY_MU, shared_secret.as_ref());

            *ephemeral_secret_key = derive_next_hop_ephemeral_secret_key(
                *ephemeral_secret_key,
                &ephemeral_public_key,
                shared_secret.as_ref(),
            );

            Some(HopKeys {
                ephemeral_public_key,
                rho,
                mu,
            })
        })
        .collect()
}

pub fn derive_key(hmac_key: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("valid hmac key");
    mac.update(shared_secret);
    mac.finalize().into_bytes().into()
}

pub fn new_onion_packet(
    _payment_path: Vec<PublicKey>,
    _session_key: SecretKey,
    _hops_data: Vec<Vec<u8>>,
    _assoc_data: Vec<u8>,
) -> Result<OnionPacket, SphinxError> {
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
    fn test_derive_hop_keys() {
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

        let hop_keys = derive_hop_keys(&payment_path, session_key, &Secp256k1::new());

        assert_eq!(hop_keys.len(), 5);

        // hop 0
        assert_eq!(
            base16::encode_lower(&(hop_keys[0].ephemeral_public_key.serialize())[..]),
            "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[0].rho)[..]),
            "ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[0].mu)[..]),
            "b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba",
        );

        // hop 1
        assert_eq!(
            base16::encode_lower(&(hop_keys[1].ephemeral_public_key.serialize())[..]),
            "028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[1].rho)[..]),
            "450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[1].mu)[..]),
            "05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9",
        );

        // hop 2
        assert_eq!(
            base16::encode_lower(&(hop_keys[2].ephemeral_public_key.serialize())[..]),
            "03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[2].rho)[..]),
            "11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[2].mu)[..]),
            "caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78",
        );

        // hop 3
        assert_eq!(
            base16::encode_lower(&(hop_keys[3].ephemeral_public_key.serialize())[..]),
            "031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[3].rho)[..]),
            "cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[3].mu)[..]),
            "5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9",
        );

        // hop 4
        assert_eq!(
            base16::encode_lower(&(hop_keys[4].ephemeral_public_key.serialize())[..]),
            "03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[4].rho)[..]),
            "034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b",
        );
        assert_eq!(
            base16::encode_lower(&(hop_keys[4].mu)[..]),
            "8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a",
        );
    }
}
