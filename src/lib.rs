use std::str::FromStr;

use hmac::{Hmac, Mac as _};
use secp256k1::{ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey, Signing};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const HOP_DATA_LEN: usize = 1300;

const HMAC_KEY_RHO: &[u8] = b"rho";
const HMAC_KEY_MU: &[u8] = b"mu";

// TODO: use molecule to serialize?
pub struct OnionPacket {
    pub version: u8,
    pub public_key: PublicKey,
    pub hop_data: [u8; HOP_DATA_LEN],
    pub hmac: [u8; 32],
}

impl OnionPacket {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 33 + HOP_DATA_LEN + 32);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.public_key.serialize());
        bytes.extend_from_slice(&self.hop_data);
        bytes.extend_from_slice(&self.hmac);
        bytes
    }
}

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

/// Generates the initial 1300 bytes of onion packet padding data from PRG.
///
/// Uses Chacha as the PRG. The key is derived from the session key using HMAC, and the nonce is all zeros.
pub fn generate_padding_data(pad_key: &[u8]) -> [u8; HOP_DATA_LEN] {
    use chacha20::{
        cipher::{KeyIvInit, StreamCipher},
        ChaCha20,
    };
    let mut cipher = ChaCha20::new(pad_key.into(), &[0u8; 12].into());
    let mut buffer = [0u8; HOP_DATA_LEN];
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn new_onion_packet(
    _payment_path: Vec<PublicKey>,
    _session_key: SecretKey,
    _hops_data: Vec<Vec<u8>>,
    _assoc_data: Vec<u8>,
) -> Result<OnionPacket, SphinxError> {
    Ok(OnionPacket {
        version: 0,
        public_key: PublicKey::from_str(
            "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        )
        .unwrap(),
        hop_data: [0u8; HOP_DATA_LEN],
        hmac: [0u8; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_conservative::prelude::*;

    fn get_test_session_key() -> SecretKey {
        SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order")
    }

    fn get_test_payment_path() -> Vec<PublicKey> {
        vec![
            Vec::from_hex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
            Vec::from_hex("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"),
            Vec::from_hex("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"),
            Vec::from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"),
            Vec::from_hex("02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145"),
        ]
        .into_iter()
        .map(|pk| PublicKey::from_slice(&pk.unwrap()).expect("33 bytes, valid pubkey"))
        .collect()
    }

    #[test]
    fn it_works() {
        let payment_path = get_test_payment_path();
        let session_key = get_test_session_key();
        let hops_data = vec![
            Vec::from_hex("1202023a98040205dc06080000000000000001").unwrap(),
            Vec::from_hex("52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f").unwrap(),
            Vec::from_hex("12020230d4040204e206080000000000000003").unwrap(),
            Vec::from_hex("1202022710040203e806080000000000000004").unwrap(),
            Vec::from_hex("fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a").unwrap(),
        ];
        let assoc_data = vec![0x42u8; 32];

        let packet = new_onion_packet(payment_path, session_key, hops_data, assoc_data).unwrap();
        let hex = "0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619f7f3416a5aa36dc7eeb3ec6d421e9615471ab870a33ac07fa5d5a51df0a8823aabe3fea3f90d387529d4f72837f9e687230371ccd8d263072206dbed0234f6505e21e282abd8c0e4f5b9ff8042800bbab065036eadd0149b37f27dde664725a49866e052e809d2b0198ab9610faa656bbf4ec516763a59f8f42c171b179166ba38958d4f51b39b3e98706e2d14a2dafd6a5df808093abfca5aeaaca16eded5db7d21fb0294dd1a163edf0fb445d5c8d7d688d6dd9c541762bf5a5123bf9939d957fe648416e88f1b0928bfa034982b22548e1a4d922690eecf546275afb233acf4323974680779f1a964cfe687456035cc0fba8a5428430b390f0057b6d1fe9a8875bfa89693eeb838ce59f09d207a503ee6f6299c92d6361bc335fcbf9b5cd44747aadce2ce6069cfdc3d671daef9f8ae590cf93d957c9e873e9a1bc62d9640dc8fc39c14902d49a1c80239b6c5b7fd91d05878cbf5ffc7db2569f47c43d6c0d27c438abff276e87364deb8858a37e5a62c446af95d8b786eaf0b5fcf78d98b41496794f8dcaac4eef34b2acfb94c7e8c32a9e9866a8fa0b6f2a06f00a1ccde569f97eec05c803ba7500acc96691d8898d73d8e6a47b8f43c3d5de74458d20eda61474c426359677001fbd75a74d7d5db6cb4feb83122f133206203e4e2d293f838bf8c8b3a29acb321315100b87e80e0edb272ee80fda944e3fb6084ed4d7f7c7d21c69d9da43d31a90b70693f9b0cc3eac74c11ab8ff655905688916cfa4ef0bd04135f2e50b7c689a21d04e8e981e74c6058188b9b1f9dfc3eec6838e9ffbcf22ce738d8a177c19318dffef090cee67e12de1a3e2a39f61247547ba5257489cbc11d7d91ed34617fcc42f7a9da2e3cf31a94a210a1018143173913c38f60e62b24bf0d7518f38b5bab3e6a1f8aeb35e31d6442c8abb5178efc892d2e787d79c6ad9e2fc271792983fa9955ac4d1d84a36c024071bc6e431b625519d556af38185601f70e29035ea6a09c8b676c9d88cf7e05e0f17098b584c4168735940263f940033a220f40be4c85344128b14beb9e75696db37014107801a59b13e89cd9d2258c169d523be6d31552c44c82ff4bb18ec9f099f3bf0e5b1bb2ba9a87d7e26f98d294927b600b5529c47e04d98956677cbcee8fa2b60f49776d8b8c367465b7c626da53700684fb6c918ead0eab8360e4f60edd25b4f43816a75ecf70f909301825b512469f8389d79402311d8aecb7b3ef8599e79485a4388d87744d899f7c47ee644361e17040a7958c8911be6f463ab6a9b2afacd688ec55ef517b38f1339efc54487232798bb25522ff4572ff68567fe830f92f7b8113efce3e98c3fffbaedce4fd8b50e41da97c0c08e423a72689cc68e68f752a5e3a9003e64e35c957ca2e1c48bb6f64b05f56b70b575ad2f278d57850a7ad568c24a4d32a3d74b29f03dc125488bc7c637da582357f40b0a52d16b3b40bb2c2315d03360bc24209e20972c200566bcf3bbe5c5b0aedd83132a8a4d5b4242ba370b6d67d9b67eb01052d132c7866b9cb502e44796d9d356e4e3cb47cc527322cd24976fe7c9257a2864151a38e568ef7a79f10d6ef27cc04ce382347a2488b1f404fdbf407fe1ca1c9d0d5649e34800e25e18951c98cae9f43555eef65fee1ea8f15828807366c3b612cd5753bf9fb8fced08855f742cddd6f765f74254f03186683d646e6f09ac2805586c7cf11998357cafc5df3f285329366f475130c928b2dceba4aa383758e7a9d20705c4bb9db619e2992f608a1ba65db254bb389468741d0502e2588aeb54390ac600c19af5c8e61383fc1bebe0029e4474051e4ef908828db9cca13277ef65db3fd47ccc2179126aaefb627719f421e20";
        assert_eq!(packet.into_bytes().len(), hex.len() / 2);
    }

    #[test]
    fn test_derive_hop_keys() {
        let payment_path = get_test_payment_path();
        let session_key = get_test_session_key();
        let hop_keys = derive_hop_keys(&payment_path, session_key, &Secp256k1::new());

        assert_eq!(hop_keys.len(), 5);

        // hop 0
        assert_eq!(
            hop_keys[0]
                .ephemeral_public_key
                .serialize()
                .to_lower_hex_string(),
            "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        );
        assert_eq!(
            hop_keys[0].rho.to_lower_hex_string(),
            "ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986",
        );
        assert_eq!(
            hop_keys[0].mu.to_lower_hex_string(),
            "b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba",
        );

        // hop 1
        assert_eq!(
            hop_keys[1]
                .ephemeral_public_key
                .serialize()
                .to_lower_hex_string(),
            "028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2",
        );
        assert_eq!(
            hop_keys[1].rho.to_lower_hex_string(),
            "450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59",
        );
        assert_eq!(
            hop_keys[1].mu.to_lower_hex_string(),
            "05ed2b4a3fb023c2ff5dd6ed4b9b6ea7383f5cfe9d59c11d121ec2c81ca2eea9",
        );

        // hop 2
        assert_eq!(
            hop_keys[2]
                .ephemeral_public_key
                .serialize()
                .to_lower_hex_string(),
            "03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0",
        );
        assert_eq!(
            hop_keys[2].rho.to_lower_hex_string(),
            "11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea",
        );
        assert_eq!(
            hop_keys[2].mu.to_lower_hex_string(),
            "caafe2820fa00eb2eeb78695ae452eba38f5a53ed6d53518c5c6edf76f3f5b78",
        );

        // hop 3
        assert_eq!(
            hop_keys[3]
                .ephemeral_public_key
                .serialize()
                .to_lower_hex_string(),
            "031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595",
        );
        assert_eq!(
            hop_keys[3].rho.to_lower_hex_string(),
            "cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e",
        );
        assert_eq!(
            hop_keys[3].mu.to_lower_hex_string(),
            "5052aa1b3d9f0655a0932e50d42f0c9ba0705142c25d225515c45f47c0036ee9",
        );

        // hop 4
        assert_eq!(
            hop_keys[4]
                .ephemeral_public_key
                .serialize()
                .to_lower_hex_string(),
            "03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4",
        );
        assert_eq!(
            hop_keys[4].rho.to_lower_hex_string(),
            "034e18b8cc718e8af6339106e706c52d8df89e2b1f7e9142d996acf88df8799b",
        );
        assert_eq!(
            hop_keys[4].mu.to_lower_hex_string(),
            "8e45e5c61c2b24cb6382444db6698727afb063adecd72aada233d4bf273d975a",
        );
    }

    #[test]
    fn test_derive_pad_key() {
        let session_key = get_test_session_key();
        let pad_key = derive_key(b"pad", &session_key.secret_bytes());
        assert_eq!(
            pad_key.to_lower_hex_string(),
            "70fa47d28edc4faf3e733ae0f4d2a12b8c5f09cbd74408eb7bc6ba2f1ebf88a2",
        );
    }

    #[test]
    fn test_generate_padding_data() {
        let pad_key = <[u8; 32]>::from_hex(
            "70fa47d28edc4faf3e733ae0f4d2a12b8c5f09cbd74408eb7bc6ba2f1ebf88a2",
        )
        .unwrap();
        let padding = generate_padding_data(&pad_key);
        let expected_hex = "77b5a170c57c6ff643fd6f46f5537c2fec4c5258f89fafbd722f9041f1cead9b2ab563384bc052ab9179e7d97defbee5324b29d5655f6816916310c4f08b69ad20a51ad7ffa2e07f5b28c30a2b3175adbf8d249c1fa55b02daa7c463eaf4b843ff9567afec9ef70cfc1d84ef29a802d1755c3cc6d04536744a71aa94a2419a6b5501ee8a8209191c1f43b357442a5c0847140db9c907bb2a325c414bfd1e72b1867526b071f96d718c176ff52894b45d1480149ad5d36614fb68b043d23aeb2806344832e8f925ed5428866912f4f1e7203ec73ec37fbb581e36b25fadc42bb4a5acf50d7ef1139a8482c7588bbfdfe5bde63ccb13b54d4368a4891e9c6c876814f189e9681a4efb59a91564e9f72e2047ce30840c06653ecc998ba216585cbeca617434a91a05bd8ae20b41ed84de5cfb0c3eb57ec721d4be57cf5f3223f99cfcb4250daee92b00b0de4c2d8e9e6cc6dafca49c136ef3b8ba7d983d52b079ef249f3c487ed6e982410bf86ab22636d22e06f3db5bbb887503167383f631e318ab71270528202994741264a40c69abe78eb0320ad420b229eca2335b928a3497cba182a427b0826260976608d5f50d35a5edc3574b532e28f114d21f93055f681f658fe9f6af8bac4ab5b1ec86dd575767501b6555963faba6766d70513c2cb8fbe6285f3ffea20b3b70b2e6960aca1633aa5368e19bec042ef32eacb5d326de1bc0e3120d9fe6da7f5407c7e77a66dac8f91ae11d727a5720a42ed152e6a95f61a61d80374fb0d6021d8f0a34e812bdba530bb4907b3192576a8021fae60615f89a420ada2f616fb9d006cc23621f72573e510417e91efe2335c246d614d105661866e878a1cae8dc29b92141b8d3e57479e73efa159e4a030531b54f0f9315a88e307bc0d152840166b88ed1afe6fbf159c3b74d04b7e9a31b93123fc5de7918eb1a8bd0a07ab4f07315ac5abbc36df06f613099d7f42d075366f42dd7ace9d975636363a5da4ea575a05c7114352a4b579b7aa129691e0b17934dd1146e34fa6246c953080503b9dfee62380669ebcb049e58bb259c6b1b64ff13891d0beb26dea5e624e5115ac1266e4facc65d5a0878066a253d1e9b3a2e465709ede22b312da118ad0446f2e725177452fd8f8b2eb743dbdbe3298e628c6910eb722415167eae745a28d15e2a0221db7ac7b684523b0af415acbcb9bed1d5a6fe74bb0e4e20543d684da1fad2199830e7ac421168acbc6ed547fd1ab4acd32adc34329af0a2ebfa80edeefb6fff2d6a4828b7b67da22f59ca68edcae4832be0ea856b075efbb4e14fad5e0ea5269cd75bac001acbc512833b44bbead8c861c8b2755ced0d594b7fd6b61f7f80341fe02549600298e1f68685f582d8bf5f51c01e2a68324456fd4cc342200252fd9a0025ce6b921bee965a350638830920a90f715959a936bc7cb6fef1fde4524c7eae46677efcd87be375ce25afa0d7c82bf445578ff6c49a3e461fcbe18faf4c6d711fd62a2a14e683f5919e7672deec93ccc0a843e90f7d88365bf469151793dbd9b15ef16a44909238f23cf84bcf11736089ab5ed0a0063c023cc0f90374dc37430e4279c05adb333e98cea0e650345d989b53653a1a3820410b7a1ad25bcfb39618c2b6ac29b2baa5325cc92647c9d13428d8be77b8c5f9c0492fc85a6d770ee6f123edc25b3009304c8691d90c2c54abf07413ac2ddd4d1abe34841739d4d88e865f7dda32bfe7a914400c7aa41a05745d9a4158641b26c510d671e4a539ac8d5f7a3ddb227d02788ba7b33222f2d1af605378636cddfa81825ebea6b68b0d8fca71277cdda7af17";
        assert_eq!(padding.to_lower_hex_string(), expected_hex);
    }
}
