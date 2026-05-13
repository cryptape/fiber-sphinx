//! A Rust implementation of [Sphinx][] (a.k.a. Onion Message) for [Fiber][].
//!
//! [Sphinx]: http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf
//! [Fiber]: https://github.com/nervosnetwork/fiber
//!
//! See more in the [Specification](https://github.com/nervosnetwork/fiber-sphinx/blob/develop/docs/spec.md).
//!
//! ## Example
//!
//! ```rust
//! use secp256k1::{PublicKey, SecretKey, Secp256k1};
//! use fiber_sphinx::OnionPacket;
//!
//! let secp = Secp256k1::new();
//! let hops_keys = vec![
//!     SecretKey::from_slice(&[0x20; 32]).expect("32 bytes, within curve order"),
//!     SecretKey::from_slice(&[0x21; 32]).expect("32 bytes, within curve order"),
//!     SecretKey::from_slice(&[0x22; 32]).expect("32 bytes, within curve order"),
//! ];
//! let hops_path = hops_keys.iter().map(|sk| sk.public_key(&secp)).collect();
//! let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
//! // Use the first byte to indicate the data len
//! let hops_data = vec![vec![0], vec![1, 0], vec![5, 0, 1, 2, 3, 4]];
//! let get_length = |packet_data: &[u8]| Some(packet_data[0] as usize + 1);
//! let assoc_data = vec![0x42u8; 32];
//!
//! let packet = OnionPacket::create(
//!     session_key,
//!     hops_path,
//!     hops_data.clone(),
//!     Some(assoc_data.clone()),
//!     1300,
//!     &secp,
//! ).expect("new onion packet");
//!
//! // Hop 0
//! # use fiber_sphinx::SphinxError;
//! # {
//! #     // error cases
//! #     let res = packet.clone().peel(&hops_keys[0], None, &secp, get_length);
//! #     assert_eq!(res, Err(SphinxError::HmacMismatch));
//! #     let res = packet
//! #         .clone()
//! #         .peel(&hops_keys[0], Some(&assoc_data), &secp, |_| None);
//! #     assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
//! # }
//! let res = packet.peel(&hops_keys[0], Some(&assoc_data), &secp, get_length);
//! assert!(res.is_ok());
//! let (data, packet) = res.unwrap();
//! assert_eq!(data, hops_data[0]);
//!
//! // Hop 1
//! # {
//! #     // error cases
//! #     let res = packet.clone().peel(&hops_keys[1], None, &secp, get_length);
//! #     assert_eq!(res, Err(SphinxError::HmacMismatch));
//! #     let res = packet
//! #         .clone()
//! #         .peel(&hops_keys[1], Some(&assoc_data), &secp, |_| None);
//! #     assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
//! # }
//! let res = packet.peel(&hops_keys[1], Some(&assoc_data), &secp, get_length);
//! assert!(res.is_ok());
//! let (data, packet) = res.unwrap();
//! assert_eq!(data, hops_data[1]);
//!
//! // Hop 2
//! # {
//! #     // error cases
//! #     let res = packet.clone().peel(&hops_keys[2], None, &secp, get_length);
//! #     assert_eq!(res, Err(SphinxError::HmacMismatch));
//! #     let res = packet
//! #         .clone()
//! #         .peel(&hops_keys[2], Some(&assoc_data), &secp, |_| None);
//! #     assert_eq!(res, Err(SphinxError::HopDataLenUnavailable));
//! # }
//! let res = packet.peel(&hops_keys[2], Some(&assoc_data), &secp, get_length);
//! assert!(res.is_ok());
//! let (data, _packet) = res.unwrap();
//! assert_eq!(data, hops_data[2]);
//! ```
use chacha20::{
    cipher::{KeyIvInit as _, StreamCipher},
    ChaCha20,
};
use hmac::{Hmac, Mac as _};
use secp256k1::{
    ecdh::SharedSecret, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const HMAC_KEY_RHO: &[u8] = b"rho";
const HMAC_KEY_MU: &[u8] = b"mu";
const HMAC_KEY_PAD: &[u8] = b"pad";
const HMAC_KEY_UM: &[u8] = b"um";
const HMAC_KEY_AMMAG: &[u8] = b"ammag";
const CHACHA_NONCE: [u8; 12] = [0u8; 12];

/// Onion packet to send encrypted message via multiple hops.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OnionPacket {
    /// Version of the onion packet, currently 0
    pub version: u8,
    /// The public key of the next hop. _Alpha_ in the specification.
    pub public_key: PublicKey,
    /// Encrypted packet data. _Beta_ in the specification.
    pub packet_data: Vec<u8>,
    /// HMAC of the packet data. _Gamma_ in the specification.
    pub hmac: [u8; 32],
}

/// Onion error packet to return errors to the origin node.
///
/// The nodes must store the shared secrets to forward `OnionPacket` locally and reuse them to obfuscate
/// the error packet. See the section "Returning Errors" in the specification for details.
///
/// ## Example
///
/// ```rust
/// use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// use std::str::FromStr;
/// use fiber_sphinx::{OnionErrorPacket, OnionPacket, OnionSharedSecretIter};
///
/// let secp = Secp256k1::new();
/// let hops_path = vec![
///   PublicKey::from_str("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619").expect("valid public key"),
///   PublicKey::from_str("0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c").expect("valid public key"),
///   PublicKey::from_str("027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007").expect("valid public key"),
/// ];
/// let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
/// let hops_ss = OnionSharedSecretIter::new(hops_path.iter(), session_key, &secp).collect::<Vec<_>>();
///
/// // The node 0324653...0ab1c generates the error
/// let shared_secret = hops_ss[1];
/// let error_packet = OnionErrorPacket::create(&shared_secret, b"error message".to_vec());
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OnionErrorPacket {
    /// Encrypted error-returning packet data.
    pub packet_data: Vec<u8>,
}

impl OnionPacket {
    /// Creates the new onion packet for the first hop.
    ///
    /// - `hops_path`: The public keys for each hop. These are _y_<sub>i</sub> in the specification.
    /// - `session_key`: The ephemeral secret key for the onion packet. It must be generated securely using a random process.
    ///   This is _x_ in the specification.
    /// - `hops_data`: The unencrypted data for each hop. **Attention** that the data for each hop will be concatenated with
    ///   the remaining encrypted data. To extract the data, the receiver must know the data length. For example, the hops
    ///   data can include its length at the beginning. These are _m_<sub>i</sub> in the specification.
    /// - `assoc_data`: The associated data. It will not be included in the packet itself but will be covered by the packet's
    ///   HMAC. This allows each hop to verify that the associated data has not been tampered with. This is _A_ in the
    ///   specification.
    /// - `onion_packet_len`: The length of the onion packet. The packet has the same size for each hop.
    pub fn create<C: Signing>(
        session_key: SecretKey,
        hops_path: Vec<PublicKey>,
        hops_data: Vec<Vec<u8>>,
        assoc_data: Option<Vec<u8>>,
        packet_data_len: usize,
        secp_ctx: &Secp256k1<C>,
    ) -> Result<OnionPacket, SphinxError> {
        if hops_path.len() != hops_data.len() {
            return Err(SphinxError::HopsLenMismatch);
        }
        if hops_path.is_empty() {
            return Err(SphinxError::HopsIsEmpty);
        }

        let hops_keys = derive_hops_forward_keys(&hops_path, session_key, secp_ctx);
        let pad_key = derive_key(HMAC_KEY_PAD, &session_key.secret_bytes());
        let packet_data = generate_padding_data(packet_data_len, &pad_key);
        let filler = generate_filler(packet_data_len, &hops_keys, &hops_data)?;

        construct_onion_packet(
            packet_data,
            session_key.public_key(secp_ctx),
            &hops_keys,
            &hops_data,
            assoc_data,
            filler,
        )
    }

    /// Converts the onion packet into a byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + 33 + self.packet_data.len() + 32);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.public_key.serialize());
        bytes.extend_from_slice(&self.packet_data);
        bytes.extend_from_slice(&self.hmac);
        bytes
    }

    /// Converts back from a byte vector.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SphinxError> {
        if bytes.len() < 66 {
            return Err(SphinxError::PacketDataLenTooSmall);
        }
        let version = bytes[0];
        let public_key =
            PublicKey::from_slice(&bytes[1..34]).map_err(|_| SphinxError::PublicKeyInvalid)?;
        let packet_data = (&bytes[34..(bytes.len() - 32)]).into();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&bytes[(bytes.len() - 32)..]);

        Ok(Self {
            version,
            public_key,
            packet_data,
            hmac,
        })
    }

    pub fn extract_public_key_from_slice(bytes: &[u8]) -> Result<PublicKey, SphinxError> {
        if bytes.len() < 66 {
            return Err(SphinxError::PacketDataLenTooSmall);
        }
        PublicKey::from_slice(&bytes[1..34]).map_err(|_| SphinxError::PublicKeyInvalid)
    }

    /// Derives the shared secret using the node secret key and the ephemeral public key in the onion packet.
    pub fn shared_secret(&self, secret_key: &SecretKey) -> [u8; 32] {
        SharedSecret::new(&self.public_key, secret_key).secret_bytes()
    }

    /// Peels the onion packet at the current hop.
    ///
    /// - `secret_key`: the node private key. _x_<sub>i</sub> in the specification.
    /// - `assoc_data`: The associated data. It was covered by the onion packet's HMAC. _A_ in the specification.
    /// - `get_hop_data_len`: Tell the hop data len given the decrypted packet data for the current hop.
    ///
    /// Returns a tuple (m, p) where m is the hop data for the current hop, and p is remaining onion packet for
    /// the next hop.
    pub fn peel<C, F>(
        self,
        secret_key: &SecretKey,
        assoc_data: Option<&[u8]>,
        secp_ctx: &Secp256k1<C>,
        get_hop_data_len: F,
    ) -> Result<(Vec<u8>, Self), SphinxError>
    where
        C: Verification,
        F: FnOnce(&[u8]) -> Option<usize>,
    {
        let packet_data_len = self.packet_data.len();
        let shared_secret = self.shared_secret(secret_key);
        let rho = derive_key(HMAC_KEY_RHO, shared_secret.as_ref());
        let mu = derive_key(HMAC_KEY_MU, shared_secret.as_ref());

        if !verify_hmac(&mu, &self.packet_data, assoc_data, &self.hmac) {
            return Err(SphinxError::HmacMismatch);
        }

        let mut chacha = ChaCha20::new(&rho.into(), &CHACHA_NONCE.into());
        let mut packet_data = self.packet_data;
        chacha.apply_keystream(&mut packet_data[..]);

        // data | hmac | remaining
        let data_len = get_hop_data_len(&packet_data).ok_or(SphinxError::HopDataLenUnavailable)?;
        let hmac_end = data_len
            .checked_add(32)
            .ok_or(SphinxError::HopDataLenTooLarge)?;
        if hmac_end > packet_data_len {
            return Err(SphinxError::HopDataLenTooLarge);
        }
        let hop_data = packet_data[0..data_len].to_vec();
        let mut hmac = [0; 32];
        hmac.copy_from_slice(&packet_data[data_len..hmac_end]);
        shift_slice_left(&mut packet_data[..], hmac_end);
        // Encrypt 0 bytes until the end
        chacha.apply_keystream(&mut packet_data[(packet_data_len - hmac_end)..]);

        let public_key =
            derive_next_hop_ephemeral_public_key(self.public_key, shared_secret.as_ref(), secp_ctx);

        Ok((
            hop_data,
            OnionPacket {
                version: self.version,
                public_key,
                packet_data,
                hmac,
            },
        ))
    }
}

impl OnionErrorPacket {
    /// Creates an onion error packet using the erring node shared secret.
    ///
    /// The erring node should store the shared secrets to forward the onion packet locally and reuse them to obfuscate
    /// the error packet.
    ///
    /// The shared secret can be obtained via `OnionPacket::shared_secret`.
    pub fn create(shared_secret: &[u8; 32], payload: Vec<u8>) -> Self {
        let ReturnKeys { ammag, um } = ReturnKeys::new(shared_secret);
        let hmac = compute_hmac(&um, &payload, None);
        Self::concat(hmac, payload).xor_cipher_stream_with_ammag(ammag)
    }

    /// Concatenates HMAC and the payload without encryption.
    pub fn concat(hmac: [u8; 32], mut payload: Vec<u8>) -> Self {
        let mut packet_data = hmac.to_vec();
        packet_data.append(&mut payload);
        OnionErrorPacket { packet_data }
    }

    fn xor_cipher_stream_with_ammag(self, ammag: [u8; 32]) -> Self {
        let mut chacha = ChaCha20::new(&ammag.into(), &CHACHA_NONCE.into());
        let mut packet_data = self.packet_data;
        chacha.apply_keystream(&mut packet_data[..]);

        Self { packet_data }
    }

    /// Encrypts or decrypts the packet data with the chacha20 stream.
    ///
    /// Apply XOR on the packet data with the keystream generated by the chacha20 stream cipher.
    pub fn xor_cipher_stream(self, shared_secret: &[u8; 32]) -> Self {
        let ammag = derive_ammag_key(shared_secret);
        self.xor_cipher_stream_with_ammag(ammag)
    }

    /// Decrypts the packet data and parses the error message.
    ///
    /// This method is for the origin node to decrypts the packet data node by node and try to parse the message.
    ///
    /// - `hops_path`: The public keys for each hop. These are _y_<sub>i</sub> in the specification.
    /// - `session_key`: The ephemeral secret key for the onion packet. It must be generated securely using a random process.
    ///   This is _x_ in the specification.
    /// - `parse_payload`: A function to parse the error payload from the decrypted packet data. It should return `Some(T)` if
    ///   the given buffer starts with a valid error payload, otherwise `None`.
    ///
    /// Returns the parsed error message and the erring node index in `hops_path` if the HMAC is valid and the error message is
    /// successfully parsed by the function `parse_payload`.
    pub fn parse<F, T>(
        self,
        hops_path: Vec<PublicKey>,
        session_key: SecretKey,
        parse_payload: F,
    ) -> Option<(T, usize)>
    where
        F: Fn(&[u8]) -> Option<T>,
    {
        // The packet must contain the HMAC so it has to be at least 32 bytes
        if self.packet_data.len() < 32 {
            return None;
        }

        let secp_ctx = Secp256k1::new();
        let mut packet = self;
        for (index, shared_secret) in
            OnionSharedSecretIter::new(hops_path.iter(), session_key, &secp_ctx).enumerate()
        {
            let ReturnKeys { ammag, um } = ReturnKeys::new(&shared_secret);
            packet = packet.xor_cipher_stream_with_ammag(ammag);
            if let Some(error) = parse_payload(&packet.packet_data[32..]) {
                if verify_hmac(
                    &um,
                    &packet.packet_data[32..],
                    None,
                    &packet.packet_data[..32],
                ) {
                    return Some((error, index));
                }
            }
        }

        None
    }

    /// Splits into HMAC and payload without decryption.
    pub fn split(self) -> ([u8; 32], Vec<u8>) {
        let mut hmac = [0u8; 32];
        if self.packet_data.len() >= 32 {
            hmac.copy_from_slice(&self.packet_data[..32]);
            let payload = self.packet_data[32..].to_vec();
            (hmac, payload)
        } else {
            hmac.copy_from_slice(&self.packet_data[..]);
            (hmac, Vec::new())
        }
    }

    /// Converts the onion packet into a byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.packet_data
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { packet_data: bytes }
    }
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum SphinxError {
    #[error("The hops path does not match the hops data length")]
    HopsLenMismatch,

    #[error("The hops path is empty")]
    HopsIsEmpty,

    #[error("The HMAC does not match the packet data and optional assoc data")]
    HmacMismatch,

    #[error("Unable to parse the data len for the current hop")]
    HopDataLenUnavailable,

    #[error("The parsed data len is larger than the onion packet len")]
    HopDataLenTooLarge,

    #[error("The parsed data len is too small")]
    PacketDataLenTooSmall,

    #[error("Invalid public key")]
    PublicKeyInvalid,
}

/// Keys used to forward the onion packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ForwardKeys {
    /// Key derived from the shared secret for the hop. It is used to encrypt the packet data.
    pub rho: [u8; 32],
    /// Key derived from the shared secret for the hop. It is used to compute the HMAC of the packet data.
    pub mu: [u8; 32],
}

impl ForwardKeys {
    /// Derive keys for forwarding the onion packet from the shared secret.
    pub fn new(shared_secret: &[u8]) -> ForwardKeys {
        ForwardKeys {
            rho: derive_key(HMAC_KEY_RHO, shared_secret),
            mu: derive_key(HMAC_KEY_MU, shared_secret),
        }
    }
}

/// Keys used to return the error packet.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReturnKeys {
    /// Key derived from the shared secret for the hop. It is used to encrypt the error packet data.
    pub ammag: [u8; 32],
    /// Key derived from the shared secret for the hop. It is used to compute the HMAC of the error packet data.
    pub um: [u8; 32],
}

impl ReturnKeys {
    /// Derive keys for returning the error onion packet from the shared secret.
    pub fn new(shared_secret: &[u8]) -> ReturnKeys {
        ReturnKeys {
            ammag: derive_ammag_key(shared_secret),
            um: derive_key(HMAC_KEY_UM, shared_secret),
        }
    }
}

#[inline]
pub fn derive_ammag_key(shared_secret: &[u8]) -> [u8; 32] {
    derive_key(HMAC_KEY_AMMAG, shared_secret)
}

/// Shared secrets generator.
///
/// ## Example
///
/// ```rust
/// use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// use fiber_sphinx::{OnionSharedSecretIter};
///
/// let secp = Secp256k1::new();
/// let hops_keys = vec![
///     SecretKey::from_slice(&[0x20; 32]).expect("32 bytes, within curve order"),
///     SecretKey::from_slice(&[0x21; 32]).expect("32 bytes, within curve order"),
///     SecretKey::from_slice(&[0x22; 32]).expect("32 bytes, within curve order"),
/// ];
/// let hops_path: Vec<_> = hops_keys.iter().map(|sk| sk.public_key(&secp)).collect();
/// let session_key = SecretKey::from_slice(&[0x41; 32]).expect("32 bytes, within curve order");
/// // Gets shared secrets for each hop
/// let hops_ss: Vec<_> = OnionSharedSecretIter::new(hops_path.iter(), session_key, &secp).collect();
/// ```
#[derive(Clone)]
pub struct OnionSharedSecretIter<'s, I, C: Signing> {
    /// A list of node public keys
    hops_path_iter: I,
    ephemeral_secret_key: SecretKey,
    secp_ctx: &'s Secp256k1<C>,
}

impl<'s, I, C: Signing> OnionSharedSecretIter<'s, I, C> {
    /// Creates an iterator to generate shared secrets for each hop.
    ///
    /// - `hops_path`: The public keys for each hop. These are _y_<sub>i</sub> in the specification.
    /// - `session_key`: The ephemeral secret key for the onion packet. It must be generated securely using a random process.
    ///   This is _x_ in the specification.
    pub fn new(hops_path_iter: I, session_key: SecretKey, secp_ctx: &'s Secp256k1<C>) -> Self {
        OnionSharedSecretIter {
            hops_path_iter,
            secp_ctx,
            ephemeral_secret_key: session_key,
        }
    }
}

impl<'s, 'i, I: Iterator<Item = &'i PublicKey>, C: Signing> Iterator
    for OnionSharedSecretIter<'s, I, C>
{
    type Item = [u8; 32];

    fn next(&mut self) -> Option<Self::Item> {
        self.hops_path_iter.next().map(|pk| {
            let shared_secret = SharedSecret::new(pk, &self.ephemeral_secret_key);

            let ephemeral_public_key = self.ephemeral_secret_key.public_key(self.secp_ctx);
            self.ephemeral_secret_key = derive_next_hop_ephemeral_secret_key(
                self.ephemeral_secret_key,
                &ephemeral_public_key,
                shared_secret.as_ref(),
            );

            shared_secret.secret_bytes()
        })
    }
}

/// Derives keys for forwarding the onion packet.
fn derive_hops_forward_keys<C: Signing>(
    hops_path: &[PublicKey],
    session_key: SecretKey,
    secp_ctx: &Secp256k1<C>,
) -> Vec<ForwardKeys> {
    OnionSharedSecretIter::new(hops_path.iter(), session_key, secp_ctx)
        .map(|shared_secret| ForwardKeys::new(&shared_secret))
        .collect()
}

#[inline]
fn shift_slice_right(arr: &mut [u8], amt: usize) {
    for i in (amt..arr.len()).rev() {
        arr[i] = arr[i - amt];
    }
    for item in arr.iter_mut().take(amt) {
        *item = 0;
    }
}

#[inline]
fn shift_slice_left(arr: &mut [u8], amt: usize) {
    let pivot = arr.len() - amt;
    for i in 0..pivot {
        arr[i] = arr[i + amt];
    }
    for item in arr.iter_mut().skip(pivot) {
        *item = 0;
    }
}

/// Computes hmac of packet_data and optional associated data using the key `hmac_key`.
fn compute_hmac(hmac_key: &[u8; 32], packet_data: &[u8], assoc_data: Option<&[u8]>) -> [u8; 32] {
    let mut hmac_engine = Hmac::<Sha256>::new_from_slice(hmac_key).expect("valid hmac key");
    hmac_engine.update(packet_data);
    if let Some(assoc_data) = assoc_data {
        hmac_engine.update(assoc_data);
    }
    hmac_engine.finalize().into_bytes().into()
}

fn verify_hmac(
    hmac_key: &[u8; 32],
    packet_data: &[u8],
    assoc_data: Option<&[u8]>,
    expected_hmac: &[u8],
) -> bool {
    let mut hmac_engine = Hmac::<Sha256>::new_from_slice(hmac_key).expect("valid hmac key");
    hmac_engine.update(packet_data);
    if let Some(assoc_data) = assoc_data {
        hmac_engine.update(assoc_data);
    }
    hmac_engine.verify_slice(expected_hmac).is_ok()
}

/// Forwards the cursor of the stream cipher by `n` bytes.
fn forward_stream_cipher<S: StreamCipher>(stream: &mut S, n: usize) {
    for _ in 0..n {
        let mut dummy = [0; 1];
        stream.apply_keystream(&mut dummy);
    }
}

/// Derives the ephemeral secret key for the next hop.
///
/// Assume that the current hop is $n_{i-1}$, and the next hop is $n_i$.
///
/// The parameters are:
///
/// - `ephemeral_secret_key`: the ephemeral secret key of the current node $n_{i-1}$,
///   which is x times the blinding factors so far: $x b_0 b_1 \cdots b_{i-2}$
/// - `ephemeral_public_key`: the corresponding public key of `ephemeral_secret_key`.
///   This is the _alpha_ in the specification.
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
        sha.update(shared_secret);
        sha.finalize().into()
    };

    ephemeral_secret_key
        .mul_tweak(&Scalar::from_be_bytes(blinding_factor).expect("valid scalar"))
        .expect("valid mul tweak")
}

/// Derives the ephemeral public key for the next hop.
///
/// This is the _alpha_ in the specification.
fn derive_next_hop_ephemeral_public_key<C: Verification>(
    ephemeral_public_key: PublicKey,
    shared_secret: &[u8],
    secp_ctx: &Secp256k1<C>,
) -> PublicKey {
    let blinding_factor: [u8; 32] = {
        let mut sha = Sha256::new();
        sha.update(&ephemeral_public_key.serialize()[..]);
        sha.update(shared_secret.as_ref());
        sha.finalize().into()
    };

    ephemeral_public_key
        .mul_tweak(
            secp_ctx,
            &Scalar::from_be_bytes(blinding_factor).expect("valid scalar"),
        )
        .expect("valid mul tweak")
}

/// Derives a key from the shared secret using HMAC.
fn derive_key(hmac_key: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("valid hmac key");
    mac.update(shared_secret);
    mac.finalize().into_bytes().into()
}

/// Generates the initial bytes of onion packet padding data from PRG.
///
/// Uses Chacha as the PRG. The key is derived from the session key using HMAC, and the nonce is all zeros.
fn generate_padding_data(packet_data_len: usize, pad_key: &[u8]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(pad_key.into(), &CHACHA_NONCE.into());
    let mut buffer = vec![0u8; packet_data_len];
    cipher.apply_keystream(&mut buffer);
    buffer
}

/// Generates the filler to obfuscate the onion packet.
fn generate_filler(
    packet_data_len: usize,
    hops_keys: &[ForwardKeys],
    hops_data: &[Vec<u8>],
) -> Result<Vec<u8>, SphinxError> {
    let mut filler = Vec::new();
    let mut pos = 0;

    for (i, (data, keys)) in hops_data.iter().zip(hops_keys.iter()).enumerate() {
        let mut chacha = ChaCha20::new(&keys.rho.into(), &[0u8; 12].into());
        forward_stream_cipher(&mut chacha, packet_data_len - pos);

        // 32 for mac
        pos += data.len() + 32;
        if pos > packet_data_len {
            return Err(SphinxError::HopDataLenTooLarge);
        }

        if i == hops_data.len() - 1 {
            break;
        }

        filler.resize(pos, 0u8);
        chacha.apply_keystream(&mut filler);
    }

    Ok(filler)
}

/// Constructs the onion packet internally.
///
/// - `packet_data`: The initial 1300 bytes of the onion packet generated by `generate_padding_data`.
/// - `public_key`: The ephemeral public key for the first hop.
/// - `hops_keys`: The keys for each hop generated by `derive_hops_forward_keys`.
/// - `hops_data`: The unencrypted data for each hop.
/// - `assoc_data`: The associated data. It will not be included in the packet itself but will be covered by the packet's
///   HMAC. This allows each hop to verify that the associated data has not been tampered with.
/// - `filler`: The filler to obfuscate the packet data, which is generated by `generate_filler`.
fn construct_onion_packet(
    mut packet_data: Vec<u8>,
    public_key: PublicKey,
    hops_keys: &[ForwardKeys],
    hops_data: &[Vec<u8>],
    assoc_data: Option<Vec<u8>>,
    filler: Vec<u8>,
) -> Result<OnionPacket, SphinxError> {
    let mut hmac = [0; 32];

    for (i, (data, keys)) in hops_data.iter().zip(hops_keys.iter()).rev().enumerate() {
        let data_len = data.len();
        shift_slice_right(&mut packet_data, data_len + 32);
        packet_data[0..data_len].copy_from_slice(data);
        packet_data[data_len..(data_len + 32)].copy_from_slice(&hmac);

        let mut chacha = ChaCha20::new(&keys.rho.into(), &[0u8; 12].into());
        chacha.apply_keystream(&mut packet_data);

        if i == 0 {
            let stop_index = packet_data.len();
            let start_index = stop_index
                .checked_sub(filler.len())
                .ok_or(SphinxError::HopDataLenTooLarge)?;
            packet_data[start_index..stop_index].copy_from_slice(&filler[..]);
        }

        hmac = compute_hmac(&keys.mu, &packet_data, assoc_data.as_deref());
    }

    Ok(OnionPacket {
        version: 0,
        public_key,
        packet_data,
        hmac,
    })
}

#[cfg(test)]
mod tests;
