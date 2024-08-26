use secp256k1::{PublicKey, SecretKey};

pub struct OnionPacket;
pub struct Error;

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
}
