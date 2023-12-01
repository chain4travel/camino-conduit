use avalanche_types::{formatting, hash, key};

/// An error encountered when trying to parse an invalid ID string.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to decode hex signature.
    #[error("failed to decode hex signature")]
    DecodeSignatureError,

    /// Failed to recover public key from signature.
    #[error("failed to recover public key from signature")]
    PublicKeyError,

    /// Failed to produce address from public key
    #[error("failed to produce address from public key")]
    FormatAddressError,
}

pub fn recover_address(payload: &str, signature: &str, network_id: u32) -> Result<String, Error> {
    let decoded_signature = formatting::decode_hex_with_checksum(signature.as_bytes())
        .map_err(|_| Error::DecodeSignatureError)?;

    let public_key =
        key::secp256k1::public_key::Key::from_signature(&hash::sha256(payload), &decoded_signature)
            .map_err(|_| Error::PublicKeyError)?;

    public_key
        .to_hrp_address(network_id, "T")
        .map_err(|_| Error::FormatAddressError)
}
