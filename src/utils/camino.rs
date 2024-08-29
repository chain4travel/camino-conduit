use avalanche_types::{formatting, hash, key};

/// An error encountered when trying to parse an invalid ID string.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to verify signature.
    #[error("failed to verify signature")]
    VerifySignatureError,

    /// Signature doesn't match public key.
    #[error("signature doesn't match public key")]
    SignatureMismatchError,

    // /// Signature is no longer valid.
    // #[error("signature is expired")]
    // SignatureExpiredError,
    /// Failed to decode hex public key.
    #[error("failed to decode hex public key")]
    DecodeKeyError,

    /// Failed to decode hex signature.
    #[error("failed to decode hex signature")]
    DecodeSignatureError,

    /// Failed to parse public key.
    #[error("failed to parse public key")]
    PublicKeyError,

    /// Signature is no longer valid
    #[error("identifier or required part of it is empty")]
    FormatAddressError,
}

// TODO @evlekht wrap low level errors and pass them up
pub fn verify_signature(message: &str, signature: &str, network_id: u32) -> Result<String, Error> {
    let decoded_message: Vec<u8> = formatting::decode_hex_with_checksum(message.as_bytes())
        .map_err(|_| Error::DecodeKeyError)?;
    let public_key = key::secp256k1::public_key::Key::from_sec1_bytes(&decoded_message)
        .map_err(|_| Error::PublicKeyError)?;

    let decoded_signature = formatting::decode_hex_with_checksum(signature.as_bytes())
        .map_err(|_| Error::DecodeSignatureError)?;
    // TODO@ parse timestamp at the beginning of message, verify it with time.Now()

    let result = public_key
        .verify(&hash::sha256(decoded_message), &decoded_signature)
        .map_err(|_| Error::VerifySignatureError)?;
    if !result {
        return Err(Error::SignatureMismatchError);
    }

    Ok(public_key.to_eth_address())

    // public_key
    //     .to_hrp_address(network_id, "T")
    //     .map_err(|_| Error::FormatAddressError)
}
