use anyhow::{anyhow, Context};
use pgp::{
    composed::{Deserializable, Message, SignedPublicKey},
    crypto::sym::SymmetricKeyAlgorithm,
    ArmorOptions,
};
use rand::thread_rng;
use std::io::Cursor;

pub fn encrypt_message(plaintext: &str, public_key_armor: &str) -> anyhow::Result<String> {
    let (pubkey, _) = SignedPublicKey::from_string(public_key_armor)
        .map_err(|e| anyhow!("Failed to parse public key: {e}"))?;

    let msg = Message::new_literal("message.txt", plaintext);

    let rng = thread_rng();
    let encrypted = msg
        .encrypt_to_keys_seipdv1(rng, SymmetricKeyAlgorithm::AES256, &[&pubkey])
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut buf = Vec::new();
    encrypted
        .to_armored_writer(&mut buf, ArmorOptions::default())
        .map_err(|e| anyhow!("Armoring failed: {e}"))?;

    String::from_utf8(buf).context("Armored output is not valid UTF-8")
}

#[allow(dead_code)]
pub fn decrypt_message(
    ciphertext: &str,
    private_key_armor: &str,
    passphrase: &str,
) -> anyhow::Result<String> {
    use pgp::composed::SignedSecretKey;

    let (seckey, _) = SignedSecretKey::from_string(private_key_armor)
        .map_err(|e| anyhow!("Failed to parse private key: {e}"))?;

    let pp = passphrase.to_string();
    let cursor = Cursor::new(ciphertext.as_bytes());
    let (msg, _) =
        Message::from_armor_single(cursor).map_err(|e| anyhow!("Failed to parse message: {e}"))?;

    let (decrypted, _key_ids) = msg
        .decrypt(|| pp.clone(), &[&seckey])
        .map_err(|e| anyhow!("Decryption failed: {e}"))?;

    let content = decrypted
        .get_content()
        .map_err(|e| anyhow!("Failed to get content: {e}"))?
        .ok_or_else(|| anyhow!("No content in decrypted message"))?;

    String::from_utf8(content).context("Decrypted content is not valid UTF-8")
}
