use ::kem::Decapsulate;
use ::kem::Encapsulate;
use ml_kem::*;
use ml_kem::{KemCore, B32};
use sha3::Digest;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

// re-export for convenience
pub use ml_kem::MlKem1024;

pub fn generate_keys<K: KemCore>(input: &str) -> (K::DecapsulationKey, K::EncapsulationKey) {
    // TODO: replace with proper key derivation function
    let input = input.as_bytes();
    assert!(input.len() <= 32);
    let mut full_input = [0_u8; 32];
    input.iter().enumerate().for_each(|(i, b)| {
        full_input[i] = *b;
    });

    //let d = B32::from_slice(&[0_u8; 32]);
    //let z = B32::from_slice(&[0_u8; 32]);

    let d = B32::from_slice(&full_input);
    let z = B32::from_slice(&full_input);

    let (dk, ek) = K::generate_deterministic(d, z);

    (dk, ek)
}

pub fn ek_from_bytes<K: KemCore>(input: &[u8]) -> K::EncapsulationKey {
    let ek = Encoded::<K::EncapsulationKey>::from_slice(input);
    K::EncapsulationKey::from_bytes(ek)
}

pub fn ek_shared_secret<K: KemCore>(ek: &K::EncapsulationKey) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let (c, k) = ek.encapsulate(&mut rng).unwrap();

    (c.to_vec(), k.to_vec())
}

pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub encapsulated_sym_key: Vec<u8>,
}
pub fn encrypt(encapsulation_key: &[u8], plaintext: &str) -> anyhow::Result<EncryptionResult> {
    let ek = ek_from_bytes::<MlKem1024>(encapsulation_key);

    let (encapsulated_sym_key, sym_key) = ek_shared_secret::<MlKem1024>(&ek);

    let ciphertext = aes_enc(plaintext.as_bytes(), &sym_key)?;

    Ok(EncryptionResult {
        ciphertext,
        encapsulated_sym_key,
    })
}

pub fn decrypt<K: KemCore>(
    password: &str,
    ciphertext: &[u8],
    encapsulated_sym_key: &[u8],
) -> anyhow::Result<String> {
    let encapsulated_secret = Ciphertext::<K>::from_slice(encapsulated_sym_key);

    let (dk, _) = generate_keys::<K>(password);

    let sym_key = dk
        .decapsulate(encapsulated_secret)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate symetric key: {:?}", e))?;

    let plaintext = aes_dec(ciphertext, &sym_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt ciphertext: {:?}", e))?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!(e))
}

pub fn aes_enc(plaintext: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)?;
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to aes encrypt: {:?}", e))?;

    Ok(ciphertext)
}

pub fn aes_dec(ciphertext: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)?;
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to aes decrypt: {:?}", e))?;

    Ok(ciphertext)
}

pub fn encapsulation_key_fingerprint(encapsulation_key: &[u8]) -> String {
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(encapsulation_key);
    format!("{:X}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm_siv::aead::OsRng;

    #[test]
    fn encrypt_decrypt_test() {
        let password = "somepassword";
        let plaintext = "plaintext";

        let (_, encapsulaton_key) = generate_keys::<MlKem1024>(password);

        let EncryptionResult {
            ciphertext,
            encapsulated_sym_key,
        } = encrypt(&encapsulaton_key.as_bytes(), plaintext).unwrap();

        let decrypted = decrypt::<MlKem1024>(password, &ciphertext, &encapsulated_sym_key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_plus_kyber() {
        let mut rng = rand::thread_rng();

        let password = "qqq";
        let plaintext = b"some plaintext message";

        let (_dk, ek) = generate_keys::<MlKem1024>(password);

        let (_, k_send) = ek.encapsulate(&mut rng).unwrap();

        let ciphertext = aes_enc(plaintext, &k_send).unwrap();

        let dec_plaintext = aes_dec(&ciphertext, &k_send).unwrap();

        assert_eq!(dec_plaintext, plaintext);
    }

    #[test]
    fn ml_kem_keygen() {
        let mut rng = rand::thread_rng();

        let password = "qqq";

        let (_, ek) = generate_keys::<MlKem1024>(password);
        let (dk, _) = generate_keys::<MlKem1024>(password);

        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        let k_recv = dk.decapsulate(&ct).unwrap();

        println!("{:?}", k_send);
        println!("{:?}", k_recv);
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn test_decrypt() {
        let mut rng = rand::thread_rng();

        let password = "qqq";

        let (_, ek) = generate_keys::<MlKem1024>(password);
        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        let aes_cipher = aes_enc(b"plaintext", &k_send).unwrap();

        let k_recv = decrypt::<MlKem1024>(password, &aes_cipher, &ct).unwrap();

        assert_eq!(k_recv, "plaintext")
    }

    #[test]
    fn aestest() {
        let plaintext = b"plaintext message";
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("failed to encrypt");

        println!("ciphertext: {ciphertext:?}");
        println!("cipher len: {}", ciphertext.len());
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("failed to decrypt");
        assert_eq!(&plaintext, &plaintext);
    }
}
