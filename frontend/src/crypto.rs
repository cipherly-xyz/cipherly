use ::kem::Decapsulate;
use ::kem::Encapsulate;
use argon2::{Algorithm, Argon2, Version};
use ml_kem::*;
use ml_kem::{KemCore, B32};
use rand::Rng;
use sha3::Digest;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};

// re-export for convenience
pub use ml_kem::MlKem1024;

pub fn key_derivation(password: &str, username: &str) -> [u8; 64] {
    let mut output_key_material = [0u8; 64];
    let salt = format!("cipherly{username}");

    // https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    // recommendation 2: 3 iterations, 4 lanes,64MiB RAM
    let mut params_builder = argon2::ParamsBuilder::DEFAULT;
    let params = params_builder
        .t_cost(3)
        .p_cost(4)
        .m_cost(65536)
        .build()
        .unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(
            password.as_bytes(),
            salt.as_bytes(),
            &mut output_key_material,
        )
        .unwrap();

    output_key_material
}

pub fn generate_keys<K: KemCore>(
    input: &str,
    username: &str,
) -> (K::DecapsulationKey, K::EncapsulationKey) {
    let key_input = key_derivation(input, username);

    let d = B32::from_slice(&key_input[..32]);
    let z = B32::from_slice(&key_input[32..]);

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
    pub nonce: Vec<u8>,
}
pub fn encrypt(encapsulation_key: &[u8], plaintext: &str) -> anyhow::Result<EncryptionResult> {
    let ek = ek_from_bytes::<MlKem1024>(encapsulation_key);

    let (encapsulated_sym_key, sym_key) = ek_shared_secret::<MlKem1024>(&ek);

    let nonce = rand::thread_rng().gen::<[u8; 12]>();
    let ciphertext = aes_enc(plaintext.as_bytes(), &sym_key, &nonce)?;

    Ok(EncryptionResult {
        ciphertext,
        encapsulated_sym_key,
        nonce: nonce.to_vec(),
    })
}

pub fn decrypt<K: KemCore>(
    password: &str,
    username: &str,
    ciphertext: &[u8],
    encapsulated_sym_key: &[u8],
    nonce: &[u8],
) -> anyhow::Result<String> {
    let encapsulated_secret = Ciphertext::<K>::from_slice(encapsulated_sym_key);

    let (dk, _) = generate_keys::<K>(password, username);

    let sym_key = dk
        .decapsulate(encapsulated_secret)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate symetric key: {:?}", e))?;

    let plaintext = aes_dec(ciphertext, &sym_key, nonce)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt ciphertext: {:?}", e))?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!(e))
}

pub fn aes_enc(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)?;
    let nonce = Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to aes encrypt: {:?}", e))?;

    Ok(ciphertext)
}

pub fn aes_dec(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key)?;
    let nonce = Nonce::from_slice(nonce);
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
        let username = "username";
        let plaintext = "plaintext";

        let (_, encapsulaton_key) = generate_keys::<MlKem1024>(password, username);

        let EncryptionResult {
            ciphertext,
            encapsulated_sym_key,
            nonce,
        } = encrypt(&encapsulaton_key.as_bytes(), plaintext).unwrap();

        let decrypted = decrypt::<MlKem1024>(
            password,
            username,
            &ciphertext,
            &encapsulated_sym_key,
            &nonce,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_plus_kyber() {
        let mut rng = rand::thread_rng();

        let password = "qqq";
        let username = "username";

        let plaintext = b"some plaintext message";

        let (_dk, ek) = generate_keys::<MlKem1024>(password, username);

        let (_, k_send) = ek.encapsulate(&mut rng).unwrap();

        let nonce = b"unique nonce";
        let ciphertext = aes_enc(plaintext, &k_send, nonce).unwrap();

        let dec_plaintext = aes_dec(&ciphertext, &k_send, nonce).unwrap();

        assert_eq!(dec_plaintext, plaintext);
    }

    #[test]
    fn ml_kem_keygen() {
        let mut rng = rand::thread_rng();

        let password = "qqq";
        let username = "username";

        let (_, ek) = generate_keys::<MlKem1024>(password, username);
        let (dk, _) = generate_keys::<MlKem1024>(password, username);

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
        let username = "username";

        let (_, ek) = generate_keys::<MlKem1024>(password, username);
        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();

        let nonce = b"unique nonce";
        let aes_cipher = aes_enc(b"plaintext", &k_send, nonce).unwrap();

        let k_recv = decrypt::<MlKem1024>(password, username, &aes_cipher, &ct, nonce).unwrap();

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

    #[test]
    /// This test detects breaking changes in the key derivation function
    fn key_derivation_test() {
        let password = "somepassword";
        let username = "someusername";
        let key = key_derivation(password, username);

        let expected = [
            104, 143, 235, 85, 194, 150, 234, 118, 119, 198, 229, 81, 32, 139, 81, 195, 223, 182,
            67, 195, 178, 197, 204, 63, 29, 30, 225, 174, 246, 203, 145, 116, 190, 26, 9, 156, 205,
            158, 74, 145, 185, 247, 91, 211, 32, 114, 46, 235, 50, 107, 117, 101, 134, 254, 21, 5,
            125, 122, 211, 124, 116, 114, 240, 111,
        ];
        assert_eq!(key, expected);
    }
}
