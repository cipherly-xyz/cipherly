use aes_gcm_siv::aead::generic_array::sequence::GenericSequence;

use ml_kem::{EncapsulateDeterministic, Encoded, KemCore, MlKem768, B32};
pub use ml_kem::kem::EncapsulationKey;
use ml_kem::*;
use ::kem::Decapsulate;
use ::kem::Encapsulate;

use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce // Or `Aes128GcmSiv`
};
use rand::Error;

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

#[derive(Debug)]
pub enum Errors {
    AesKeyInvalidLength,
}

pub fn aes_enc(plaintext: &[u8], key: &[u8]) ->  Result<Vec<u8>, Errors> {
    
    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| Errors::AesKeyInvalidLength)?;
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("failed to encrypt");
    
    return Ok(ciphertext)
}

pub fn aes_dec(ciphertext: &[u8], key: &[u8]) ->  Result<Vec<u8>, Errors> {
    
    let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|_| Errors::AesKeyInvalidLength)?;
    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("failed to encrypt");
    
    return Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_plus_kyber() {
        let mut rng = rand::thread_rng();
        
        let password = "qqq";
        let plaintext = b"some plaintext message";
        
        let (dk, ek) = generate_keys::<MlKem1024>(password);
        
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
    fn aestest() {
        
        let plaintext = b"plaintext message";
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("failed to encrypt");
        
        println!("ciphertext: {ciphertext:?}");
        println!("cipher len: {}", ciphertext.len());
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("failed to decrypt");
        assert_eq!(&plaintext, &plaintext);
    }
}
