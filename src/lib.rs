use std::num::ParseIntError;

use crypto::{
    aessafe::{AesSafe128Decryptor, AesSafe128Encryptor},
    symmetriccipher::{BlockDecryptor, BlockEncryptor},
};

const AES_BLOCK_SIZE: usize = 16;

pub fn aes_128_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let ptext_bytes = pkcs5_pad(plaintext);
    let mut prev_block = iv.to_vec();
    let mut ciphertext = vec![];

    let cipher = AesSafe128Encryptor::new(key);
    let mut encrypted_block = [0; AES_BLOCK_SIZE];
    for block in ptext_bytes.chunks_exact(AES_BLOCK_SIZE) {
        cipher.encrypt_block(&xor(&prev_block, block), &mut encrypted_block);
        ciphertext.extend_from_slice(&mut encrypted_block);
        prev_block = encrypted_block.to_vec();
    }
    let mut ciphertext_with_iv = iv.to_vec();
    ciphertext_with_iv.extend_from_slice(&ciphertext);
    ciphertext_with_iv
}

pub fn aes_128_cbc_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = AesSafe128Decryptor::new(key);

    let iv = &ciphertext[0..AES_BLOCK_SIZE];
    let mut prev_block = iv.to_vec();
    let mut plaintext = vec![];

    let mut decrypted_block = [0; AES_BLOCK_SIZE];
    for block in ciphertext[AES_BLOCK_SIZE..].chunks(AES_BLOCK_SIZE) {
        cipher.decrypt_block(&block, &mut decrypted_block);
        plaintext.extend_from_slice(&mut xor(&prev_block, &mut decrypted_block));
        prev_block = block.to_vec();
    }
    remove_pkcs5_padding(&plaintext)
}

pub fn aes_128_ctr_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = AesSafe128Encryptor::new(key);

    let mut buffer = vec![];
    let mut counter = iv.to_vec();
    for block in plaintext.chunks(AES_BLOCK_SIZE) {
        let mut encrypted_block = [0; AES_BLOCK_SIZE];
        cipher.encrypt_block(&counter, &mut encrypted_block);
        buffer.extend_from_slice(&xor(block, &encrypted_block));

        increment_counter(&mut counter);
    }
    let mut ciphertext = iv.to_vec();
    ciphertext.append(&mut buffer);
    ciphertext
}

pub fn aes_128_ctr_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = AesSafe128Encryptor::new(key);

    let mut plaintext = vec![];
    let mut counter = (&ciphertext[0..AES_BLOCK_SIZE]).to_vec();
    let mut encrypted_block = [0; AES_BLOCK_SIZE];

    for block in ciphertext[AES_BLOCK_SIZE..].chunks(AES_BLOCK_SIZE) {
        cipher.encrypt_block(&counter, &mut encrypted_block);
        plaintext.extend_from_slice(&xor(block, &encrypted_block));

        increment_counter(&mut counter);
    }
    plaintext
}

fn increment_counter(counter: &mut [u8]) {
    let mut carry = true;
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            carry = false;
            break;
        }
    }
    if carry {
        panic!("Counter overflow");
    }
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(&x, &y)| x ^ y).collect()
}

pub fn encode_hex(vec: Vec<u8>) -> String {
    vec.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join("")
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn pkcs5_pad(txt: &[u8]) -> Vec<u8> {
    let mut res = txt.to_vec();
    let pad_len = AES_BLOCK_SIZE - (txt.len() % AES_BLOCK_SIZE);
    for _ in 1..=pad_len {
        res.push(pad_len as u8)
    }
    res
}

fn remove_pkcs5_padding(bytes: &[u8]) -> Vec<u8> {
    if let Some(pad_len) = bytes.last() {
        if let Ok(len) = usize::try_from(*pad_len) {
            return bytes[..(bytes.len().wrapping_sub(len))].to_vec();
        }
    }
    bytes.to_vec()
}
