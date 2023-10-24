use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use owo_colors::{OwoColorize, Stream::Stdout};
use std::{collections::HashMap, path::Path};

use crate::utils::{meta_vec_from_file, random_vec, write_to_file};

fn chacha20_encrypt(shellcode: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.encrypt(<&Nonce>::from(nonce), shellcode).unwrap()
}
pub fn meta_chacha20(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let key = random_vec(32);
    let nonce = random_vec(12);
    println!(
        "{} {} encrypting shellcode with {} {:?} and {} {:?}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "ChaCha20".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        key,
        "nonce".if_supports_color(Stdout, |text| text.yellow()),
        nonce
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = chacha20_encrypt(
        &unencrypted,
        <&[u8; 32]>::try_from(&key[..32]).unwrap(),
        <&[u8; 12]>::try_from(&nonce[..12]).unwrap(),
    );
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let decryption_function =
        "fn chacha20_decrypt(encrypted: &Vec<u8>, key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.decrypt(<&Nonce>::from(nonce), encrypted.as_ref()).unwrap()
}"
        .to_string();
    let main = format!(
        "let key: [u8; 32] = {:?};
    let nonce: [u8; 12] = {:?};
    vec = chacha20_decrypt(&vec, &key, &nonce);
    ",
        key, nonce
    );
    let dependencies = r#"chacha20poly1305 = "0.10.1""#.to_string();
    let imports = "
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    "
    .to_string();
    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);
    result.insert(String::from("dependencies"), dependencies);
    result.insert(String::from("imports"), imports);
    println!(
        "{} Done encrypting shellcode!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
