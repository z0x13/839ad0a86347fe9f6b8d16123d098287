use libaes::Cipher;
use owo_colors::{OwoColorize, Stream::Stdout};
use std::{collections::HashMap, path::Path};

use crate::utils::{meta_vec_from_file, random_vec, write_to_file};

fn aes_256_encrypt(shellcode: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let cipher = Cipher::new_256(key);
    cipher.cbc_encrypt(iv, shellcode)
}
pub fn meta_aes(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let key = random_vec(32);
    let iv = random_vec(16);
    println!(
        "{} {} encrypting shellcode with {} {:?} and {} {:?}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "AES".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        &key,
        "IV".if_supports_color(Stdout, |text| text.yellow()),
        &iv
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = aes_256_encrypt(
        &unencrypted,
        <&[u8; 32]>::try_from(&key[..32]).unwrap(),
        <&[u8; 16]>::try_from(&iv[..16]).unwrap(),
    );
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let decryption_function =
        "fn aes_256_decrypt(buf: &Vec<u8>, key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
        let cipher = Cipher::new_256(key);
        let decrypted = cipher.cbc_decrypt(iv, &buf);
        decrypted
    }"
        .to_string();
    let main = format!(
        "let key: [u8; 32] = {:?};
    let iv: [u8; 16] = {:?};
    vec = aes_256_decrypt(&vec, &key, &iv);
    ",
        key, iv
    );
    let dependencies = r#"libaes = "0.7.0""#.to_string();
    let imports = "
    use libaes::Cipher;
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
