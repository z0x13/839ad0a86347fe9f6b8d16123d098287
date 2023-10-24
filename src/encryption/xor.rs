use owo_colors::{OwoColorize, Stream::Stdout};
use rand::random;
use std::{collections::HashMap, path::Path};

use crate::{utils::meta_vec_from_file, utils::write_to_file};

fn xor_encrypt(shellcode: &[u8], key: u8) -> Vec<u8> {
    shellcode.iter().map(|x| x ^ key).collect()
}
pub fn meta_xor(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let key: u8 = random();
    println!(
        "{} {} encrypting shellcode with {} 0x{:02x}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "XOR".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        key
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = xor_encrypt(&unencrypted, key);
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

    let decryption_function = "fn xor_decrypt(buf: &Vec<u8>, key: u8) -> Vec<u8> {
        buf.iter().map(|x| x ^ key).collect()
    }"
    .to_string();

    let main = format!("vec = xor_decrypt(&vec, {});", key);

    result.insert(String::from("decryption_function"), decryption_function);
    result.insert(String::from("main"), main);
    result.insert(String::from("dependencies"), "".to_string());
    result.insert(String::from("imports"), "".to_string());

    println!(
        "{} Done encrypting shellcode!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
