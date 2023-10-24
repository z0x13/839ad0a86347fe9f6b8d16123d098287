use owo_colors::{OwoColorize, Stream::Stdout};
use std::{collections::HashMap, path::Path};

use crate::utils::{meta_vec_from_file, random_vec, write_to_file};

fn smart_xor_encrypt(shellcode: &[u8], key: &Vec<u8>) -> Vec<u8> {
    std::iter::zip(shellcode, key).map(|x| x.0 ^ x.1).collect()
}
pub fn meta_smart_xor(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let unencrypted = meta_vec_from_file(input_path);
    let shellcode_len: usize = unencrypted.len();
    let key = random_vec(shellcode_len);
    println!(
        "{} {} encrypting shellcode with {} {:?}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "Smart XOR".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        key
    );
    let encrypted_content = smart_xor_encrypt(&unencrypted, &key);
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let decryption_function = "fn smart_xor_decrypt(encrypted: &[u8], key: &Vec<u8>) -> Vec<u8> {
    std::iter::zip(encrypted, key).map(|x| x.0 ^ x.1).collect()
}"
    .to_string();
    let main = format!(
        "let key: Vec<u8> = Vec::from({:?});
    vec = smart_xor_decrypt(&vec, &key);",
        key
    );
    let dependencies = "".to_string();
    let imports = "".to_string();
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
