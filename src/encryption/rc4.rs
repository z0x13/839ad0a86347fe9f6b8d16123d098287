use owo_colors::{OwoColorize, Stream::Stdout};
use rc4::{KeyInit, Rc4, StreamCipher};
use std::{collections::HashMap, path::Path};

use crate::utils::{meta_vec_from_file, random_vec, write_to_file};

fn rc4_encrypt(shellcode: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::from(shellcode);
    let mut rc4 = Rc4::new(key.into());
    rc4.apply_keystream(&mut data);
    data
}
pub fn meta_rc4(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    let key = random_vec(32);
    println!(
        "{} {} encrypting shellcode with {} {:?}",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "RC4".if_supports_color(Stdout, |text| text.yellow()),
        "key".if_supports_color(Stdout, |text| text.yellow()),
        key
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = rc4_encrypt(&unencrypted, <&[u8; 32]>::try_from(&key[..32]).unwrap());
    match write_to_file(&encrypted_content, export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let decryption_function = "fn rc4_decrypt(encrypted: &Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
    let mut data = encrypted.clone();
    let mut rc4 = Rc4::new(key.into());
    rc4.apply_keystream(&mut data);
    data
}"
    .to_string();
    let main = format!(
        "let key: [u8; 32] = {:?};
    vec = rc4_decrypt(&vec, &key);
    ",
        key
    );
    let dependencies = r#"rc4 = "0.1.0""#.to_string();
    let imports = "
    use rc4::{KeyInit, StreamCipher, Rc4};
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
