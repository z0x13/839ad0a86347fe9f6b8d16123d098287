use base64::{engine::general_purpose, Engine as _};
use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashMap;
use std::path::Path;

use crate::{utils::meta_vec_from_file, utils::write_to_file};

fn base64_encode(unencrypted: &Vec<u8>) -> String {
    general_purpose::STANDARD.encode(unencrypted)
}
pub fn meta_base64(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    println!(
        "{} {} obfuscating shellcode ..",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "Base64".if_supports_color(Stdout, |text| text.yellow())
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = base64_encode(&unencrypted);
    match write_to_file(encrypted_content.as_bytes(), export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let deobfuscation_function = "fn base64_decode(encrypted: &Vec<u8>) -> Vec<u8> {
    general_purpose::STANDARD.decode(&encrypted).unwrap()
}"
    .to_string();
    let main = r#"vec = base64_decode(&vec);"#.to_string();
    let dependencies = r#"base64 = "0.21.3""#.to_string();
    let imports = "
    use base64::{engine::general_purpose, Engine as _};
    "
    .to_string();

    result.insert(String::from("dependencies"), dependencies);
    result.insert(String::from("imports"), imports);
    result.insert(
        String::from("deobfuscation_function"),
        deobfuscation_function,
    );
    result.insert(String::from("main"), main);

    println!(
        "{} Done obfuscating shellcode!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
