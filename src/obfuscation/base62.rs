use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashMap;
use std::path::Path;

use crate::{utils::meta_vec_from_file, utils::write_to_file};

fn base62_encode(unencrypted: &[u8]) -> String {
    bs62::encode_data(unencrypted)
}
pub fn meta_base62(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    println!(
        "{} {} obfuscating shellcode ..",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "Base62".if_supports_color(Stdout, |text| text.yellow())
    );
    let unencrypted = meta_vec_from_file(input_path);
    let encrypted_content = base62_encode(&unencrypted);
    match write_to_file(encrypted_content.as_bytes(), export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }
    let mut result: HashMap<String, String> = HashMap::new();
    let deobfuscation_function = "fn base62_decode(encrypted: &Vec<u8>) -> Vec<u8> {
    bs62::decode_data(std::str::from_utf8(encrypted).unwrap()).unwrap()
}"
    .to_string();
    let main = r#"vec = base62_decode(&vec);"#.to_string();
    let dependencies = r#"bs62 = "0.1.4""#.to_string();
    let imports = "".to_string();

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
