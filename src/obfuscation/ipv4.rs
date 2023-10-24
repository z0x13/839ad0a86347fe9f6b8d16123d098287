use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashMap;
use std::path::Path;

use crate::utils::{meta_vec_from_file, write_to_file};

fn ipv4_obfuscate(shellcode: &[u8]) -> String {
    let mut obfuscated: Vec<String> = Vec::new();
    let mut temp: String = String::new();
    for (i, byte) in shellcode.iter().enumerate() {
        if i != 0 && i % 4 == 0 {
            obfuscated.push(temp.clone());
            temp.clear();
        } else if i != 0 {
            temp += ".";
        }
        temp = format!("{}{}", temp, byte);
    }
    obfuscated.push(temp);
    obfuscated.join(", ")
}
pub fn meta_ipv4(input_path: &Path, export_path: &Path) -> HashMap<String, String> {
    println!(
        "{} {} obfuscating shellcode ..",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "Ipv4".if_supports_color(Stdout, |text| text.yellow())
    );
    let plain = meta_vec_from_file(input_path);
    let obfuscated_content = ipv4_obfuscate(&plain);
    match write_to_file(obfuscated_content.as_bytes(), export_path) {
        Ok(()) => (),
        Err(err) => panic!("{:?}", err),
    }

    let mut result: HashMap<String, String> = HashMap::new();

    let deobfuscation_function = "fn ipv4_deobfuscate(obfuscated: &Vec<u8>) -> Vec<u8> {
        let obfuscated_string = std::str::from_utf8(obfuscated).unwrap();
        let mut deobfuscated: Vec<u8> = Vec::new();
        for s in obfuscated_string.split(\", \") {
            for value in s.split(\".\") {
                deobfuscated.push(value.parse().unwrap());
            }
        }
        deobfuscated
    }"
    .to_string();

    let main = r#"vec = ipv4_deobfuscate(&vec);"#.to_string();

    result.insert(String::from("dependencies"), "".to_string());
    result.insert(String::from("imports"), "".to_string());
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
