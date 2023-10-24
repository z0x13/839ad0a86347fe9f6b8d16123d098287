use std::collections::HashMap;
use std::path::PathBuf;

use crate::obfuscation::base32::meta_base32;
use crate::obfuscation::base45::meta_base45;
use crate::obfuscation::base58::meta_base58;
use crate::obfuscation::base62::meta_base62;
use crate::obfuscation::base64::meta_base64;
use crate::obfuscation::base85::meta_base85;
use crate::obfuscation::ipv4::meta_ipv4;
use crate::obfuscation::ipv6::meta_ipv6;
use crate::obfuscation::mac_addr::meta_mac_addr;
use crate::template::{Obfuscation, Template};
use crate::utils::{absolute_path, path_to_string};

pub(crate) mod base32;
pub(crate) mod base45;
pub(crate) mod base58;
pub(crate) mod base62;
pub(crate) mod base64;
pub(crate) mod base85;
pub(crate) mod ipv4;
pub(crate) mod ipv6;
pub(crate) mod mac_addr;

impl Template {
    pub(crate) fn obfuscate(&self, to_main: PathBuf) -> HashMap<&str, String> {
        let mut encrypted_path: PathBuf = to_main.clone();
        encrypted_path.pop();
        encrypted_path.push("shellcode.enc");

        let mut path_to_obfuscated = to_main.clone();
        path_to_obfuscated.pop();
        path_to_obfuscated.push("shellcode.result");
        let absolute_path_to_obfuscated = match absolute_path(&path_to_obfuscated) {
            Ok(path) => path,
            Err(err) => panic!("{:?}", err),
        };
        let absolute_path_to_obfuscated_as_string = path_to_string(&absolute_path_to_obfuscated);
        let obfuscated_path = absolute_path_to_obfuscated.clone();

        let args: HashMap<String, String> = match self.obfuscation {
            Some(Obfuscation::Ipv4) => meta_ipv4(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Ipv6) => meta_ipv6(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::MacAddr) => meta_mac_addr(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base32) => meta_base32(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base45) => meta_base45(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base58) => meta_base58(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base62) => meta_base62(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base64) => meta_base64(&encrypted_path, &obfuscated_path),
            Some(Obfuscation::Base85) => meta_base85(&encrypted_path, &obfuscated_path),
            None => {
                std::fs::copy(&encrypted_path, &path_to_obfuscated).unwrap();
                let mut none: HashMap<String, String> = HashMap::new();
                none.insert("deobfuscation_function".to_string(), "".to_string());
                none.insert("main".to_string(), "".to_string());
                none.insert("dependencies".to_string(), "".to_string());
                none.insert("imports".to_string(), "".to_string());
                none
            }
        };

        let deobfuscation_function = match args.get("deobfuscation_function") {
            Some(content) => content,
            None => panic!("Obfuscation module: deobfuscation function not found"),
        };
        let deobfuscation_main = match args.get("main") {
            Some(content) => content,
            None => panic!("Obfuscation module: main part of deobfuscation module not found"),
        };
        let deobfuscation_dependencies = match args.get("dependencies") {
            Some(content) => content,
            None => panic!("Obfuscation module: dependencies not found"),
        };
        let deobfuscation_imports = match args.get("imports") {
            Some(content) => content,
            None => panic!("Obfuscation module: imports not found"),
        };

        let mut to_be_replaced = HashMap::new();
        to_be_replaced.insert(
            "{{DEOBFUSCATION_FUNCTION}}",
            deobfuscation_function.to_string(),
        );
        to_be_replaced.insert("{{DEOBFUSCATION}}", deobfuscation_main.to_string());
        to_be_replaced.insert(
            "{{DEOBFUSCATION_DEPENDENCIES}}",
            deobfuscation_dependencies.to_string(),
        );
        to_be_replaced.insert(
            "{{DEOBFUSCATION_IMPORTS}}",
            deobfuscation_imports.to_string(),
        );
        to_be_replaced.insert(
            "{{PATH_TO_SHELLCODE}}",
            absolute_path_to_obfuscated_as_string,
        );

        to_be_replaced
    }
}
