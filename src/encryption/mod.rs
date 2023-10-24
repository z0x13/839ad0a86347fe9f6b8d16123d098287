use std::collections::HashMap;
use std::path::PathBuf;

use crate::encryption::aes::meta_aes;
use crate::encryption::chacha20::meta_chacha20;
use crate::encryption::rabbit::meta_rabbit;
use crate::encryption::rc4::meta_rc4;
use crate::encryption::smart_xor::meta_smart_xor;
use crate::encryption::xor::meta_xor;
use crate::template::{Encryption, Template};
use crate::utils::{absolute_path, path_to_string};

pub(crate) mod aes;
pub(crate) mod chacha20;
pub(crate) mod rabbit;
pub(crate) mod rc4;
pub(crate) mod smart_xor;
pub(crate) mod xor;

impl Template {
    pub(crate) fn encrypt(&self, to_main: PathBuf) -> HashMap<&str, String> {
        let mut path_to_encrypted = to_main.clone();
        path_to_encrypted.pop();
        path_to_encrypted.push("shellcode.enc");
        let absolute_path_to_encrypted = match absolute_path(&path_to_encrypted) {
            Ok(path) => path,
            Err(err) => panic!("{:?}", err),
        };

        let absolute_path_to_encrypted_as_string = path_to_string(&absolute_path_to_encrypted);
        let encrypted_path = absolute_path_to_encrypted.clone();

        let args: HashMap<String, String> = match self.encryption {
            Some(Encryption::Xor) => meta_xor(&self.shellcode_path, &encrypted_path),
            Some(Encryption::SmartXor) => meta_smart_xor(&self.shellcode_path, &encrypted_path),
            Some(Encryption::Aes) => meta_aes(&self.shellcode_path, &encrypted_path),
            Some(Encryption::ChaCha20) => meta_chacha20(&self.shellcode_path, &encrypted_path),
            Some(Encryption::Rabbit) => meta_rabbit(&self.shellcode_path, &encrypted_path),
            Some(Encryption::RC4) => meta_rc4(&self.shellcode_path, &encrypted_path),
            None => {
                std::fs::copy(&self.shellcode_path, &path_to_encrypted).unwrap();
                let mut none: HashMap<String, String> = HashMap::new();
                none.insert("decryption_function".to_string(), "".to_string());
                none.insert("main".to_string(), "".to_string());
                none.insert("dependencies".to_string(), "".to_string());
                none.insert("imports".to_string(), "".to_string());
                none
            }
        };

        let decryption_function = match args.get("decryption_function") {
            Some(content) => content,
            None => panic!("Encryption module: decryption function not found"),
        };
        let decryption_main = match args.get("main") {
            Some(content) => content,
            None => panic!("Encryption module: main part of decryption module not found"),
        };
        let encryption_dependencies = match args.get("dependencies") {
            Some(content) => content,
            None => panic!("Encryption module: dependencies not found"),
        };
        let encryption_imports = match args.get("imports") {
            Some(content) => content,
            None => panic!("Encryption module: imports not found"),
        };

        let mut to_be_replaced = HashMap::new();
        to_be_replaced.insert("{{DECRYPTION_FUNCTION}}", decryption_function.to_string());
        to_be_replaced.insert("{{DECRYPTION}}", decryption_main.to_string());
        to_be_replaced.insert(
            "{{PATH_TO_SHELLCODE}}",
            absolute_path_to_encrypted_as_string,
        );
        to_be_replaced.insert(
            "{{ENCRYPTION_DEPENDENCIES}}",
            encryption_dependencies.to_string(),
        );
        to_be_replaced.insert("{{ENCRYPTION_IMPORTS}}", encryption_imports.to_string());

        to_be_replaced
    }
}
