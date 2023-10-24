use std::collections::HashMap;

use crate::detection::debugger::meta_antidebug;
use crate::detection::sandbox::meta_sandbox;
use crate::detection::vm::meta_vm;
use crate::template::Template;

pub(crate) mod debugger;
pub(crate) mod sandbox;
pub(crate) mod vm;

impl Template {
    pub(crate) fn antidebug(&self) -> HashMap<&str, String> {
        let mut to_be_replaced = HashMap::new();
        let args = meta_antidebug(&self.antidebug);

        let antidebug_function = match args.get("antidebug_functions") {
            Some(content) => content,
            None => panic!("Antidebug module: debug detection functions not found"),
        };
        let antidebug_main = match args.get("main") {
            Some(content) => content,
            None => panic!("Antidebug module: main part of antidebug module not found"),
        };
        let antidebug_imports = match args.get("imports") {
            Some(content) => content,
            None => panic!("Antidebug module: imports not found"),
        };
        let antidebug_dependencies = match args.get("dependencies") {
            Some(content) => content,
            None => panic!("Antidebug module: dependencies not found"),
        };

        to_be_replaced.insert("{{ANTIDEBUG}}", antidebug_main.to_string());
        to_be_replaced.insert("{{ANTIDEBUG_FUNCTION}}", antidebug_function.to_string());
        to_be_replaced.insert("{{ANTIDEBUG_IMPORTS}}", antidebug_imports.to_string());
        to_be_replaced.insert(
            "{{ANTIDEBUG_DEPENDENCIES}}",
            antidebug_dependencies.to_string(),
        );
        to_be_replaced
    }
    pub(crate) fn sandbox(&self) -> HashMap<&str, String> {
        let mut to_be_replaced = HashMap::new();
        let args = meta_sandbox(&self.sandbox);

        let sandbox_function = match args.get("sandbox_functions") {
            Some(content) => content,
            None => panic!("Sandbox module: sandbox detection functions not found"),
        };
        let sandbox_main = match args.get("main") {
            Some(content) => content,
            None => panic!("Sandbox module: main part of sandbox module not found"),
        };
        let sandbox_imports = match args.get("imports") {
            Some(content) => content,
            None => panic!("Sandbox module: imports not found"),
        };
        let sandbox_dependencies = match args.get("dependencies") {
            Some(content) => content,
            None => panic!("Sandbox module: dependencies not found"),
        };

        to_be_replaced.insert("{{SANDBOX}}", sandbox_main.to_string());
        to_be_replaced.insert("{{SANDBOX_FUNCTION}}", sandbox_function.to_string());
        to_be_replaced.insert("{{SANDBOX_IMPORTS}}", sandbox_imports.to_string());
        to_be_replaced.insert("{{SANDBOX_DEPENDENCIES}}", sandbox_dependencies.to_string());
        to_be_replaced
    }
    pub(crate) fn vm(&self) -> HashMap<&str, String> {
        let mut to_be_replaced = HashMap::new();
        let args = meta_vm(&self.vm);

        let vm_main = match args.get("main") {
            Some(content) => content,
            None => panic!("VM module: main part of VM module not found"),
        };
        let vm_function = match args.get("vm_functions") {
            Some(content) => content,
            None => panic!("VM module: VM detection functions not found"),
        };
        let vm_imports = match args.get("imports") {
            Some(content) => content,
            None => panic!("VM module: imports not found"),
        };

        to_be_replaced.insert("{{VM}}", vm_main.to_string());
        to_be_replaced.insert("{{VM_FUNCTION}}", vm_function.to_string());
        to_be_replaced.insert("{{VM_IMPORTS}}", vm_imports.to_string());
        to_be_replaced
    }
}
