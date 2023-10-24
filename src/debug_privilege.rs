use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashMap;

use crate::template::Template;

pub fn meta_debug_privilege() -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();
    println!(
        "{} Adding {} ..",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "debug privilege".if_supports_color(Stdout, |text| text.yellow())
    );
    let main = r#"
unsafe {
    tasklist::enable_debug_priv();
}
"#
    .to_string();
    let dependencies = r#"tasklist = "0.2.13""#.to_string();
    result.insert(String::from("main"), main);
    result.insert(String::from("dependencies"), dependencies);
    println!(
        "{} Added debug privilege!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}

impl Template {
    pub(crate) fn debug_privilege(&self) -> HashMap<&str, String> {
        let mut to_be_replaced = HashMap::new();
        match self.debug_privilege {
            true => {
                let args = meta_debug_privilege();
                let self_destroy_main = match args.get("main") {
                    Some(content) => content,
                    None => panic!("I don't even know how this happened.."),
                };
                let self_destroy_dependencies = match args.get("dependencies") {
                    Some(content) => content,
                    None => panic!("I don't even know how this happened.."),
                };
                to_be_replaced.insert("{{DEBUG_PRIVILEGE}}", self_destroy_main.to_string());
                to_be_replaced.insert(
                    "{{DEBUG_PRIVILEGE_DEPENDENCIES}}",
                    self_destroy_dependencies.to_string(),
                );
            }
            false => {
                to_be_replaced.insert("{{DEBUG_PRIVILEGE}}", "".to_string());
                to_be_replaced.insert("{{DEBUG_PRIVILEGE_DEPENDENCIES}}", "".to_string());
            }
        };
        to_be_replaced
    }
}
