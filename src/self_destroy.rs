use owo_colors::{OwoColorize, Stream::Stdout};
use std::collections::HashMap;

use crate::template::Template;

pub fn meta_self_destroy() -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();
    println!(
        "{} Adding {} ..",
        "[+]".if_supports_color(Stdout, |text| text.green()),
        "self-destruction".if_supports_color(Stdout, |text| text.yellow())
    );
    let main = r#"
    houdini::disappear().ok();"#
        .to_string();
    let dependencies = r#"houdini = "2.0.0""#.to_string();
    result.insert(String::from("main"), main);
    result.insert(String::from("dependencies"), dependencies);
    println!(
        "{} Added self-destruction!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}

impl Template {
    pub(crate) fn self_destroy(&self) -> HashMap<&str, String> {
        let mut to_be_replaced = HashMap::new();
        match self.self_destroy {
            true => {
                let args = meta_self_destroy();
                let self_destroy_main = match args.get("main") {
                    Some(content) => content,
                    None => panic!("I don't even know how this happened.."),
                };
                let self_destroy_dependencies = match args.get("dependencies") {
                    Some(content) => content,
                    None => panic!("I don't even know how this happened.."),
                };
                to_be_replaced.insert("{{SELF-DESTROY}}", self_destroy_main.to_string());
                to_be_replaced.insert(
                    "{{SELF-DESTROY_DEPENDENCIES}}",
                    self_destroy_dependencies.to_string(),
                );
            }
            false => {
                to_be_replaced.insert("{{SELF-DESTROY}}", "".to_string());
                to_be_replaced.insert("{{SELF-DESTROY_DEPENDENCIES}}", "".to_string());
            }
        };
        to_be_replaced
    }
}
