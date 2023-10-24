use owo_colors::{OwoColorize, Stream::Stdout};

use crate::template::Template;

mod debug_privilege;
mod detection;
mod encryption;
mod obfuscation;
mod self_destroy;
mod template;
mod utils;
mod virustotal;

fn main() {
    let (template, virustotal) = utils::arg_parser::meta_arg_parser();
    match virustotal.bypass_target {
        Some(_) => {
            Template::generate(template, &virustotal);
        }
        None => {
            let path = Template::new(template).compile();
            if let Some(path) = path {
                if virustotal.is_enabled {
                    virustotal.check(path.clone());
                    println!(
                        "\n{} {}",
                        "[Result]".if_supports_color(Stdout, |text| text.green()),
                        path
                    );
                }
            }
        }
    }
}
