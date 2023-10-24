#![allow(dead_code)]

use owo_colors::{OwoColorize, Stream::Stdout};
use regex::Regex;
use rust_embed::RustEmbed;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::template::{Antidebug, CustomAntidebug, DebugActions, DebugDetection, Level};

mod debug_action;
mod debug_detection;

#[derive(RustEmbed)]
#[folder = "src/detection/debugger"]
pub struct AntidebugLibrary;

pub fn meta_antidebug(antidebug: &Option<Antidebug>) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    let mut detection_files: HashMap<DebugDetection, String> = HashMap::new();
    let mut action_files: HashMap<DebugActions, String> = HashMap::new();

    let mut filepath: String;
    for file in AntidebugLibrary::iter() {
        if let Some(content) = PathBuf::from(file.as_ref()).file_name() {
            filepath = file.to_string();
            match content.to_str().unwrap() {
                "hide_from_debugger.rs" => {
                    action_files.insert(DebugActions::Hide, filepath);
                }
                "is_debugger_present.rs" => {
                    detection_files.insert(DebugDetection::IsDebuggerPresent, filepath);
                }
                "peb_is_debugger_present.rs" => {
                    detection_files.insert(DebugDetection::PebIsDebuggerPresent, filepath);
                }
                "peb_nt_global_flag.rs" => {
                    detection_files.insert(DebugDetection::PebNTGlobalFlag, filepath);
                }
                "peb_heap_flags.rs" => {
                    detection_files.insert(DebugDetection::PebHeapFlags, filepath);
                }
                "check_remote_debugger_present.rs" => {
                    detection_files.insert(DebugDetection::CheckRemoteDebuggerPresent, filepath);
                }
                "nt_query_information_process_debug_port.rs" => {
                    detection_files.insert(DebugDetection::NTQueryDebugPort, filepath);
                }
                "nt_query_information_process_debug_object.rs" => {
                    detection_files.insert(DebugDetection::NTQueryDebugObject, filepath);
                }
                "nt_query_information_process_debug_flags.rs" => {
                    detection_files.insert(DebugDetection::NTQueryDebugFlags, filepath);
                }
                "debug_registers.rs" => {
                    detection_files.insert(DebugDetection::DebugRegisters, filepath);
                }
                _ => {}
            }
        }
    }

    let mut presets: HashMap<Level, CustomAntidebug> = HashMap::new();
    presets.insert(
        Level::Low,
        CustomAntidebug {
            detection_methods: vec![DebugDetection::IsDebuggerPresent],
            action: DebugActions::Exit,
        },
    );
    presets.insert(
        Level::Basic,
        CustomAntidebug {
            detection_methods: vec![
                DebugDetection::PebIsDebuggerPresent,
                DebugDetection::PebNTGlobalFlag,
            ],
            action: DebugActions::Hide,
        },
    );
    presets.insert(
        Level::Paranoid,
        CustomAntidebug {
            detection_methods: vec![
                DebugDetection::PebIsDebuggerPresent,
                DebugDetection::PebNTGlobalFlag,
                DebugDetection::CheckRemoteDebuggerPresent,
                DebugDetection::DebugRegisters,
            ],
            action: DebugActions::Exit,
        },
    );

    let mut antidebug_functions = r#"
#[inline]
#[cfg(target_pointer_width = "64")]
pub unsafe fn __readgsqword(offset: std::os::raw::c_ulong) -> winapi::ctypes::__uint64 {
    let out: u64;
    std::arch::asm!(
    "mov {}, gs:[{:e}]",
    lateout(reg) out,
    in(reg) offset,
    options(nostack, pure, readonly),
    );
    out
}
fn antidebug() {
    if {{IsDebuggerPresent}} ||
       {{PebIsDebuggerPresent}} ||
       {{PebNTGlobalFlag}} ||
       {{PebHeapFlags}} ||
       {{CheckRemoteDebuggerPresent}} ||
       {{NTQueryDebugPort}} ||
       {{NTQueryDebugObject}} ||
       {{NTQueryDebugFlags}} ||
       {{DebugRegisters}} {
       {{ACTION}}
    }
}
"#
    .to_string();

    let custom_functions = match antidebug {
        Some(content) => match &content.preset {
            Some(level) => presets.get(level).unwrap(),
            None => antidebug.as_ref().unwrap().custom.as_ref().unwrap(),
        },
        None => {
            let mut none: HashMap<String, String> = HashMap::new();
            none.insert("main".to_string(), "".to_string());
            none.insert("antidebug_functions".to_string(), "".to_string());
            none.insert("dependencies".to_string(), "".to_string());
            none.insert("imports".to_string(), "".to_string());
            return none;
        }
    };

    print!(
        "{} Adding antidebug protection. Detection methods:",
        "[+]".if_supports_color(Stdout, |text| text.green()),
    );
    for method in &custom_functions.detection_methods {
        print!(
            " {}",
            method
                .as_ref()
                .if_supports_color(Stdout, |text| text.yellow())
        );
    }
    println!(
        ". Action if debugger detected: {} ..",
        custom_functions
            .action
            .as_ref()
            .if_supports_color(Stdout, |text| text.yellow())
    );

    for technique in &custom_functions.detection_methods {
        let antidebug_function = AntidebugLibrary::get(detection_files.get(technique).unwrap())
            .expect("Failed to get content")
            .data;
        antidebug_functions.push_str(std::str::from_utf8(antidebug_function.as_ref()).unwrap());
        antidebug_functions = match technique {
            DebugDetection::IsDebuggerPresent => {
                antidebug_functions.replace("{{IsDebuggerPresent}}", "is_debugger_present()")
            }
            DebugDetection::PebIsDebuggerPresent => {
                antidebug_functions.replace("{{PebIsDebuggerPresent}}", "peb_is_debugger_present()")
            }
            DebugDetection::PebNTGlobalFlag => {
                antidebug_functions.replace("{{PebNTGlobalFlag}}", "peb_nt_global_flag()")
            }
            DebugDetection::PebHeapFlags => {
                antidebug_functions.replace("{{PebHeapFlags}}", "peb_heap_flags()")
            }
            DebugDetection::CheckRemoteDebuggerPresent => antidebug_functions.replace(
                "{{CheckRemoteDebuggerPresent}}",
                "check_remote_debugger_present()",
            ),
            DebugDetection::NTQueryDebugPort => antidebug_functions.replace(
                "{{NTQueryDebugPort}}",
                "nt_query_information_process_debug_port()",
            ),
            DebugDetection::NTQueryDebugObject => antidebug_functions.replace(
                "{{NTQueryDebugObject}}",
                "nt_query_information_process_debug_object()",
            ),
            DebugDetection::NTQueryDebugFlags => antidebug_functions.replace(
                "{{NTQueryDebugFlags}}",
                "nt_query_information_process_debug_flags()",
            ),
            DebugDetection::DebugRegisters => {
                antidebug_functions.replace("{{DebugRegisters}}", "debug_registers()")
            }
        }
    }
    let rg =
        Regex::new(r"use crate::detection::debugger::debug_detection::readgsqword::__readgsqword;")
            .unwrap();
    antidebug_functions = rg.replace_all(antidebug_functions.as_str(), "").to_string();

    match &custom_functions.action {
        DebugActions::Hide => {
            let action_function =
                AntidebugLibrary::get(action_files.get(&DebugActions::Hide).unwrap())
                    .expect("Failed to get content")
                    .data;
            antidebug_functions.push_str(std::str::from_utf8(action_function.as_ref()).unwrap());
            antidebug_functions =
                antidebug_functions.replace("{{ACTION}}", "hide_from_debugger();");
        }
        DebugActions::Exit => {
            antidebug_functions =
                antidebug_functions.replace("{{ACTION}}", "std::process::exit(0);");
        }
    }

    let rg = Regex::new(r"\{\{[a-zA-Z]+}}").unwrap();
    antidebug_functions = rg
        .replace_all(antidebug_functions.as_str(), "false")
        .to_string();

    let main = "antidebug();".to_string();
    let dependencies = r#"
    kernel32-sys = "0.2.2"
    "#
    .to_string();
    let imports = "
    use winapi::um::debugapi::IsDebuggerPresent;
    "
    .to_string();
    result.insert(String::from("main"), main);
    result.insert(String::from("antidebug_functions"), antidebug_functions);
    result.insert(String::from("dependencies"), dependencies);
    result.insert(String::from("imports"), imports);
    println!(
        "{} Added antidebug protection!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
