#![allow(dead_code)]

use owo_colors::{OwoColorize, Stream::Stdout};
use regex::Regex;
use rust_embed::RustEmbed;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::template::{Level, Vm, VmDetection};

mod vm_detection;

#[derive(RustEmbed)]
#[folder = "src/detection/vm"]
pub struct VmLibrary;

pub fn meta_vm(vm: &Option<Vm>) -> HashMap<String, String> {
    let mut result: HashMap<String, String> = HashMap::new();

    let mut detection_files: HashMap<VmDetection, String> = HashMap::new();
    let mut filepath: String;
    for file in VmLibrary::iter() {
        if let Some(content) = PathBuf::from(file.as_ref()).file_name() {
            filepath = file.to_string();
            match content.to_str().unwrap() {
                "cpuid_hw_bit.rs" => {
                    detection_files.insert(VmDetection::CpuidHWbit, filepath);
                }
                "cpuid_vendor.rs" => {
                    detection_files.insert(VmDetection::CpuidVmVendor, filepath);
                }
                "rdtsc.rs" => {
                    detection_files.insert(VmDetection::Rdtsc, filepath);
                }
                "rdtsc_vmexit.rs" => {
                    detection_files.insert(VmDetection::RdtscVmExit, filepath);
                }
                _ => {}
            }
        }
    }

    let mut presets: HashMap<Level, Vec<VmDetection>> = HashMap::new();
    presets.insert(Level::Low, vec![VmDetection::CpuidHWbit]);
    presets.insert(Level::Basic, vec![VmDetection::CpuidVmVendor]);
    presets.insert(
        Level::Paranoid,
        vec![
            VmDetection::CpuidVmVendor,
            VmDetection::Rdtsc,
            VmDetection::RdtscVmExit,
        ],
    );

    let mut vm_functions = r#"
fn vm() {
    if {{CpuidHWbit}} ||
       {{CpuidVmVendor}} ||
       {{Rdtsc}} ||
       {{RdtscVmExit}} {
       std::process::exit(0);
    }
}"#
    .to_string();

    let custom_functions = match vm {
        Some(content) => match &content.preset {
            Some(level) => presets.get(level).unwrap(),
            None => vm.as_ref().unwrap().custom.as_ref().unwrap(),
        },
        None => {
            let mut none: HashMap<String, String> = HashMap::new();
            none.insert("main".to_string(), "".to_string());
            none.insert("vm_functions".to_string(), "".to_string());
            none.insert("dependencies".to_string(), "".to_string());
            none.insert("imports".to_string(), "".to_string());
            return none;
        }
    };

    print!(
        "{} Adding VM protection. Detection methods:",
        "[+]".if_supports_color(Stdout, |text| text.green())
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
        let antidebug_function = VmLibrary::get(detection_files.get(technique).unwrap())
            .expect("Failed to get content")
            .data;
        vm_functions.push_str(std::str::from_utf8(antidebug_function.as_ref()).unwrap());
        vm_functions = match technique {
            VmDetection::CpuidHWbit => vm_functions.replace("{{CpuidHWbit}}", "cpuid_hv_bit()"),
            VmDetection::CpuidVmVendor => {
                vm_functions.replace("{{CpuidVmVendor}}", "cpuid_vendor()")
            }
            VmDetection::Rdtsc => vm_functions.replace("{{Rdtsc}}", "rdtsc()"),
            VmDetection::RdtscVmExit => vm_functions.replace("{{RdtscVmExit}}", "rdtsc_vmexit()"),
        }
    }

    let rg = Regex::new(r"\{\{[a-zA-Z]+}}").unwrap();
    vm_functions = rg.replace_all(vm_functions.as_str(), "false").to_string();

    let main = r#"vm();"#.to_string();
    let imports = "".to_string();
    result.insert(String::from("main"), main);
    result.insert(String::from("vm_functions"), vm_functions);
    result.insert(String::from("imports"), imports);
    println!(
        "{} Added VM protection!",
        "[+]".if_supports_color(Stdout, |text| text.green())
    );
    result
}
